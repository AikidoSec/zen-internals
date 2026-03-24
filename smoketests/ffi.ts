import { assertEquals } from "https://deno.land/std/testing/asserts.ts";

const libSuffix = Deno.build.os == "darwin" ? "dylib" : "so";
const fullTargetDir = `./target/release/libzen_internals.${libSuffix}`;

const lib = Deno.dlopen(fullTargetDir, {
    detect_sql_injection: {
        parameters: ["pointer", "usize", "pointer", "usize", "i32"],
        result: "i32",
    },
    detect_js_injection: {
        parameters: ["pointer", "usize", "pointer", "usize", "i32"],
        result: "i32",
    },
    idor_analyze_sql_ffi: {
        parameters: ["pointer", "usize", "i32"],
        result: "pointer",
    },
    free_string: {
        parameters: ["pointer"],
        result: "void",
    },
});

function getBufferAndLength(str: string): [Deno.PointerValue, number] {
    const encoder = new TextEncoder();

    const encoded = encoder.encode(str);
    const buffer = new Uint8Array(encoded.length);
    buffer.set(encoded);
    const pointer = Deno.UnsafePointer.of(buffer);

    return [pointer, buffer.length];
}

// Test SQL injection
assertEquals(
    lib.symbols.detect_sql_injection(
        ...getBufferAndLength("SELECT * FROM users WHERE id = '' OR 1=1 -- '"),
        ...getBufferAndLength("' OR 1=1 -- "),
        0
    ),
    1
);

// Not an injection
assertEquals(
    lib.symbols.detect_sql_injection(
        ...getBufferAndLength("SELECT * FROM users WHERE id = 'hello world'"),
        ...getBufferAndLength("hello world"),
        0
    ),
    0
);

// Test fallback to generic dialect
assertEquals(
    lib.symbols.detect_sql_injection(
        ...getBufferAndLength("SELECT * FROM users WHERE id = '' OR 1=1 -- '"),
        ...getBufferAndLength("' OR 1=1 -- "),
        2141
    ),
    1
);

// Test unsafe pointer
assertEquals(
    lib.symbols.detect_sql_injection(
        ...getBufferAndLength("🔥", ""),
        Deno.UnsafePointer.of(new Uint8Array([])),
        0,
        0
    ),
    2
);
assertEquals(
    lib.symbols.detect_sql_injection(
        Deno.UnsafePointer.of(new Uint8Array([])),
        0,
        ...getBufferAndLength("🔥"),
        0
    ),
    2
);
assertEquals(
    lib.symbols.detect_sql_injection(null, 0, ...getBufferAndLength("🔥"), 0),
    2
);

// Test tokenization failure
assertEquals(
    lib.symbols.detect_sql_injection(
        ...getBufferAndLength('SELECT unicorns fly over the "rainbow'),
        ...getBufferAndLength("rainbow"),
        0
    ),
    3
);

// Test JS injection
assertEquals(
    lib.symbols.detect_js_injection(
        ...getBufferAndLength("const test = 'Hello World!'; //';"),
        ...getBufferAndLength("Hello World!'; //"),
        0
    ),
    1
);

// Not an injection
assertEquals(
    lib.symbols.detect_js_injection(
        ...getBufferAndLength("const test = 'Hello World!';"),
        ...getBufferAndLength("Hello World!"),
        0
    ),
    0
);

// Test unsafe pointer
assertEquals(
    lib.symbols.detect_js_injection(
        ...getBufferAndLength("🔥"),
        Deno.UnsafePointer.of(new Uint8Array([])),
        0,
        0
    ),
    2
);
assertEquals(
    lib.symbols.detect_js_injection(
        Deno.UnsafePointer.of(new Uint8Array([])),
        0,
        ...getBufferAndLength("🔥"),
        0
    ),
    2
);
assertEquals(
    lib.symbols.detect_js_injection(null, 0, ...getBufferAndLength("🔥"), 0),
    2
);

function toCStringInvalidUtf8(): Deno.PointerValue {
    const buffer = new Uint8Array([0xc3, 0x28]); // Invalid UTF-8 sequence
    return Deno.UnsafePointer.of(buffer);
}

assertEquals(
    lib.symbols.detect_sql_injection(
        toCStringInvalidUtf8(),
        2,
        ...getBufferAndLength("test"),
        0
    ),
    2
);
assertEquals(
    lib.symbols.detect_sql_injection(
        ...getBufferAndLength("test"),
        toCStringInvalidUtf8(),
        2,
        0
    ),
    2
);
assertEquals(
    lib.symbols.detect_js_injection(
        toCStringInvalidUtf8(),
        2,
        ...getBufferAndLength("test"),
        0
    ),
    2
);
assertEquals(
    lib.symbols.detect_js_injection(
        ...getBufferAndLength("test"),
        toCStringInvalidUtf8(),
        2,
        0
    ),
    2
);

// Zero length not allowed
assertEquals(
    lib.symbols.detect_sql_injection(
        getBufferAndLength("SELECT * FROM users WHERE id = '' OR 1=1 -- '").at(
            0
        ),
        0,
        ...getBufferAndLength("' OR 1=1 -- "),
        0
    ),
    2
);
assertEquals(
    lib.symbols.detect_sql_injection(
        ...getBufferAndLength("SELECT * FROM users WHERE id = '' OR 1=1 -- '"),
        getBufferAndLength("' OR 1=1 -- ").at(0),
        0,
        0
    ),
    2
);
assertEquals(
    lib.symbols.detect_js_injection(
        getBufferAndLength("const test = 'Hello World!'; //';").at(0),
        0,
        ...getBufferAndLength("Hello World!'; //"),
        0
    ),
    2
);
assertEquals(
    lib.symbols.detect_js_injection(
        ...getBufferAndLength("const test = 'Hello World!'; //';"),
        getBufferAndLength("Hello World!'; //").at(0),
        0,
        0
    ),
    2
);

// Can't detect SQL injection with just one character
assertEquals(
    lib.symbols.detect_sql_injection(
        ...getBufferAndLength("SELECT * FROM users WHERE id = '' OR 1=1 -- '"),
        getBufferAndLength("' OR 1=1 -- ").at(0),
        1,
        0
    ),
    0
);
assertEquals(
    lib.symbols.detect_js_injection(
        ...getBufferAndLength("const test = 'Hello World!'; //';"),
        getBufferAndLength("Hello World!'; //").at(0),
        1,
        0
    ),
    0
);

// It detects injection with a null terminator
assertEquals(
    lib.symbols.detect_sql_injection(
        ...getBufferAndLength(
            "SELECT * FROM users WHERE id = '\0' OR 1=1 -- '"
        ),
        ...getBufferAndLength("\0' OR 1=1 -- "),
        0
    ),
    1
);
assertEquals(
    lib.symbols.detect_js_injection(
        ...getBufferAndLength("const test = '\0Hello World!'; //';"),
        ...getBufferAndLength("\0Hello World!'; //"),
        0
    ),
    1
);

// Test IDOR SQL analysis
function callIdorAnalyzeSql(query: string, dialect: number): unknown {
    const [queryPtr, queryLen] = getBufferAndLength(query);
    const resultPtr = lib.symbols.idor_analyze_sql_ffi(queryPtr, queryLen, dialect);
    const result = new Deno.UnsafePointerView(resultPtr!).getCString();
    lib.symbols.free_string(resultPtr);
    return JSON.parse(result);
}

assertEquals(
    callIdorAnalyzeSql("SELECT * FROM users WHERE tenant_id = $1", 9),
    [{ kind: "select", tables: [{ name: "users" }], filters: [{ column: "tenant_id", value: "$1", is_placeholder: true }] }]
);

assertEquals(
    callIdorAnalyzeSql("INSERT INTO users (name, email) VALUES ('test', 'test@example.com')", 9),
    [{ kind: "insert", tables: [{ name: "users" }], filters: [], insert_columns: [[{ column: "name", value: "test", is_placeholder: false }, { column: "email", value: "test@example.com", is_placeholder: false }]] }]
);

assertEquals(
    callIdorAnalyzeSql("INVALID SQL QUERY", 9),
    { error: "sql parser error: Expected: an SQL statement, found: INVALID at Line: 1, Column: 1" }
);

assertEquals(
    (() => {
        const resultPtr = lib.symbols.idor_analyze_sql_ffi(null, 0, 9);
        const result = new Deno.UnsafePointerView(resultPtr!).getCString();
        lib.symbols.free_string(resultPtr);
        return JSON.parse(result);
    })(),
    { error: "Invalid query pointer or length" }
);

// Test transaction-related queries
assertEquals(
    callIdorAnalyzeSql("COMMIT", 9),
    []
);

// Test WAF
const wafLib = Deno.dlopen(fullTargetDir, {
    waf_set_rules: {
        parameters: ["pointer", "usize"],
        result: "pointer",
    },
    waf_evaluate: {
        parameters: ["pointer", "usize"],
        result: "pointer",
    },
    free_string: {
        parameters: ["pointer"],
        result: "void",
    },
});

function callWafSetRules(json: string): unknown {
    const [ptr, len] = getBufferAndLength(json);
    const resultPtr = wafLib.symbols.waf_set_rules(ptr, len);
    const result = new Deno.UnsafePointerView(resultPtr!).getCString();
    wafLib.symbols.free_string(resultPtr);
    return JSON.parse(result);
}

function callWafEvaluate(json: string): unknown {
    const [ptr, len] = getBufferAndLength(json);
    const resultPtr = wafLib.symbols.waf_evaluate(ptr, len);
    const result = new Deno.UnsafePointerView(resultPtr!).getCString();
    wafLib.symbols.free_string(resultPtr);
    return JSON.parse(result);
}

// Set a rule
assertEquals(
    callWafSetRules(JSON.stringify([
        { id: "block-admin", expression: 'http.request.uri.path contains "/admin"', action: "block" }
    ])),
    { success: true }
);

// Should match
assertEquals(
    callWafEvaluate(JSON.stringify({
        host: "example.com", method: "GET", path: "/admin/users", query: "",
        uri: "/admin/users", full_uri: "https://example.com/admin/users", ip_src: "1.2.3.4"
    })),
    { matched: true, rule_id: "block-admin", action: "block" }
);

// Should not match
assertEquals(
    callWafEvaluate(JSON.stringify({
        host: "example.com", method: "GET", path: "/index.html", query: "",
        uri: "/index.html", full_uri: "https://example.com/index.html", ip_src: "1.2.3.4"
    })),
    { matched: false }
);

// Update rules - old rule should no longer match
callWafSetRules(JSON.stringify([
    { id: "block-api", expression: 'http.request.uri.path contains "/api"', action: "block" }
]));
assertEquals(
    callWafEvaluate(JSON.stringify({
        host: "example.com", method: "GET", path: "/admin/users", query: "",
        uri: "/admin/users", full_uri: "https://example.com/admin/users", ip_src: "1.2.3.4"
    })),
    { matched: false }
);
assertEquals(
    callWafEvaluate(JSON.stringify({
        host: "example.com", method: "GET", path: "/api/users", query: "",
        uri: "/api/users", full_uri: "https://example.com/api/users", ip_src: "1.2.3.4"
    })),
    { matched: true, rule_id: "block-api", action: "block" }
);

// Invalid expression
const badResult = callWafSetRules(JSON.stringify([
    { id: "bad", expression: "not valid !!!", action: "block" }
])) as { success: boolean; rule_id: string };
assertEquals(badResult.success, false);
assertEquals(badResult.rule_id, "bad");

wafLib.close();
lib.close();
