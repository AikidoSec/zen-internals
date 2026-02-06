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
    detect_shell_injection: {
        parameters: ["pointer", "usize", "pointer", "usize"],
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

// Test shell injection
assertEquals(
    lib.symbols.detect_shell_injection(
        ...getBufferAndLength("ls; rm -rf /"),
        ...getBufferAndLength("; rm -rf /"),
    ),
    1
);

// Not an injection
assertEquals(
    lib.symbols.detect_shell_injection(
        ...getBufferAndLength("echo 'safe'"),
        ...getBufferAndLength("safe"),
    ),
    0
);

// Tokenization failure (unclosed quote)
assertEquals(
    lib.symbols.detect_shell_injection(
        ...getBufferAndLength("echo 'unclosed"),
        ...getBufferAndLength("unclosed"),
    ),
    3
);

// Test unsafe pointer
assertEquals(
    lib.symbols.detect_shell_injection(
        null,
        0,
        ...getBufferAndLength("test"),
    ),
    2
);

// Zero length not allowed
assertEquals(
    lib.symbols.detect_shell_injection(
        getBufferAndLength("ls; rm -rf /").at(0),
        0,
        ...getBufferAndLength("; rm -rf /"),
    ),
    2
);

// Invalid UTF-8
assertEquals(
    lib.symbols.detect_shell_injection(
        toCStringInvalidUtf8(),
        2,
        ...getBufferAndLength("test"),
    ),
    2
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
    [{ kind: "select", tables: [{ name: "users" }], filters: [{ column: "tenant_id", value: "$1" }] }]
);

assertEquals(
    callIdorAnalyzeSql("INSERT INTO users (name, email) VALUES ('test', 'test@example.com')", 9),
    [{ kind: "insert", tables: [{ name: "users" }], filters: [], insert_columns: [[{ column: "name", value: "test" }, { column: "email", value: "test@example.com" }]] }]
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

lib.close();
