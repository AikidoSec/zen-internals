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

lib.close();
