import { assertEquals } from "https://deno.land/std/testing/asserts.ts";

const libSuffix = Deno.build.os == "darwin" ? "dylib" : "so";
const fullTargetDir = `./target/release/libzen_internals.${libSuffix}`;

const lib = Deno.dlopen(
    fullTargetDir,
    {
        detect_sql_injection: {
            parameters: ["pointer", "pointer", "i32"],
            result: "i32",
        },
        detect_js_injection: {
            parameters: ["pointer", "pointer", "i32"],
            result: "i32",
        },
    }
);

function toCString(str: string): Deno.PointerValue {
    const encoder = new TextEncoder();
    const encoded = encoder.encode(str + "\0"); // Null-terminated string
    const buffer = new Uint8Array(encoded.length);
    buffer.set(encoded);

    return Deno.UnsafePointer.of(buffer);
}

// Test SQL injection
assertEquals(
    lib.symbols.detect_sql_injection(toCString("SELECT * FROM users WHERE id = '' OR 1=1 -- '"), toCString("' OR 1=1 -- "), 0),
    1
);

// Not an injection
assertEquals(
    lib.symbols.detect_sql_injection(toCString("SELECT * FROM users WHERE id = 'hello world'"), toCString("hello world"), 0),
    0
);

// Test fallback to generic dialect
assertEquals(
    lib.symbols.detect_sql_injection(toCString("SELECT * FROM users WHERE id = '' OR 1=1 -- '"), toCString("' OR 1=1 -- "), 2141),
    1
);

// Test unsafe pointer
assertEquals(
    lib.symbols.detect_sql_injection(toCString("🔥"), Deno.UnsafePointer.of(new Uint8Array([])), 0),
    2
);
assertEquals(
    lib.symbols.detect_sql_injection(Deno.UnsafePointer.of(new Uint8Array([])), toCString("🔥"), 0),
    2
);
assertEquals(
    lib.symbols.detect_sql_injection(null, toCString("🔥"), 0),
    2
);

// Test JS injection
assertEquals(
    lib.symbols.detect_js_injection(toCString("const test = 'Hello World!'; //';"), toCString("Hello World!'; //"), 0),
    1
);

// Not an injection
assertEquals(
    lib.symbols.detect_js_injection(toCString("const test = 'Hello World!';"), toCString("Hello World!"), 0),
    0
);

// Test unsafe pointer
assertEquals(
    lib.symbols.detect_js_injection(toCString("🔥"), Deno.UnsafePointer.of(new Uint8Array([])), 0),
    2
);
assertEquals(
    lib.symbols.detect_js_injection(Deno.UnsafePointer.of(new Uint8Array([])), toCString("🔥"), 0),
    2
);
assertEquals(
    lib.symbols.detect_js_injection(null, toCString("🔥"), 0),
    2
);

lib.close();
