import { assertEquals, } from "https://deno.land/std/testing/asserts.ts";

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

assertEquals(
    lib.symbols.detect_sql_injection(toCString("SELECT * FROM users WHERE id = '' OR 1=1 -- '"), toCString("' OR 1=1 -- "), 0),
    1
);

assertEquals(
    lib.symbols.detect_sql_injection(toCString("SELECT * FROM users WHERE id = 'hello world'"), toCString("hello world"), 0),
    0
);

assertEquals(
    lib.symbols.detect_js_injection(toCString("const test = 'Hello World!'; //';"), toCString("Hello World!'; //"), 0),
    1
);

assertEquals(
    lib.symbols.detect_js_injection(toCString("const test = 'Hello World!';"), toCString("Hello World!"), 0),
    0
);

lib.close();
