const internals = require("../pkg/zen_internals");
const { deepStrictEqual } = require("node:assert");
const test = require("node:test");

test("wasm_detect_sql_injection", () => {
 deepStrictEqual(internals.wasm_detect_sql_injection("SELECT * FROM users WHERE id = '' OR 1=1 -- '", "' OR 1=1 -- ", 0), 1);
 deepStrictEqual(internals.wasm_detect_sql_injection("SELECT * FROM users WHERE id = 'hello world'", 'hello world'), 0);

 // Tokenize error
 deepStrictEqual(internals.wasm_detect_sql_injection('SELECT unicorns fly over the "rainbow', "rainbow"), 3);
});

test("wasm_detect_js_injection", () => {
 deepStrictEqual(internals.wasm_detect_js_injection("const test = 'Hello World!'; //';", "Hello World!'; //", 0), true);
 deepStrictEqual(internals.wasm_detect_js_injection("const test = 'Hello World!'; //';", "Hello World!", 0), false);
});
