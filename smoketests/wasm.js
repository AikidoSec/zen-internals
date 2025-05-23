const internals = require("../pkg/zen_internals");
const { deepStrictEqual } = require("node:assert");
const test = require("node:test");

test("wasm_detect_sql_injection", () => {
 deepStrictEqual(internals.wasm_detect_sql_injection("SELECT * FROM users WHERE id = '' OR 1=1 -- '", "' OR 1=1 -- ", 0), true);
 deepStrictEqual(internals.wasm_detect_sql_injection("SELECT * FROM users WHERE id = 'hello world'", 'hello world'), false);
});

test("wasm_detect_js_injection", () => {
 deepStrictEqual(internals.wasm_detect_js_injection("const test = 'Hello World!'; //';", "Hello World!'; //", 0), true);
 deepStrictEqual(internals.wasm_detect_js_injection("const test = 'Hello World!'; //';", "Hello World!", 0), false);
});
