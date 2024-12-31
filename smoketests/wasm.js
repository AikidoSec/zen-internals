const internals = require("../pkg/zen_internals");
const { equal } = require("node:assert");

equal(internals.wasm_detect_sql_injection("SELECT * FROM users WHERE id = '' OR 1=1 -- '", "' OR 1=1 -- ", 0), true);

equal(internals.wasm_detect_shell_injection("SELECT * FROM users WHERE id = 'hello world'", 'hello world'), false);

equal(internals.wasm_detect_js_injection("const test = 'Hello World!'; //';", "Hello World!'; //", 0), true);

equal(internals.wasm_detect_js_injection("const test = 'Hello World!'; //';", "Hello World!", 0), false);
