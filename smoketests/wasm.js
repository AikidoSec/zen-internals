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

test("wasm_detect_shell_injection", () => {
 deepStrictEqual(internals.wasm_detect_shell_injection("ls; rm -rf /", "; rm -rf /"), 1);
 deepStrictEqual(internals.wasm_detect_shell_injection("echo 'safe'", "safe"), 0);

 // Tokenize error (unclosed quote)
 deepStrictEqual(internals.wasm_detect_shell_injection("echo 'unclosed", "unclosed"), 3);
});

test("wasm_idor_analyze_sql", () => {
 deepStrictEqual(
  internals.wasm_idor_analyze_sql("SELECT * FROM users WHERE tenant_id = $1", 9),
  [{ kind: "select", tables: [{ name: "users" }], filters: [{ column: "tenant_id", value: "$1", is_placeholder: true }] }]
 );
 deepStrictEqual(
  internals.wasm_idor_analyze_sql("INSERT INTO users (name, email) VALUES ('test', 'test@example.com')", 9),
  [{ kind: "insert", tables: [{ name: "users" }], filters: [], insert_columns: [[{ column: "name", value: "test", is_placeholder: false }, { column: "email", value: "test@example.com", is_placeholder: false }]] }]
 );
 deepStrictEqual(
  internals.wasm_idor_analyze_sql("INVALID SQL QUERY", 9),
  { error: "sql parser error: Expected: an SQL statement, found: INVALID at Line: 1, Column: 1" }
 );
 // Test transaction-related queries
 deepStrictEqual(
  internals.wasm_idor_analyze_sql("COMMIT", 9),
  []
 );
});
