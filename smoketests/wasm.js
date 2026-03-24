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

test("wasm_waf_set_rules and wasm_waf_evaluate", () => {
 // Set a rule
 const setResult = internals.wasm_waf_set_rules(JSON.stringify([
  { id: "block-admin", expression: 'http.request.uri.path contains "/admin"', action: "block" }
 ]));
 deepStrictEqual(setResult.success, true);

 // Should match
 const matchResult = internals.wasm_waf_evaluate(JSON.stringify({
  host: "example.com", method: "GET", path: "/admin/users", query: "",
  uri: "/admin/users", full_uri: "https://example.com/admin/users", ip_src: "1.2.3.4"
 }));
 deepStrictEqual(matchResult.matched, true);
 deepStrictEqual(matchResult.rule_id, "block-admin");
 deepStrictEqual(matchResult.action, "block");

 // Should not match
 const noMatchResult = internals.wasm_waf_evaluate(JSON.stringify({
  host: "example.com", method: "GET", path: "/index.html", query: "",
  uri: "/index.html", full_uri: "https://example.com/index.html", ip_src: "1.2.3.4"
 }));
 deepStrictEqual(noMatchResult.matched, false);

 // Update rules - old rule should no longer match
 internals.wasm_waf_set_rules(JSON.stringify([
  { id: "block-api", expression: 'http.request.uri.path contains "/api"', action: "block" }
 ]));
 const oldRuleResult = internals.wasm_waf_evaluate(JSON.stringify({
  host: "example.com", method: "GET", path: "/admin/users", query: "",
  uri: "/admin/users", full_uri: "https://example.com/admin/users", ip_src: "1.2.3.4"
 }));
 deepStrictEqual(oldRuleResult.matched, false);
 const newRuleResult = internals.wasm_waf_evaluate(JSON.stringify({
  host: "example.com", method: "GET", path: "/api/users", query: "",
  uri: "/api/users", full_uri: "https://example.com/api/users", ip_src: "1.2.3.4"
 }));
 deepStrictEqual(newRuleResult.matched, true);
 deepStrictEqual(newRuleResult.rule_id, "block-api");

 // Invalid expression
 const badResult = internals.wasm_waf_set_rules(JSON.stringify([
  { id: "bad", expression: "not valid !!!", action: "block" }
 ]));
 deepStrictEqual(badResult.success, false);
 deepStrictEqual(badResult.rule_id, "bad");
});
