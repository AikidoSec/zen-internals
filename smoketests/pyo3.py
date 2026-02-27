"""Smoke test for PyO3 Python bindings."""
import json
import sys

try:
    import zen_internals
except ImportError:
    print("❌ Could not import zen_internals – run `maturin develop --features python` first")
    sys.exit(1)

# detect_sql_injection: injection detected
assert zen_internals.detect_sql_injection(
    "select * from users where id = '' or 1=1 -- '",
    "' or 1=1 -- ",
    0,
) == 1, "should detect injection"

# detect_sql_injection: clean query
assert zen_internals.detect_sql_injection(
    "SELECT * FROM users WHERE id = 'hello world'",
    "hello world",
    0,
) == 0, "should not detect injection"

# detect_sql_injection: tokenization failure → code 3
assert zen_internals.detect_sql_injection(
    'SELECT unicorns fly over the "rainbow',
    "rainbow",
    0,
) == 3, "should return 3 on tokenize failure"

# idor_analyze_sql: basic SELECT
result = json.loads(zen_internals.idor_analyze_sql(
    "SELECT * FROM users WHERE tenant_id = $1", 9
))
assert result == [
    {
        "kind": "select",
        "tables": [{"name": "users"}],
        "filters": [{"column": "tenant_id", "value": "$1", "is_placeholder": True}],
    }
], f"unexpected result: {result}"

# idor_analyze_sql: error on invalid SQL
result = json.loads(zen_internals.idor_analyze_sql("INVALID SQL QUERY", 9))
assert "error" in result, f"expected error key, got: {result}"

# idor_analyze_sql: transaction statement returns empty list
result = json.loads(zen_internals.idor_analyze_sql("COMMIT", 9))
assert result == [], f"expected [], got: {result}"

print("✅ PyO3 smoketest passed")
