#!/usr/bin/env bash
set -euo pipefail

CRITERION_DIR="${1:-../target/criterion}"
FAILED=0

check() {
    local group="$1"
    local bench="$2"
    local threshold_ns="$3"
    local estimates_file="${CRITERION_DIR}/${group}/${bench}/new/estimates.json"

    if [ ! -f "$estimates_file" ]; then
        echo "MISSING: ${group}/${bench} — no estimates file at ${estimates_file}"
        FAILED=1
        return
    fi

    local mean_ns result
    mean_ns=$(jq '.mean.point_estimate' "$estimates_file")
    result=$(jq -r --argjson t "$threshold_ns" 'if .mean.point_estimate > $t then "FAIL" else "OK" end' "$estimates_file")

    if [ "$result" = "FAIL" ]; then
        printf "FAIL: %-45s %10.0f ns  >  threshold %d ns\n" "${group}/${bench}" "$mean_ns" "$threshold_ns"
        FAILED=1
    else
        printf "OK:   %-45s %10.0f ns  (threshold: %d ns)\n" "${group}/${bench}" "$mean_ns" "$threshold_ns"
    fi
}

# Thresholds are set at ~1.5x the measured mean on ubuntu-latest GH Action runner

# SQL injection
check "sql" "is injection"       9000
check "sql" "is not injection"   1300
check "sql" "big sql"         2850000

# JS injection
check "js"  "is injection"       2100
check "js"  "is not injection"   2250
check "js"  "big code"         488000

# IDOR analysis
check "idor" "simple_select"                   11000
check "idor" "select_with_join"                27000
check "idor" "insert"                           9750
check "idor" "update"                          11000
check "idor" "cte_with_multiple_queries"       40000
check "idor" "union"                           22000
check "idor" "large_complex_query"            712500
check "idor" "col_col_simple"                  31000
check "idor" "col_col_deep_transitive_chain"  274000

echo ""
if [ "$FAILED" -ne 0 ]; then
    echo "One or more benchmarks exceeded their threshold."
    exit 1
fi
echo "All benchmarks within thresholds."
