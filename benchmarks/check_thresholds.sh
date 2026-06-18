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

# Thresholds are set at ~2x the measured mean on ubuntu-latest GH Action runner

# SQL injection
check "sql" "is injection"      12000
check "sql" "is not injection"   1750 
check "sql" "big sql"         3800000

# JS injection
check "js"  "is injection"       2800
check "js"  "is not injection"   3000
check "js"  "big code"         650000

# IDOR analysis
check "idor" "simple_select"                   15000
check "idor" "select_with_join"                36000 
check "idor" "insert"                          13000
check "idor" "update"                          15000
check "idor" "cte_with_multiple_queries"       53000
check "idor" "union"                           29000
check "idor" "large_complex_query"            950000
check "idor" "col_col_simple"                  41000
check "idor" "col_col_deep_transitive_chain"  365000

echo ""
if [ "$FAILED" -ne 0 ]; then
    echo "One or more benchmarks exceeded their threshold."
    exit 1
fi
echo "All benchmarks within thresholds."
