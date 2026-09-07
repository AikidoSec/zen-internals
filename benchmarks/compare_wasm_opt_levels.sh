#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

opt_levels=(s 2 3)

for opt_level in "${opt_levels[@]}"; do
  echo "Building WASM with opt-level ${opt_level}"
  CARGO_PROFILE_WASM_OPT_LEVEL="$opt_level" \
    CARGO_TARGET_DIR="target/wasm-opt-level-${opt_level}" \
    wasm-pack build \
      --profile wasm \
      --target nodejs \
      --out-dir "pkg-opt-level-${opt_level}" \
      --features wasm-js
done

variants=()
for opt_level in "${opt_levels[@]}"; do
  variants+=("${opt_level}=pkg-opt-level-${opt_level}/zen_internals.js")
done

node --expose-gc benchmarks/compare_wasm_opt_levels.mjs "${variants[@]}"
