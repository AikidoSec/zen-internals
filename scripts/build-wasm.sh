#!/usr/bin/env bash

set -euo pipefail

bindings_dir="$(mktemp -d)"
target_dir="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
trap 'rm -rf "$bindings_dir"' EXIT

wasm-pack build --target nodejs --features wasm-js
# wasm-pack cannot enable reset support, so
# rerun the pinned wasm-bindgen version to regenerate only the JS bindings.
wasm-bindgen \
  "$target_dir/wasm32-unknown-unknown/release/zen_internals.wasm" \
  --out-dir "$bindings_dir" \
  --out-name zen_internals \
  --target nodejs \
  --typescript \
  --experimental-reset-state-function
cp "$bindings_dir/zen_internals.js" "$bindings_dir/zen_internals.d.ts" pkg
