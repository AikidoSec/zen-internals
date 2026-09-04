#!/usr/bin/env bash

set -euo pipefail

wasm_path="target/wasm32-unknown-unknown/release/zen_internals.wasm"

cargo build --target wasm32-unknown-unknown --release

# Limit single-caller inlining so Chicory does not generate JVM methods larger than 64 KB.
wasm-opt \
  -O \
  --one-caller-inline-max-function-size=512 \
  --enable-bulk-memory \
  --enable-sign-ext \
  --enable-nontrapping-float-to-int \
  "$wasm_path" \
  -o "$wasm_path"
