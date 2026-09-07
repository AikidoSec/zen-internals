#!/usr/bin/env bash

set -euo pipefail

if grep -q '^\[profile\.wasm\]' Cargo.toml; then
  exec wasm-pack build --profile wasm --target nodejs --features wasm-js
fi

export CARGO_PROFILE_RELEASE_OPT_LEVEL=2
exec wasm-pack build --target nodejs --features wasm-js
