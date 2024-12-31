.PHONY: build
build:
	cargo build --release

.PHONY: test
test:
	cargo test

.PHONY: lint
lint:
	cargo fmt

.PHONY: smoketest
smoketest:
	node smoketests/wasm.js
	deno run --allow-ffi smoketests/ffi.ts

.PHONY: bench
bench:
	cd benchmarks && cargo bench
