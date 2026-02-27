.PHONY: build
build:
	cargo build --release

.PHONY: build-python
build-python:
	maturin develop --features python

.PHONY: test
test:
	cargo test

.PHONY: lint
lint:
	cargo fmt

.PHONY: smoketest
smoketest:
	node smoketests/wasm.js
# Deno doesn't change the exit code when a panic occurs, so we have to check the output
	@{ \
		output=$$(deno run --allow-ffi smoketests/ffi.ts 2>&1); \
		if echo "$$output" | grep -q "panic"; then \
			echo "❌ Smoketest failed: panic detected"; \
			echo "$$output"; \
			exit 1; \
		else \
			echo "✅ Smoketest passed (no panics detected)"; \
		fi \
	}

.PHONY: smoketest-python
smoketest-python:
	maturin develop --features python
	python3 smoketests/pyo3.py

.PHONY: playground
playground:
	wasm-pack build --target web --features wasm-js
	ln -sfn ../pkg playground/pkg
	@echo "Open http://localhost:8080"
	python3 -m http.server 8080 --directory playground

.PHONY: bench
bench:
	cd benchmarks && cargo bench
