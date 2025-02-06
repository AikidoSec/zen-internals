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

.PHONY: bench
bench:
	cd benchmarks && cargo bench
