.PHONY: build
build:
	cargo build --release

.PHONY: buildwasm
buildwasm:
	wasm-pack build --target bundler

.PHONY: test
test:
	cargo test

.PHONY: lint
lint:
	cargo fmt
