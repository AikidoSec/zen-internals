.PHONY: build
build:
	cargo build --release

.PHONY: buildwasm
buildwasm:
	wasm-pack build --target nodejs

.PHONY: test
test:
	cargo test

.PHONY: lint
lint:
	cargo fmt
