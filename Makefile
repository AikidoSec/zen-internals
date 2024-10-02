.PHONY: build
build:
	cargo build --release

.PHONY: buildwasm
buildwasm:
	wasm-pack build --release --target nodejs --scope aikidosec

.PHONY: test
test:
	cargo test

.PHONY: lint
lint:
	cargo fmt
