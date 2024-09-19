.PHONY: build
build:
	cargo build --release

.PHONY: test
test:
	cargo test

.PHONY: lint
lint:
	cargo fmt
