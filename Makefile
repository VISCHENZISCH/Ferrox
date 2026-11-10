CARGO ?= cargo
HARDEN := -C link-arg=-Wl,-z,relro,-z,now -C link-arg=-Wl,-z,noexecstack
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

.PHONY: build release test lint fmt check audit cov dist dist-windows asan tsan miri valgrind clean

build:            ## compilation de développement
	$(CARGO) build --workspace

release:          ## binaires optimisés et durcis (Linux)
	RUSTFLAGS="$(HARDEN)" $(CARGO) build --workspace --release

test:
	$(CARGO) test --workspace

lint:             ## équivalent -Wall (bloquant) puis -Wpedantic (informatif)
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	-$(CARGO) clippy --workspace --all-targets -- -W clippy::pedantic

fmt:
	$(CARGO) fmt --all -- --check

check: fmt lint test   ## tout ce que la CI vérifie

audit:            ## vulnérabilités et licences des dépendances
	$(CARGO) audit
	$(CARGO) deny check

cov:
	$(CARGO) llvm-cov -p ferrox-core --summary-only

dist: release     ## archive Linux dans dist/
	mkdir -p dist/ferrox-$(VERSION)-linux-x86_64
	cp target/release/ferrox target/release/ferroxd README.md LICENSE CHANGELOG.md \
	   config/ferrox.example.toml packaging/ferroxd.service dist/ferrox-$(VERSION)-linux-x86_64/
	tar -C dist -czf dist/ferrox-$(VERSION)-linux-x86_64.tar.gz ferrox-$(VERSION)-linux-x86_64
	cd dist && sha256sum ferrox-$(VERSION)-linux-x86_64.tar.gz > ferrox-$(VERSION)-linux-x86_64.tar.gz.sha256

dist-windows:     ## exécutables Windows par compilation croisée (mingw-w64)
	rustup target add x86_64-pc-windows-gnu
	$(CARGO) build --workspace --release --target x86_64-pc-windows-gnu

asan:
	RUSTFLAGS="-Zsanitizer=address" $(CARGO) +nightly test -p ferrox-core \
	  --target x86_64-unknown-linux-gnu

tsan:
	RUSTFLAGS="-Zsanitizer=thread" $(CARGO) +nightly test -p ferrox-core \
	  -Zbuild-std --target x86_64-unknown-linux-gnu

miri:
	$(CARGO) +nightly miri test -p ferrox-core --lib

valgrind: build
	valgrind --leak-check=full ./target/debug/ferroxd run -c config/ferrox.example.toml

clean:
	$(CARGO) clean
