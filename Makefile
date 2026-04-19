# Weave development commands
#
# The project targets Linux x86-64 only. Development happens on macOS with
# cross-compilation (cargo-zigbuild) for builds and Docker for tests.
#
# Quick reference:
#   make build      — cross-compile for Linux (works on macOS)
#   make lint       — clippy + format check (works on macOS)
#   make test-unit  — run unit tests natively on macOS (fast, no Docker)
#   make test       — run full test suite in a Linux Docker container
#   make ci         — build + lint + full test suite (mirrors CI pipeline)

.PHONY: build lint test test-unit ci fixture-wget-probe

# ── Build ──────────────────────────────────────────────────────────────────────

build:
	cargo zigbuild --target x86_64-unknown-linux-gnu

# ── Lint ───────────────────────────────────────────────────────────────────────

lint:
	cargo clippy --target x86_64-unknown-linux-gnu -- -D warnings
	cargo fmt --check

# ── Unit tests (native macOS — no Docker required) ────────────────────────────
# Runs PE parser and loader tests directly on macOS. Only covers weave-core
# and weave-common (the stub crates use extern "win64" which doesn't exist
# on ARM64). Fast (~2s).

test-unit:
	cargo test -p weave-core -p weave-common --target aarch64-apple-darwin

# ── Full test suite (Docker — requires OrbStack or Docker Desktop) ─────────────
# Runs the complete test suite inside a Linux container, matching CI exactly.
# First run pulls the rust image (~1.5 GB); subsequent runs use cache.
# Uses a named volume for the Cargo build cache so rebuilds are fast.

test:
	docker run --rm --platform linux/amd64 \
		-v "$$(pwd)":/weave \
		-w /weave \
		-v weave-cargo-cache:/usr/local/cargo/registry \
		-v weave-target-cache:/weave/docker-target \
		-e CARGO_TARGET_DIR=/weave/docker-target \
		rust:latest \
		sh -c "apt-get update -qq && apt-get install -y -qq fonts-dejavu-core libpipewire-0.3-0 libpipewire-0.3-dev libclang-dev xvfb >/dev/null 2>&1; Xvfb :99 -screen 0 1280x720x24 & sleep 1; DISPLAY=:99 cargo test --features weave-winmm/pipewire-audio,weave-mmdevapi/pipewire-audio"

# ── Fixture cross-compile (mingw-w64) ──────────────────────────────────────────
# Requires x86_64-w64-mingw32-gcc on PATH. Output goes to tests/fixtures/bin/.

fixture-wget-probe:
	x86_64-w64-mingw32-gcc -O2 -o tests/fixtures/bin/wget_probe.exe tests/fixtures/src/wget_probe.c -lws2_32

# ── Full CI mirror ─────────────────────────────────────────────────────────────

ci: build lint test
