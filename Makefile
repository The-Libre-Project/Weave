# Weave development commands
#
# The project targets Linux x86-64 only. Development happens on this Windows PC with
# cross-compilation (cargo-zigbuild).
#
# Quick reference:
#   make build      — cross-compile for Linux (works on any OS with cargo-zigbuild)
#   make lint       — clippy + format check
#   make test-unit  — run unit tests (PE parser/loader tests)
#   make test       — run full test suite in a Linux Docker container
#   make ci         — build + lint + full test suite

.PHONY: build lint test test-gate test-unit ci state-lint fixture-wget-probe coverage-gauge hooks backfill-notes

# ── Build ──────────────────────────────────────────────────────────────────────

build:
	cargo zigbuild --target x86_64-unknown-linux-gnu

# ── Lint ───────────────────────────────────────────────────────────────────────

lint:
	cargo clippy --target x86_64-unknown-linux-gnu -- -D warnings
	cargo fmt --check

# ── Unit tests ─────────────────────────────────────────────────────────────
# Runs PE parser and loader tests. Fast (~2s).

test-unit:
	cargo test -p weave-core -p weave-common

# ── Full test suite (Docker) ───────────────────────────────────────────────────
# Runs the complete test suite inside a Linux container.
# Uses a named volume for the Cargo build cache so rebuilds are fast.

test:
	docker run --rm --platform linux/amd64 \
		-v "$$(pwd)":/weave \
		-w /weave \
		-v weave-cargo-cache:/usr/local/cargo/registry \
		-v weave-target-cache:/weave/docker-target \
		-e CARGO_TARGET_DIR=/weave/docker-target \
		-e SDL_AUDIODRIVER=dummy \
		rust:latest \
		sh -c "apt-get update -qq && apt-get install -y -qq fonts-dejavu-core libpipewire-0.3-0 libpipewire-0.3-dev libclang-dev xvfb >/dev/null 2>&1; Xvfb :99 -screen 0 1280x720x24 & sleep 1; DISPLAY=:99 cargo test --features weave-winmm/pipewire-audio,weave-mmdevapi/pipewire-audio"

# ── Single gate test (Docker — same env as `make test` but one gate) ────────────
# Usage: make test-gate GATE=irfanview_image_open_gate

test-gate:
	@if [ -z "$(GATE)" ]; then \
		echo "Usage: make test-gate GATE=<test_name>" >&2; \
		exit 1; \
	fi
	docker run --rm --platform linux/amd64 \
		-v "$$(pwd)":/weave \
		-w /weave \
		-v weave-cargo-cache:/usr/local/cargo/registry \
		-v weave-target-cache:/weave/docker-target \
		-e CARGO_TARGET_DIR=/weave/docker-target \
		-e SDL_AUDIODRIVER=dummy \
		rust:latest \
		sh -c "apt-get update -qq && apt-get install -y -qq fonts-dejavu-core libpipewire-0.3-0 libpipewire-0.3-dev libclang-dev xvfb >/dev/null 2>&1; Xvfb :99 -screen 0 1280x720x24 & sleep 1; DISPLAY=:99 cargo test -p weave-cli --test hello_world $(GATE) --features weave-winmm/pipewire-audio,weave-mmdevapi/pipewire-audio -- --nocapture"

# ── Fixture cross-compile (mingw-w64) ──────────────────────────────────────────
# Requires x86_64-w64-mingw32-gcc on PATH. Output goes to tests/fixtures/bin/.

fixture-wget-probe:
	x86_64-w64-mingw32-gcc -O2 -o tests/fixtures/bin/wget_probe.exe tests/fixtures/src/wget_probe.c -lws2_32

# ── Coverage gauge (resolver-registered exports vs. §8 implemented) ──────────
# Runs in <5s. Requires python3. Strategy B (milestone-weighted).

coverage-gauge:
	@bash scripts/coverage-gauge.sh

# ── Git hooks (auto git-notes on commit + sync on push) ─────────────────────

hooks:
	@bash scripts/install-git-hooks.sh

backfill-notes:
	@bash scripts/backfill-git-notes.sh 30

# ── Full CI mirror ─────────────────────────────────────────────────────────────

state-lint:
	@bash scripts/state-lint.sh

ci: build lint test
