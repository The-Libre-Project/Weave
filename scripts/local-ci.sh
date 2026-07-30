#!/usr/bin/env bash
# Local CI — run the same checks Weave CI would, but on your machine.
# Requires: Rust toolchain, MinGW cross-compiler (for test fixtures), system deps.
#
# Usage: bash scripts/local-ci.sh [--skip-tests]
#
# Flags:
#   --skip-tests   Skip the full test suite (just build + lint)
set -euo pipefail

echo "=== Weave Local CI ==="
echo ""

# ── Step 1: Compile test fixtures ──────────────────────────────────────────
echo "=== [1/6] Compiling test fixtures ==="
FIXTURES_SRC=tests/fixtures/src
FIXTURES_BIN=tests/fixtures/bin
mkdir -p "$FIXTURES_BIN"

# Only build if MinGW cross-compiler is available
if command -v x86_64-w64-mingw32-gcc &>/dev/null; then
  x86_64-w64-mingw32-gcc -o "$FIXTURES_BIN/hello_minimal.exe" \
    "$FIXTURES_SRC/hello_minimal.c" \
    -nostdlib -nostartfiles -lntdll \
    -Wl,--entry,entry

  x86_64-w64-mingw32-gcc -o "$FIXTURES_BIN/hello.exe" \
    "$FIXTURES_SRC/hello.c" -lkernel32

  x86_64-w64-mingw32-gcc -o "$FIXTURES_BIN/fileio.exe" \
    "$FIXTURES_SRC/fileio.c" -lkernel32

  x86_64-w64-mingw32-gcc -o "$FIXTURES_BIN/registry_basic.exe" \
    "$FIXTURES_SRC/registry_basic.c" -lkernel32 -ladvapi32

  x86_64-w64-mingw32-gcc -o "$FIXTURES_BIN/foldstringw_test.exe" \
    "$FIXTURES_SRC/foldstringw_test.c" -lkernel32

  echo "  Test fixtures compiled."
else
  echo "  WARNING: MinGW cross-compiler not found. Skipping fixture compilation."
  echo "  Install with: brew install mingw-w64 (macOS) or apt install gcc-mingw-w64 (Linux)"
fi

# ── Step 2: cargo build ────────────────────────────────────────────────────
echo ""
echo "=== [2/6] cargo build ==="
cargo build --features weave-winmm/pipewire-audio,weave-mmdevapi/pipewire-audio
echo "  Build OK."

# ── Step 3: cargo test (core tests, skip display-dependent gates) ──────────
echo ""
echo "=== [3/6] cargo test (workspace) ==="
if [[ "${1:-}" != "--skip-tests" ]]; then
  cargo test --workspace --exclude weave-cli \
    --features weave-winmm/pipewire-audio,weave-mmdevapi/pipewire-audio 2>&1
  echo "  Workspace tests OK."
else
  echo "  Skipped (--skip-tests)."
fi

# ── Step 4: cargo clippy ──────────────────────────────────────────────────
echo ""
echo "=== [4/6] cargo clippy ==="
cargo clippy --features weave-winmm/pipewire-audio,weave-mmdevapi/pipewire-audio -- -D warnings
echo "  Clippy OK."

# ── Step 5: cargo fmt ─────────────────────────────────────────────────────
echo ""
echo "=== [5/6] cargo fmt ==="
cargo fmt --check
echo "  Format OK."

# ── Step 6: Integration test (if fixture exists) ──────────────────────────
echo ""
echo "=== [6/6] Integration smoke test ==="
if [[ -f "$FIXTURES_BIN/hello.exe" ]]; then
  cargo run --bin weave -- "$FIXTURES_BIN/hello.exe" 2>&1 | head -5
  echo "  Smoke test OK."
else
  echo "  Skipped (no hello.exe fixture)."
fi

echo ""
echo "=== Weave Local CI: PASSED ==="
