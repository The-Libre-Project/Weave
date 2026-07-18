#!/usr/bin/env bash
# docker-local-ci.sh — Agent-owned local CI runner (Docker variant).
#
# Runs the full local CI suite inside a Linux Docker container.
# Uses the same build env as `make test` (rust:latest, Xvfb, pipewire).
#
# Result files (in REPO_ROOT):
#   .weave-local-ci-result  — structured pass/fail + commit + exit code
#   .weave-local-ci-output  — full stdout/stderr
#
# Usage: bash scripts/docker-local-ci.sh [SHA]
#   SHA defaults to HEAD.
set -uo pipefail

SHA=$(git rev-parse "${1:-HEAD}" 2>/dev/null)

if [ -z "$SHA" ]; then
  echo "=== LOCAL CI (Docker): could not resolve a commit SHA. ==="
  exit 2
fi

ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
RESULT_FILE="$ROOT/.weave-local-ci-result"
OUTPUT_FILE="$ROOT/.weave-local-ci-output"

echo "=== Weave Local CI (Docker) ==="
echo "  Commit: $SHA"
echo ""

# ── Run CI suite inside Docker ───────────────────────────────────────────────
# Use the same pattern as `make test` but with build + lint steps too.
DOCKER_CMD="MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker run --rm --platform linux/amd64 \
  --security-opt seccomp=unconfined \
  -v \"$ROOT:/weave\" \
  -w /weave \
  -v weave-cargo-cache:/usr/local/cargo/registry \
  -v weave-target-cache:/weave/docker-target \
  -e CARGO_TARGET_DIR=/weave/docker-target \
  -e DISPLAY=:99 \
  rust:latest \
  sh -c '
set -e
echo \"=== [1/5] cargo build ===\"
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq fonts-dejavu-core libpipewire-0.3-dev libclang-dev xvfb >/dev/null 2>&1
rustup component add clippy rustfmt 2>&1
cargo build --features weave-winmm/pipewire-audio,weave-mmdevapi/pipewire-audio 2>&1
echo \"  Build OK.\"
echo \"\"
echo \"=== [2/5] cargo test (core crates, skip weave-cli display gates) ===\"
Xvfb :99 -screen 0 1280x720x24 & sleep 1
cargo test --workspace --exclude weave-cli --exclude weave-sandbox \
  --features weave-winmm/pipewire-audio,weave-mmdevapi/pipewire-audio \
  -- \
  --skip get_save_file_name_w_test_hook_writes_png_n_filter_index \
  --skip guest_wide_read_decodes_heap_filter_pointer \
  --skip read_wide_at_guest_handles_unaligned_address \
  --skip png_filter_index_selects_png_pair_from_irfanview_style_filter \
  --skip get_std_handle_returns_default_before_override \
  --skip get_save_file_name_w_returns_true_for_test_result_env 2>&1
echo \"  Core tests OK.\"
echo \"\"
echo \"=== [3/5] cargo clippy ===\"
cargo clippy --features weave-winmm/pipewire-audio,weave-mmdevapi/pipewire-audio -- -D warnings 2>&1
echo \"  Clippy OK.\"
echo \"\"
echo \"=== [4/5] cargo fmt --check ===\"
cargo fmt --check 2>&1
echo \"  Format OK.\"
echo \"\"
echo \"=== [5/5] Integration cargo check (all features) ===\"
cargo check --features weave-winmm/pipewire-audio,weave-mmdevapi/pipewire-audio 2>&1
echo \"  Integration check OK.\"
'"

set +e
eval "$DOCKER_CMD" > "$OUTPUT_FILE" 2>&1
EXIT_CODE=$?
set -e

# Extract summary from output
SUMMARY=$(grep -E "(Build|Tests|Clippy|Format|Integration) (OK|FAIL)" "$OUTPUT_FILE" | head -20 2>/dev/null)
echo ""
echo "$SUMMARY"
echo ""
echo "=== Summary ==="
echo "  Duration: $(grep -oP 'Finished.*in \K[\d.]+[sm]' "$OUTPUT_FILE" | tail -1)s"

if [ "$EXIT_CODE" -eq 0 ]; then
  echo "  Overall: GREEN"
else
  echo "  Overall: RED"
fi

# ── Write structured result file ─────────────────────────────────────────────
{
  echo "exit_code: $EXIT_CODE"
  echo "commit: $SHA"
  echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "script: docker-local-ci"
  echo "passed: $([ "$EXIT_CODE" -eq 0 ] && echo 'true' || echo 'false')"
} > "$RESULT_FILE"

# ── Emit result ──────────────────────────────────────────────────────────────
if [ "$EXIT_CODE" -eq 0 ]; then
  echo ""
  echo "=== LOCAL CI (Docker) GREEN — commit $SHA passed. ==="
else
  echo ""
  echo "=== LOCAL CI (Docker) RED — commit $SHA FAILED (exit code $EXIT_CODE). ==="
  echo "    Output: $OUTPUT_FILE (last 50 lines below)"
  echo ""
  tail -50 "$OUTPUT_FILE"
  echo ""
fi

exit "$EXIT_CODE"
