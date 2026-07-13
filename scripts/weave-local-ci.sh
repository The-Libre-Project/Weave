#!/usr/bin/env bash
# weave-local-ci.sh — Agent-owned local CI runner.
#
# Only runs on macOS/Linux (has the cross-compiler). On PC, push with
# --no-verify and pull on Mac for build/test.
# Runs the full local CI suite (build + test + lint), writes structured
# result files, and emits a machine-parseable directive on failure.
#
# CONTRACT:
#   After EVERY push, the agent launches this in the BACKGROUND
#   (Bash run_in_background:true or Task subagent). The agent owns the
#   CI watch — it is never handed to the operator.
#   On a red result this script emits the mandatory /check-in directive
#   as its terminal output, so the harness re-invokes the agent with
#   that directive first in context.
#
# Result files (in REPO_ROOT):
#   .weave-local-ci-result  — structured pass/fail + commit + exit code
#   .weave-local-ci-output  — full stdout/stderr from local-ci.sh
#
# Usage: bash scripts/weave-local-ci.sh [SHA]
#   SHA defaults to HEAD. Used to record which commit was tested.
set -uo pipefail

SHA=$(git rev-parse "${1:-HEAD}" 2>/dev/null)

if [ -z "$SHA" ]; then
  echo "=== LOCAL CI: could not resolve a commit SHA. Not in a git repo? ==="
  exit 2
fi

ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RESULT_FILE="$ROOT/.weave-local-ci-result"
OUTPUT_FILE="$ROOT/.weave-local-ci-output"

echo "=== Weave Local CI Watch ==="
echo "  Commit: $SHA"
echo "  Result: $RESULT_FILE"
echo "  Output: $OUTPUT_FILE"
echo ""

# ── Run the local CI script (native first, fall back to Docker) ──────────────
set +e
bash "$SCRIPT_DIR/local-ci.sh" > "$OUTPUT_FILE" 2>&1
EXIT_CODE=$?

# If native CI fails and Docker is available, retry inside Docker
if [ "$EXIT_CODE" -ne 0 ] && command -v docker &>/dev/null; then
  echo "" >> "$OUTPUT_FILE"
  echo "--- Native CI failed. Retrying inside Docker... ---" >> "$OUTPUT_FILE"
  echo "" >> "$OUTPUT_FILE"
  bash "$SCRIPT_DIR/docker-local-ci.sh" >> "$OUTPUT_FILE" 2>&1
  EXIT_CODE=$?
fi
set -e

# ── Write structured result file ─────────────────────────────────────────────
{
  echo "exit_code: $EXIT_CODE"
  echo "commit: $SHA"
  echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "script: local-ci.sh"
  echo "passed: $([ "$EXIT_CODE" -eq 0 ] && echo 'true' || echo 'false')"
} > "$RESULT_FILE"

# Also update the git note ci: field so the observer sees health info.
if git notes show "$SHA" >/dev/null 2>&1; then
  EXISTING=$(git notes show "$SHA")
  CI_LABEL="ci: local $([ "$EXIT_CODE" -eq 0 ] && echo 'green' || echo 'red')"
  UPDATED=$(printf '%s' "$EXISTING" | sed "s/^ci:.*/$CI_LABEL/")
  git notes add -f -m "$UPDATED" "$SHA" 2>/dev/null || true
fi

# ── Update git note ci: field ────────────────────────────────────────────
if [ "$EXIT_CODE" -eq 0 ]; then
  echo "=== LOCAL CI GREEN — commit $SHA passed. ==="
  echo ""
else
  echo "=== LOCAL CI RED — commit $SHA FAILED (exit code $EXIT_CODE). ==="
  echo "    Output: $OUTPUT_FILE (last 50 lines below)"
  echo ""
  tail -50 "$OUTPUT_FILE"
  echo ""
  echo "    MANDATORY: run /check-in BEFORE writing any fix code."
  echo "    The four-question gate decides QUICK vs ARC and writes CI-FAIL-LADDER.md."
  echo ""
fi

exit "$EXIT_CODE"
