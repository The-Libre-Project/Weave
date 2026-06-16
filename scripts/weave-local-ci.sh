#!/usr/bin/env bash
# weave-local-ci.sh — Agent-owned local CI runner.
#
# Replaces weave-ci-watch.sh (GitHub CI) for local CI workflows.
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

# ── Run the local CI script ──────────────────────────────────────────────────
set +e
bash "$SCRIPT_DIR/local-ci.sh" > "$OUTPUT_FILE" 2>&1
EXIT_CODE=$?
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

# ── GitHub CI recommendation ──────────────────────────────────────────────
RECOMMEND_GITHUB_CI=0
CHANGED_FILES=$(git diff HEAD~1 --name-only 2>/dev/null || echo "")
for path in weave-cli/ weave-user32/ weave-gdi32/ weave-winmm/ weave-ddraw/ weave-d3d9/ weave-vulkan/ weave-comctl32/ weave-ole32/ weave-ws2_32/ weave-advapi32/ weave-shell32/; do
  if echo "$CHANGED_FILES" | rg -q "^$path" 2>/dev/null; then
    RECOMMEND_GITHUB_CI=1
    break
  fi
done

# ── Emit result ──────────────────────────────────────────────────────────────
if [ "$EXIT_CODE" -eq 0 ]; then
  echo "=== LOCAL CI GREEN — commit $SHA passed. ==="
  echo ""
  if [ "$RECOMMEND_GITHUB_CI" -eq 1 ]; then
    echo "    Note: change touches crates exercised by integration gates."
    echo "    If needed: gh workflow run CI"
    echo "    (Skip for comment-only or build-config changes.)"
    echo ""
  fi
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
