#!/usr/bin/env bash
# weave-ci-watch.sh — Agent-owned CI watch.
#
# CONTRACT (see CLAUDE.md "CI watch ownership"):
#   After EVERY push, the agent launches this in the BACKGROUND (Bash run_in_background:true).
#   The agent owns the CI watch — it is never handed to the operator.
#   On a red result this script emits the mandatory /check-in directive as its terminal output,
#   so the harness re-invokes the agent with that directive first in context. The trigger for
#   /check-in is therefore mechanical, not dependent on agent memory.
#
# Usage: scripts/weave-ci-watch.sh [SHA]   (SHA defaults to HEAD)
set -uo pipefail

# Always resolve to full 40-char SHA so the exact-match jq filter works whether
# the caller passes a short ref, branch name, or full SHA.
SHA=$(git rev-parse "${1:-HEAD}" 2>/dev/null)
WORKFLOW="CI"

if [ -z "$SHA" ]; then
  echo "=== CI WATCH: could not resolve a commit SHA. Not in a git repo? ==="
  exit 2
fi

# 1. Wait for a run to appear for this SHA (GitHub lags a few seconds after push).
RUN_ID=""
for _ in $(seq 1 20); do
  RUN_ID=$(gh run list --workflow="$WORKFLOW" --limit 20 --json databaseId,headSha \
            -q ".[] | select(.headSha==\"$SHA\") | .databaseId" 2>/dev/null | head -1)
  [ -n "$RUN_ID" ] && break
  sleep 15
done

if [ -z "$RUN_ID" ]; then
  echo "=== CI WATCH: no $WORKFLOW run appeared for $SHA after ~5min."
  echo "    MANDATORY: investigate why CI did not trigger before assuming green. ==="
  exit 2
fi

echo "weave-ci-watch: watching run $RUN_ID for $SHA"

# 2. Block until the run concludes. --exit-status makes gh exit non-zero on failure.
gh run watch "$RUN_ID" --exit-status >/dev/null 2>&1
STATUS=$?

# 3. Emit the result. On non-zero, fire the /check-in directive.
if [ "$STATUS" -eq 0 ]; then
  echo "=== CI GREEN — run $RUN_ID ($SHA) passed. ==="
  # Auto-update ci: field in git notes so the observer sees CI health without
  # manual backfill. Silently skipped if the commit has no note or sed fails.
  if git notes show "$SHA" >/dev/null 2>&1; then
    EXISTING=$(git notes show "$SHA")
    UPDATED=$(printf '%s' "$EXISTING" | sed "s/^ci:.*/ci: green (run $RUN_ID)/")
    git notes add -f -m "$UPDATED" "$SHA" 2>/dev/null || true
  fi
else
  echo "=== CI RED — run $RUN_ID ($SHA) FAILED."
  echo "    MANDATORY: run /check-in BEFORE writing any fix code. Do not diagnose, do not edit first."
  echo "    The four-question gate decides QUICK vs ARC and writes CI-FAIL-LADDER.md."
  echo "    (Enforced by CLAUDE.md 'CI watch ownership'.) ==="
fi
exit "$STATUS"
