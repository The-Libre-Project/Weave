#!/usr/bin/env bash
# Tripwire: fail if Gate 5 max_phase hasn't advanced in 3 consecutive CI runs.
# Called from CI after gate5-progress.jsonl is written for this run.
#
# Requires: gh CLI (pre-installed on ubuntu-latest), GITHUB_TOKEN in env as GH_TOKEN.
set -euo pipefail

REPO="${GITHUB_REPOSITORY:-}"
if [ -z "$REPO" ]; then
  echo "Not in CI — skipping tripwire check"
  exit 0
fi

if [ ! -f gate5-progress.jsonl ]; then
  echo "No gate5-progress.jsonl — skipping tripwire check"
  exit 0
fi

# Current run's max_phase
CURRENT_PHASE=$(tail -1 gate5-progress.jsonl \
  | python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["max_phase"])' 2>/dev/null || echo "0")
CURRENT_NAME=$(tail -1 gate5-progress.jsonl \
  | python3 -c 'import sys,json; print(json.loads(sys.stdin.read()).get("phase_name","unknown"))' 2>/dev/null || echo "unknown")

echo "Current max_phase: $CURRENT_PHASE ($CURRENT_NAME)"

# Get last 2 completed run IDs for this workflow (excluding current run)
CURRENT_RUN_ID="${GITHUB_RUN_ID:-}"
PREV_RUN_IDS=$(gh run list \
  --repo "$REPO" \
  --workflow ci.yml \
  --status completed \
  --limit 5 \
  --json databaseId \
  --jq '.[].databaseId' \
  2>/dev/null | grep -v "^${CURRENT_RUN_ID}$" | head -2 || echo "")

if [ -z "$PREV_RUN_IDS" ]; then
  echo "No previous completed runs found — skipping tripwire"
  exit 0
fi

PHASES=("$CURRENT_PHASE")
mkdir -p /tmp/tripwire-artifacts

for RUN_ID in $PREV_RUN_IDS; do
  ARTIFACT_NAME=$(gh api "repos/$REPO/actions/runs/$RUN_ID/artifacts" \
    --jq '.artifacts[] | select(.name | startswith("gate5-progress")) | .name' \
    2>/dev/null | head -1 || echo "")

  if [ -z "$ARTIFACT_NAME" ]; then
    echo "No gate5-progress artifact for run $RUN_ID — skipping"
    continue
  fi

  gh run download "$RUN_ID" \
    --repo "$REPO" \
    -n "$ARTIFACT_NAME" \
    --dir "/tmp/tripwire-artifacts/$RUN_ID" \
    2>/dev/null || { echo "Download failed for run $RUN_ID — skipping"; continue; }

  PHASE=$(cat "/tmp/tripwire-artifacts/$RUN_ID/gate5-progress.jsonl" 2>/dev/null \
    | tail -1 \
    | python3 -c 'import sys,json; print(json.loads(sys.stdin.read())["max_phase"])' 2>/dev/null \
    || echo "0")

  echo "Previous run $RUN_ID max_phase: $PHASE"
  PHASES+=("$PHASE")
done

# Need 3 data points for the tripwire to fire
if [ "${#PHASES[@]}" -lt 3 ]; then
  echo "Only ${#PHASES[@]} data point(s) — need 3 for tripwire. Skipping."
  exit 0
fi

UNIQUE=$(printf '%s\n' "${PHASES[@]}" | sort -u | wc -l | tr -d ' ')

if [ "$UNIQUE" -eq 1 ]; then
  echo ""
  echo "=========================================="
  echo "  TRIPWIRE FIRED"
  echo "=========================================="
  echo "  max_phase=${PHASES[0]} has not advanced"
  echo "  across the last 3 consecutive CI runs."
  echo ""
  echo "  STOP. Do not make a 4th fix attempt."
  echo "  Write a new hypothesis in INVESTIGATION-LOG.md"
  echo "  before continuing."
  echo "=========================================="
  exit 1
fi

echo "Tripwire OK: phases across last ${#PHASES[@]} runs = ${PHASES[*]}"
exit 0
