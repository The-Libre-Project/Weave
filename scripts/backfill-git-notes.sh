#!/usr/bin/env bash
# Backfill stub git notes on recent commits and push refs/notes/commits.
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

count=${1:-30}
exec "${ROOT}/scripts/install-git-hooks.sh" --backfill "$count"
