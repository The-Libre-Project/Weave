#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

WHITELIST_FILE="$ROOT/scripts/wine-ref-whitelist.txt"
violations=0

while IFS= read -r -d '' file; do
  results=$(grep -nE '^pub( unsafe)? fn [_a-zA-Z0-9]+' "$file" 2>/dev/null || true)
  [ -z "$results" ] && continue

  while IFS=: read -r line content; do
    func_name=$(echo "$content" \
      | sed -n 's/^pub\( unsafe\)* fn \([a-zA-Z0-9_]*\).*/\2/p')
    [ -z "$func_name" ] && continue

    if [ -f "$WHITELIST_FILE" ] \
      && grep -qFx "$func_name" "$WHITELIST_FILE"; then
      continue
    fi

    start=$((line - 5))
    [ "$start" -lt 1 ] && start=1
    context=$(sed -n "${start},${line}p" "$file")

    if ! echo "$context" | grep -q 'Wine ref:'; then
      echo "VIOLATION: $file:$line — pub fn $func_name missing Wine ref comment"
      violations=$((violations + 1))
    fi
  done <<< "$results"
done < <(find weave-kernel32/src weave-user32/src weave-ntdll/src \
  -name '*.rs' ! -path '*/test*' ! -path '*/tests/*' -print0)

if [ "$violations" -gt 0 ]; then
  echo ""
  echo "FAILED: $violations pub fn(s) missing Wine ref citation(s)"
  exit 1
fi

echo "OK: all pub fn(s) in weave-kernel32, weave-user32, weave-ntdll have Wine ref citations"
