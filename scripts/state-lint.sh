#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

any_failed=0

# ── Archive step: runs first if --archive is passed ──────────────────────────

if [ "${1:-}" = "--archive" ]; then
  archive_dir="docs/archived-milestones"
  mkdir -p "$archive_dir"

  archive_date=$(date +%Y-%m-%d)
  archive_file="$archive_dir/ci-fail-archive-$archive_date.md"

  cutoff_ts=$(date -j -v-14d +%s 2>/dev/null || date -d '14 days ago' +%s)

  in_old_section=0
  kept_lines=""
  archive_lines=""
  header_kept=0

  while IFS= read -r line; do
    if echo "$line" | grep -qE '^## Fail #[0-9]+ — ([0-9]{4}-[0-9]{2}-[0-9]{2})'; then
      entry_date=$(echo "$line" | sed -E 's/^## Fail #[0-9]+ — ([0-9]{4}-[0-9]{2}-[0-9]{2}).*/\1/')
      entry_ts=$(date -j -f '%Y-%m-%d' "$entry_date" +%s 2>/dev/null || date -d "$entry_date" +%s 2>/dev/null)
      if [ "$entry_ts" -lt "$cutoff_ts" ]; then
        in_old_section=1
      else
        in_old_section=0
      fi
    fi
    if [ "$in_old_section" -eq 1 ]; then
      archive_lines="$archive_lines$line"$'\n'
    else
      kept_lines="$kept_lines$line"$'\n'
    fi
  done < CI-FAIL-LADDER.md

  if [ -n "$archive_lines" ]; then
    {
      echo "# CI Fail Archive — entries older than 14 days (archived $archive_date)"
      echo ""
      echo -n "$archive_lines"
    } > "$archive_file"
    echo "Archived old entries to $archive_file" >&2
  else
    echo "No entries older than 14 days found" >&2
  fi

  echo -n "$kept_lines" > CI-FAIL-LADDER.md
fi

# ── Check 1: SESSION-STATUS contract ──────────────────────────────────────

count_closed=$(grep -cE '^\*\*(M\d+|E3-M\d+).*CLOSED\*\*' SESSION-STATUS.md 2>/dev/null || true)
if [ "$count_closed" -gt 5 ]; then
  echo "FAIL: SESSION-STATUS.md has $count_closed CLOSED one-liners (max 5 per its own contract §Document scope)" >&2
  any_failed=1
else
  echo "PASS" >&2
fi

# ── Check 2: tasks/ staleness ─────────────────────────────────────────────

now_ts=$(date +%s)
stale_found=0

for f in tasks/*; do
  basename_f="$(basename "$f")"
  [ "$basename_f" = "done" ] || [ "$basename_f" = ".DS_Store" ] && continue
  [ -f "$f" ] || continue
  last_commit=$(git log -1 --format=%ci -- "$f" 2>/dev/null || echo "")
  if [ -z "$last_commit" ]; then
    echo "FAIL: tasks/$basename_f has no git history (untracked or never committed)" >&2
    stale_found=1
    continue
  fi
  commit_ts=$(date -j -f '%Y-%m-%d %H:%M:%S %z' "$last_commit" +%s 2>/dev/null || date -d "$last_commit" +%s 2>/dev/null)
  age_days=$(( (now_ts - commit_ts) / 86400 ))
  if [ "$age_days" -gt 14 ]; then
    echo "FAIL: tasks/$basename_f is $age_days days old (max 14) — archive to tasks/done/ or delete" >&2
    stale_found=1
  fi
done

if [ "$stale_found" -eq 0 ]; then
  echo "PASS" >&2
else
  any_failed=1
fi

# ── Check 3: git note ci: field on src commits ────────────────────────────

parent_count=$(git log -1 --format=%p HEAD | wc -w)
if [ "$parent_count" -gt 1 ]; then
  echo "PASS (merge commit, skipped)" >&2
else
  touched_src=0
  while IFS= read -r line; do
    case "$line" in
      weave-*/src/*) touched_src=1; break ;;
    esac
  done < <(git diff HEAD~1 --name-only 2>/dev/null || echo "")

  if [ "$touched_src" -eq 1 ]; then
    note=$(git notes show HEAD 2>/dev/null || echo "")
    if echo "$note" | grep -q '^ci:'; then
      echo "PASS" >&2
    else
      echo "FAIL: HEAD touches src/ but git note lacks ci: field" >&2
      any_failed=1
    fi
  else
    echo "PASS (no src/ changes, skipped)" >&2
  fi
fi

# ── Check 4: CI-FAIL-LADDER size ──────────────────────────────────────────

ladder_lines=$(wc -l < CI-FAIL-LADDER.md 2>/dev/null || echo 0)
if [ "$ladder_lines" -gt 800 ]; then
  echo "FAIL: CI-FAIL-LADDER.md is $ladder_lines lines (max 800) — archive entries older than 14 days to docs/archived-milestones/ci-fail-archive-<date>.md" >&2
  any_failed=1
else
  echo "PASS" >&2
fi

exit $any_failed
