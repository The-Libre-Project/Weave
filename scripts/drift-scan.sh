#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TODAY=$(date +%Y-%m-%d)

# Cross-platform date-to-seconds: linux uses date -d, macOS uses date -j -f
date_to_sec() {
  local d="$1"
  if date -d "$d" +%s >/dev/null 2>&1; then
    date -d "$d" +%s 2>/dev/null || echo 0
  elif date -j -f "%Y-%m-%d" "$d" +%s >/dev/null 2>&1; then
    date -j -f "%Y-%m-%d" "$d" +%s 2>/dev/null || echo 0
  else
    echo 0
  fi
}

date_valid() {
  local d="$1"
  if date -d "$d" +%s >/dev/null 2>&1; then
    return 0
  elif date -j -f "%Y-%m-%d" "$d" +%s >/dev/null 2>&1; then
    return 0
  fi
  return 1
}
REPORT_DIR="$ROOT/reports"
REPORT="$REPORT_DIR/drift-scan-$TODAY.md"

mkdir -p "$REPORT_DIR"

HARD_VIOLATIONS=()
WARNINGS=()
INFO=()
CLEAN_CHECKS=()

# ── Check 1: Quarantined test inventory ──────────────────────────────
QUARANTINE_DIR="$ROOT/weave-cli/tests/quarantined"
KNOWN_BUGS="$ROOT/docs/reference/KNOWN-BUG-CLASSES.md"
q_unreferenced=()

if [ -d "$QUARANTINE_DIR" ]; then
  while IFS= read -r -d '' qfile; do
    basename_q=$(basename "$qfile")
    # Extract #[ignore] test function names
    in_ignore=false
    current_fn=""
    while IFS= read -r line; do
      if echo "$line" | grep -q '\[ignore\]'; then
        in_ignore=true
      elif $in_ignore && echo "$line" | grep -qE '^fn [a-zA-Z_][a-zA-Z0-9_]*'; then
        current_fn=$(echo "$line" | sed -n 's/^fn \([a-zA-Z_][a-zA-Z0-9_]*\).*/\1/p')
        if [ -n "$current_fn" ]; then
          if [ -f "$KNOWN_BUGS" ] && grep -qF "$current_fn" "$KNOWN_BUGS"; then
            :
          else
            q_unreferenced+=("$current_fn (in $basename_q)")
          fi
        fi
        in_ignore=false
        current_fn=""
      elif echo "$line" | grep -qE '^fn [a-zA-Z_][a-zA-Z0-9_]*'; then
        in_ignore=false
      fi
    done < "$qfile"
  done < <(find "$QUARANTINE_DIR" -name '*.rs' -print0)
fi

if [ ${#q_unreferenced[@]} -gt 0 ]; then
  HARD_VIOLATIONS+=("Quarantined test(s) missing from KNOWN-BUG-CLASSES.md:")
  for item in "${q_unreferenced[@]}"; do
    HARD_VIOLATIONS+=("$item")
  done
else
  CLEAN_CHECKS+=("All quarantined tests are referenced in KNOWN-BUG-CLASSES.md")
fi

# ── Check 2: RELEASE-CLAIMS freshness ────────────────────────────────
RC_FILE="$ROOT/docs/RELEASE-CLAIMS.md"
claims_no_date=0
claims_stale_date=0

if [ -f "$RC_FILE" ]; then
  in_table=false
  while IFS= read -r line; do
    # Check separator first (before pipe-content pattern, since separators also match it)
    if echo "$line" | grep -qE '^\|---'; then
      in_table=true
      continue
    fi
    if $in_table && echo "$line" | grep -qE '^\|.*\|.*\|.*\|.*\|$'; then
      # Check if this data row has a YES or NO in the last column
      claim_status=$(echo "$line" | awk -F'|' '{print $5}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
      if echo "$claim_status" | grep -qE '^(YES|NO)'; then
        # Check for date in the line (look for YYYY-MM-DD pattern)
        if ! echo "$line" | grep -qE '[0-9]{4}-[0-9]{2}-[0-9]{2}'; then
          claims_no_date=$((claims_no_date + 1))
        fi
      fi
    fi
  done < "$RC_FILE"

  # Check the Last full audit date
  last_audit=$(grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' "$RC_FILE" | tail -1)
  if [ -n "$last_audit" ]; then
    if date_valid "$last_audit"; then
      last_sec=$(date_to_sec "$last_audit")
      now_sec=$(date +%s)
      age_days=$(( (now_sec - last_sec) / 86400 ))
      if [ "$age_days" -gt 30 ]; then
        WARNINGS+=("RELEASE-CLAIMS.md last full audit ($last_audit) is $age_days days old (max 30)")
      else
        CLEAN_CHECKS+=("RELEASE-CLAIMS.md last full audit ($last_audit) is $age_days days old (within 30-day window)")
      fi
    else
      WARNINGS+=("RELEASE-CLAIMS.md last full audit date ($last_audit) is not a valid date")
    fi
  else
    WARNINGS+=("RELEASE-CLAIMS.md has no last full audit date")
  fi

  if [ "$claims_no_date" -gt 0 ]; then
    WARNINGS+=("$claims_no_date RELEASE-CLAIMS.md row(s) lack a last-verified date")
  fi
else
  CLEAN_CHECKS+=("RELEASE-CLAIMS.md not found — skipped")
fi

# ── Check 3: OBSERVER-STATE freshness ────────────────────────────────
OS_FILE="$ROOT/OBSERVER-STATE.md"
if [ -f "$OS_FILE" ]; then
  os_date=$(grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' "$OS_FILE" | head -1)
  if [ -n "$os_date" ]; then
    if date_valid "$os_date"; then
      os_sec=$(date_to_sec "$os_date")
      now_sec=$(date +%s)
      os_age=$(( (now_sec - os_sec) / 86400 ))
      if [ "$os_age" -gt 14 ]; then
        WARNINGS+=("OBSERVER-STATE.md last updated $os_date ($os_age days ago) — older than 14 days")
      else
        CLEAN_CHECKS+=("OBSERVER-STATE.md last updated $os_date ($os_age days ago) — within 14-day window")
      fi
    else
      WARNINGS+=("OBSERVER-STATE.md date ($os_date) is not a valid date")
    fi
  else
    WARNINGS+=("OBSERVER-STATE.md has no date — cannot check freshness")
  fi
fi

# ── Check 4: Cargo.toml license vs LICENSE file ─────────────────────
if grep -q 'license' "$ROOT/Cargo.toml" 2>/dev/null; then
  if grep 'license' "$ROOT/Cargo.toml" | grep -q 'GPL-3.0'; then
    CLEAN_CHECKS+=("Cargo.toml license field is GPL-3.0")
  else
    HARD_VIOLATIONS+=("Cargo.toml license field does not contain GPL-3.0")
  fi
else
  HARD_VIOLATIONS+=("Cargo.toml has no license field")
fi

# ── Check 5: Wine ref citation check (reporting mode) ────────────────
WINE_REF_SCRIPT="$ROOT/scripts/check-wine-refs.sh"
if [ -f "$WINE_REF_SCRIPT" ]; then
  wine_violations=0
  wine_output=$(bash "$WINE_REF_SCRIPT" 2>&1 || wine_violations=$?)
  if [ "$wine_violations" -gt 0 ]; then
    while IFS= read -r line; do
      if echo "$line" | grep -q 'VIOLATION:'; then
        WARNINGS+=("Wine ref: $line")
      fi
    done <<< "$wine_output"
    # Count the total
    total_wine=$(echo "$wine_output" | grep -c 'VIOLATION:' || true)
    if [ "$total_wine" -gt 0 ]; then
      CLEAN_CHECKS+=("Wine ref check ran — $total_wine violation(s) reported (non-blocking)")
    fi
  else
    CLEAN_CHECKS+=("All pub fns in weave-kernel32, weave-user32, weave-ntdll have Wine ref citations")
  fi
else
  WARNINGS+=("check-wine-refs.sh not found — Wine ref check skipped")
fi

# ── Check 6: Stale files in weave-*/src/ ─────────────────────────────
stale_files=()
while IFS= read -r -d '' f; do
  stale_files+=("$f")
done < <(find "$ROOT"/weave-*/src/ -name '*.rs' -type f -mtime +90 -print0 2>/dev/null || true)

if [ ${#stale_files[@]} -gt 0 ]; then
  INFO+=("${#stale_files[@]} source file(s) not modified in 90+ days:")
  idx=0
  for sf in "${stale_files[@]}"; do
    rel="${sf#$ROOT/}"
    mod_time=$(stat -f "%Sm" -t "%Y-%m-%d" "$sf" 2>/dev/null || stat -c "%y" "$sf" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
    INFO+=("  $rel (last modified: $mod_time)")
    idx=$((idx + 1))
    if [ "$idx" -ge 20 ]; then
      INFO+=("  ... and $((${#stale_files[@]} - 20)) more")
      break
    fi
  done
else
  CLEAN_CHECKS+=("No stale source files (>90 days) in weave-*/src/")
fi

# ── Write report ──────────────────────────────────────────────────────
{
  echo "# Drift Scan — $TODAY"
  echo ""
  echo "Automated drift detection report. Generated by \`scripts/drift-scan.sh\`."
  echo ""
  echo "---"
  echo ""

  # Hard violations
  echo "## Hard violations (action required)"
  echo ""
  if [ ${#HARD_VIOLATIONS[@]} -gt 0 ]; then
    i=0
    for item in "${HARD_VIOLATIONS[@]}"; do
      if [ $i -eq 0 ]; then
        echo "- $item"
      else
        echo "  - $item"
      fi
      i=$((i + 1))
    done
  else
    echo "_None_"
  fi
  echo ""
  echo "---"
  echo ""

  # Warnings
  echo "## Warnings (review recommended)"
  echo ""
  if [ ${#WARNINGS[@]} -gt 0 ]; then
    for item in "${WARNINGS[@]}"; do
      echo "- $item"
    done
  else
    echo "_None_"
  fi
  echo ""
  echo "---"
  echo ""

  # Informational
  echo "## Informational"
  echo ""
  if [ ${#INFO[@]} -gt 0 ]; then
    for item in "${INFO[@]}"; do
      echo "- $item"
    done
  else
    echo "_None_"
  fi
  echo ""
  echo "---"
  echo ""

  # Clean checks
  echo "## Clean checks"
  echo ""
  if [ ${#CLEAN_CHECKS[@]} -gt 0 ]; then
    for item in "${CLEAN_CHECKS[@]}"; do
      echo "- $item"
    done
  else
    echo "_None_"
  fi
  echo ""
  echo "---"
  echo ""

  echo "_Scanner exit code: 0 (informational only — no deployment is blocked by this report)_"
} > "$REPORT"

echo "Drift scan written to $REPORT"
exit 0
