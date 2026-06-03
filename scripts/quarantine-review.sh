#!/usr/bin/env bash
# Organ C — Quarantine Review (retrospective governor at /check-in stamp)
# Read-only by default. --stamp updates docs/QUARANTINE-LEDGER.md "Last reviewed" snapshot.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

LEDGER="${REPO_ROOT}/docs/QUARANTINE-LEDGER.md"
CI_YML="${REPO_ROOT}/.github/workflows/ci.yml"
LADDER="${REPO_ROOT}/CI-FAIL-LADDER.md"
ARCS="${REPO_ROOT}/docs/loop-arcs"
Q_MAX=2
M_ABSOLUTE=8

stamp_mode=false
fixture_mode=false
for arg in "$@"; do
  case "$arg" in
    --stamp) stamp_mode=true ;;
    --fixture) fixture_mode=true ;;
  esac
done

if [[ ! -f "$LEDGER" ]]; then
  echo "ERROR: missing $LEDGER"
  exit 1
fi

list_quarantined_gates() {
  if $fixture_mode; then
    echo "acceptance_test_unaccounted_gate"
    return
  fi
  grep 'hello_world' "$CI_YML" | sed -n 's/.*hello_world \([a-zA-Z0-9_]*\).*/\1/p' | while read -r gate; do
    [[ -z "$gate" ]] && continue
    if grep -F "hello_world ${gate}" "$CI_YML" | grep -q '|| true'; then
      echo "$gate"
    fi
  done | sort -u
}

strike_count_for_gate() {
  local gate="$1"
  if [[ ! -f "$LADDER" ]]; then
    echo 0
    return
  fi
  local explicit
  explicit=$(grep -E "Strike count:.*${gate}" "$LADDER" 2>/dev/null | head -1 | sed -n 's/.*Strike count:[^0-9]*\([0-9][0-9]*\) of.*/\1/p' || true)
  if [[ -n "${explicit:-}" ]]; then
    echo "$explicit"
    return
  fi
  local n
  n=$(grep -Ec "## Fail #[0-9]+.*${gate}" "$LADDER" 2>/dev/null || true)
  echo "${n:-0}"
}

premise_strike_for_gate() {
  local gate="$1"
  local log="${ARCS}/${gate}.md"
  if [[ -f "$log" ]]; then
    local ps
    ps=$(grep -Eo 'strike [0-9]+/3' "$log" 2>/dev/null | tail -1 | sed 's/strike //;s|/3||' || true)
    if [[ -n "${ps:-}" ]]; then
      echo "$ps"
      return
    fi
  fi
  strike_count_for_gate "$gate"
}

arc_verdict_for_gate() {
  local gate="$1"
  local log="${ARCS}/${gate}.md"
  if [[ ! -f "$log" ]]; then
    echo "MISSING"
    return
  fi
  grep -E '^## VERDICT:|^VERDICT:' "$log" 2>/dev/null | tail -1 | sed 's/^## //' || echo "MISSING"
}

ledger_bin_for_gate() {
  local gate="$1"
  local section=""
  while IFS= read -r line; do
    case "$line" in
      "## human-blocked"*) section="human-blocked" ;;
      "## agent-addressable"*) section="agent-addressable" ;;
      "## flaky"*) section="flaky" ;;
      "## "*) section="" ;;
    esac
    if [[ -n "$section" && "$line" == *"\`${gate}\`"* ]]; then
      echo "$section"
      return
    fi
  done < "$LEDGER"
  echo "UNLISTED"
}

count_agent_addressable() {
  awk '
    /^## agent-addressable/ { in_sec=1; next }
    /^## / && in_sec { exit }
    in_sec && /^\| `\S+`/ && !/^\| Gate/ && !/total/ { c++ }
    END { print c+0 }
  ' "$LEDGER"
}

read_snapshot_gates() {
  awk '/^## Last reviewed/,0 {
    if ($0 ~ /^\| `[^`]+` \|/ && $0 !~ /total/) {
      g=$2; gsub(/`/,"",g); print g
    }
  }' "$LEDGER" | sort -u
}

read_snapshot_strike() {
  local gate="$1"
  awk -v g="$gate" '
    /^## Last reviewed/ { in_snap=1; next }
    in_snap && /^## / { exit }
    in_snap && $0 ~ g {
      print $3
      exit
    }
  ' "$LEDGER"
}

echo "=== Organ C — Quarantine Review ==="
echo "Date: $(date -u +%Y-%m-%d)"
echo ""

CURRENT=()
while IFS= read -r g; do
  [[ -n "$g" ]] && CURRENT+=("$g")
done < <(list_quarantined_gates)

echo "Current || true gates in ci.yml (${#CURRENT[@]}):"
if ((${#CURRENT[@]} == 0)); then
  echo "  (none)"
else
  for g in "${CURRENT[@]}"; do echo "  - $g"; done
fi
echo ""

NEW=()
STRIKE_UP=()
MISSING_VERDICT=()
PAST_M_NOT_HUMAN=()
ADDR_COUNT=0

for gate in "${CURRENT[@]}"; do
  strikes=$(strike_count_for_gate "$gate")
  display_strikes=$strikes
  verdict=$(arc_verdict_for_gate "$gate")
  bin=$(ledger_bin_for_gate "$gate")
  if [[ "$bin" == "agent-addressable" ]]; then
    display_strikes=$(premise_strike_for_gate "$gate")
  fi

  if [[ "$bin" == "agent-addressable" ]]; then
    ADDR_COUNT=$((ADDR_COUNT + 1))
  fi

  snap_strike=$(read_snapshot_strike "$gate" || true)
  snap_strike="${snap_strike//$'\n'/}"
  if [[ -z "${snap_strike:-}" ]]; then
    NEW+=("$gate")
    if [[ "$verdict" == "MISSING" ]]; then
      MISSING_VERDICT+=("$gate")
    fi
  elif [[ "$strikes" =~ ^[0-9]+$ && "$snap_strike" =~ ^[0-9]+$ && "$strikes" -gt "$snap_strike" ]]; then
    STRIKE_UP+=("$gate (${snap_strike} → ${strikes})")
  fi

  if [[ "$strikes" -ge "$M_ABSOLUTE" && "$bin" != "human-blocked" ]]; then
    PAST_M_NOT_HUMAN+=("$gate strikes=${strikes} bin=${bin}")
  fi

  echo "Gate: $gate"
  echo "  Ledger bin:     $bin"
  if [[ "$display_strikes" != "$strikes" ]]; then
    echo "  Strike count:   $display_strikes (re-aimed premise; ladder total $strikes, M_absolute=$M_ABSOLUTE)"
  else
    echo "  Strike count:   $strikes (M_absolute=$M_ABSOLUTE)"
  fi
  echo "  Arc VERDICT:    $verdict"
  echo ""
done

CEILING=$(count_agent_addressable)
if [[ "${CEILING:-0}" -lt "$ADDR_COUNT" ]]; then
  CEILING=$ADDR_COUNT
fi

echo "--- Operator stamp surface ---"
if ((${#NEW[@]})); then
  echo "NEW quarantines since Last reviewed:"
  for g in "${NEW[@]}"; do echo "  - $g"; done
else
  echo "NEW quarantines: (none)"
fi

if ((${#STRIKE_UP[@]})); then
  echo "Strike count rose:"
  for s in "${STRIKE_UP[@]}"; do echo "  - $s"; done
else
  echo "Strike count rose: (none)"
fi

echo "Agent-addressable: $CEILING / $Q_MAX (Q_addressable_max)"

echo ""
echo "--- Tripwires (flag loud) ---"
trip=false
if ((${#MISSING_VERDICT[@]})); then
  trip=true
  echo "TRIPWIRE: new or unaccounted quarantine with no arc-log VERDICT:"
  for g in "${MISSING_VERDICT[@]}"; do echo "  - $g"; done
fi
if [[ "${CEILING:-0}" -gt "$Q_MAX" ]]; then
  trip=true
  echo "TRIPWIRE: agent-addressable count $CEILING exceeds ceiling $Q_MAX — drain before add"
fi
if ((${#PAST_M_NOT_HUMAN[@]})); then
  trip=true
  echo "TRIPWIRE: gate past M_absolute=$M_ABSOLUTE not yet human-blocked:"
  for p in "${PAST_M_NOT_HUMAN[@]}"; do echo "  - $p"; done
fi
if ! $trip; then
  echo "(none)"
fi

if $stamp_mode; then
  TODAY=$(date -u +%Y-%m-%d)
  TMP=$(mktemp)
  if grep -q '^## Last reviewed' "$LEDGER"; then
    awk '/^## Last reviewed/{exit} {print}' "$LEDGER" > "$TMP"
    mv "$TMP" "$LEDGER"
  fi
  {
    echo ""
    echo "## Last reviewed"
    echo ""
    echo "**Date:** ${TODAY}"
    echo ""
    echo "| Gate | Strikes (snapshot) | Bin |"
    echo "|------|-------------------|-----|"
    for gate in "${CURRENT[@]}"; do
      bin=$(ledger_bin_for_gate "$gate")
      if [[ "$bin" == "agent-addressable" ]]; then
        strikes=$(premise_strike_for_gate "$gate")
      else
        strikes=$(strike_count_for_gate "$gate")
      fi
      echo "| \`${gate}\` | ${strikes} | ${bin} |"
    done
    echo "| *(agent-addressable total)* | ${CEILING} / ${Q_MAX} | — |"
  } >> "$LEDGER"
  echo ""
  echo "Stamped: Last reviewed snapshot updated in $LEDGER"
fi

echo ""
echo "(Organ C is read-only — no exit 2; informs operator stamp / redirect.)"
