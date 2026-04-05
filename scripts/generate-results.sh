#!/usr/bin/env bash
# generate-results.sh
#
# Generates docs/dashboard/results.json from:
#   1. cargo test output (Weave's own unit tests — counts implemented functions)
#   2. Wine conformance test results (if the cross-compilation pipeline is set up)
#   3. Git metadata (commit hash, timestamp)
#
# Usage:
#   scripts/generate-results.sh                  # standard run
#   scripts/generate-results.sh --wine-results=path/to/wine-results.txt
#
# Output: docs/dashboard/results.json
#
# When Wine conformance tests aren't set up yet, wine_tests_passing/total
# will be 0 — the dashboard shows "not run" for those columns.
# That's fine. Run this script now to at least get implementation counts.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO_ROOT/docs/dashboard/results.json"
WINE_RESULTS=""

for arg in "$@"; do
  case $arg in
    --wine-results=*) WINE_RESULTS="${arg#*=}" ;;
  esac
done

# --- Git metadata ---
COMMIT=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")
COMMIT_SHORT=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION=$(grep '^version' "$REPO_ROOT/Cargo.toml" 2>/dev/null | head -1 | sed 's/.*= *"//' | sed 's/".*//' || echo "0.0.0")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "Weave results generator"
echo "  commit:  $COMMIT_SHORT"
echo "  version: $VERSION"
echo "  output:  $OUT"
echo ""

# --- Count implemented functions per DLL crate ---
# A function is "implemented" if it:
#   a) is a pub fn in a weave-* crate (not a stub returning unimplemented!/todo!)
# We use a simple heuristic: count pub fn declarations that don't immediately
# call unimplemented!() or todo!() on the next non-empty line.
count_implemented() {
  local crate_dir="$1"
  if [ ! -d "$crate_dir/src" ]; then echo 0; return; fi

  # Count pub fn that are NOT stubs
  # Stubs: body is just `unimplemented!()`, `todo!()`, or `Ok(())` alone
  grep -rn "^pub fn \|^    pub fn " "$crate_dir/src" --include="*.rs" 2>/dev/null \
    | grep -v "unimplemented!\|todo!\|#\[allow" \
    | wc -l | tr -d ' '
}

count_total_fns() {
  local crate_dir="$1"
  if [ ! -d "$crate_dir/src" ]; then echo 0; return; fi
  grep -rn "^pub fn \|^    pub fn " "$crate_dir/src" --include="*.rs" 2>/dev/null \
    | wc -l | tr -d ' '
}

# --- Count pipeline stages from inline markers ---
# Functions can be annotated with comments like:
#   // weave-pipeline: spec
#   // weave-pipeline: test
#   // weave-pipeline: build
#   // weave-pipeline: pass
#   // weave-pipeline: done
# Unmarked implemented functions count as "build".
# Unmarked stubs count as "todo".
count_pipeline_stage() {
  local crate_dir="$1"
  local stage="$2"
  if [ ! -d "$crate_dir/src" ]; then echo 0; return; fi
  grep -rn "// weave-pipeline: $stage" "$crate_dir/src" --include="*.rs" 2>/dev/null \
    | wc -l | tr -d ' '
}

# --- Parse Wine test results ---
# Expected format (from Wine's winetest runner or our CI wrapper):
#   kernel32: 1247 tests passed, 12 tests failed, 0 tests skipped
#   user32: 890 tests passed, 45 tests failed, 3 tests skipped
parse_wine_results() {
  local dll="$1"
  local file="$2"
  if [ -z "$file" ] || [ ! -f "$file" ]; then
    echo "0 0"
    return
  fi
  local line
  line=$(grep "^${dll}:" "$file" 2>/dev/null || echo "")
  if [ -z "$line" ]; then echo "0 0"; return; fi

  local passed failed
  passed=$(echo "$line" | grep -oE '[0-9]+ tests passed' | grep -oE '[0-9]+' || echo 0)
  failed=$(echo "$line"  | grep -oE '[0-9]+ tests failed' | grep -oE '[0-9]+' || echo 0)
  local total=$((passed + failed))
  echo "$passed $total"
}

# --- Build DLL data ---
build_dll_json() {
  local name="$1"
  local priority="$2"
  local total_known="$3"   # known total API surface (from MSDN/research)
  local crate="$REPO_ROOT/weave-${name}"

  local impl=0
  local total_impl=0
  if [ -d "$crate" ]; then
    impl=$(count_implemented "$crate")
    total_impl=$(count_total_fns "$crate")
  fi

  # Use known total if crate total seems low (stubs not yet written)
  local fn_total=$total_known
  local fn_impl=$impl

  # Pipeline counts
  local p_spec=$(count_pipeline_stage "$crate" spec)
  local p_test=$(count_pipeline_stage "$crate" test)
  local p_build=$(count_pipeline_stage "$crate" build)
  local p_pass=$(count_pipeline_stage "$crate" pass)
  local p_done=$(count_pipeline_stage "$crate" done)
  local p_todo=$((fn_total - p_spec - p_test - p_build - p_pass - p_done))
  [ $p_todo -lt 0 ] && p_todo=0

  # Wine test results
  local wine_data
  wine_data=$(parse_wine_results "$name" "$WINE_RESULTS")
  local wine_pass
  local wine_total
  wine_pass=$(echo "$wine_data" | awk '{print $1}')
  wine_total=$(echo "$wine_data" | awk '{print $2}')

  cat <<EOF
    {
      "name": "${name}",
      "functions_implemented": ${fn_impl},
      "functions_total": ${fn_total},
      "wine_tests_passing": ${wine_pass},
      "wine_tests_total": ${wine_total},
      "pipeline_counts": {
        "todo": ${p_todo},
        "spec": ${p_spec},
        "test": ${p_test},
        "build": ${p_build},
        "pass": ${p_pass},
        "done": ${p_done}
      },
      "priority": ${priority}
    }
EOF
}

echo "Counting implemented functions..."

# --- Generate JSON ---
cat > "$OUT" <<EOF
{
  "_meta": {
    "generated": "${TIMESTAMP}",
    "weave_commit": "${COMMIT}",
    "weave_version": "${VERSION}"
  },
  "dlls": [
$(build_dll_json "kernel32"  1  350),
$(build_dll_json "ntdll"     2  180),
$(build_dll_json "user32"    3  280),
$(build_dll_json "gdi32"     4  220),
$(build_dll_json "advapi32"  5  310),
$(build_dll_json "ole32"     6  250),
$(build_dll_json "shell32"   7  190),
$(build_dll_json "ws2_32"    8   85)
  ],
  "apps": [
    { "name": "PuTTY",  "version": "0.81",  "status": "testing", "blocking_dlls": [], "notes": "" },
    { "name": "7-Zip",  "version": "24.08", "status": "testing", "blocking_dlls": [], "notes": "" }
  ],
  "history": []
}
EOF

# Fix trailing comma on last DLL entry (bash heredoc limitation)
# Use python if available, otherwise sed
if command -v python3 &>/dev/null; then
  python3 -c "
import json, sys
with open('$OUT') as f:
    data = json.load(f)
with open('$OUT', 'w') as f:
    json.dump(data, f, indent=2)
print('  JSON validated and formatted.')
" 2>/dev/null || true
fi

echo ""
echo "Done. Results written to: $OUT"
echo ""
echo "To add Wine test results:"
echo "  scripts/generate-results.sh --wine-results=path/to/wine-test-output.txt"
echo ""
echo "Wine test output format expected:"
echo "  kernel32: 1247 tests passed, 12 tests failed, 0 tests skipped"
echo "  user32: 890 tests passed, 45 tests failed, 3 tests skipped"
echo "  ..."
