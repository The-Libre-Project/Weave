#!/usr/bin/env bash
# coverage-gauge.sh
#
# Computes the percentage of resolver-registered Win32 exports that count as
# "implemented" per SHIM-CONTRACT.md §8, weighted by milestone-mention
# frequency (Strategy B).
#
# SHIM-CONTRACT.md §8 defines "implemented" as ALL of:
#   (a) Has a "// Wine ref:" or "/// Wine ref:" comment in proximity in src
#   (c) Does NOT have panic!/unimplemented!()/todo!() as the sole function body
#   (d) Named in at least one milestone doc under docs/milestones/**/*.md
#
# Strategy B weights:
#   weight(fn) = max(1, occurrences of fn name across all milestone docs)
#
# Gauge formula:
#   coverage = sum(weight_i * implemented_bit_i) / sum(weight_i) * 100
#
# Usage:
#   bash scripts/coverage-gauge.sh
#
# Exit code: always 0

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "============================================================"
echo "  Weave Coverage Gauge  (Strategy B — milestone-weighted)"
echo "============================================================"
echo ""

# ── Temp files ──────────────────────────────────────────────────────────────
EXPORTS_TMP=$(mktemp /tmp/weave-cg-exports.XXXXXX)
WINEREF_SET=$(mktemp /tmp/weave-cg-wineref.XXXXXX)
PANIC_SET=$(mktemp /tmp/weave-cg-panic.XXXXXX)
MILESTONE_COUNTS=$(mktemp /tmp/weave-cg-ms.XXXXXX)
IMPLEMENTED_SET=$(mktemp /tmp/weave-cg-impl.XXXXXX)

cleanup() {
    rm -f "$EXPORTS_TMP" "$WINEREF_SET" "$PANIC_SET" \
          "$MILESTONE_COUNTS" "$IMPLEMENTED_SET"
}
trap cleanup EXIT

# ── Step 1: Enumerate all registered exports ────────────────────────────────
# Each resolver lib.rs has match arms:  "FunctionName" =>
# Collect (crate, function_name) pairs into EXPORTS_TMP.

for lib in "$REPO_ROOT"/weave-*/src/lib.rs; do
    crate=$(basename "$(dirname "$(dirname "$lib")")")
    grep -oE '"[A-Za-z][A-Za-z0-9_]+" =>' "$lib" 2>/dev/null \
        | sed 's/^"//; s/" =>$//' \
        | sed "s/^/${crate}\t/"
done > "$EXPORTS_TMP"

TOTAL_EXPORTS=$(wc -l < "$EXPORTS_TMP" | tr -d ' ')
echo "Step 1 — Registered resolver exports:  $TOTAL_EXPORTS"

# ── Step 2: Wine-ref set (criterion a) ─────────────────────────────────────
# For each crate, scan ALL src/*.rs files for "Wine ref:" to build a set of
# line numbers. Then for each export, check if the match arm line in lib.rs
# is within 300 lines of any Wine ref line in that same file.
# Batch approach: use Python for speed.

python3 - "$REPO_ROOT" "$EXPORTS_TMP" "$WINEREF_SET" <<'PYEOF'
import sys, os, re

repo_root = sys.argv[1]
exports_file = sys.argv[2]
out_file = sys.argv[3]

# Load exports: {crate: [fn_name, ...]}
exports = {}
with open(exports_file) as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) == 2:
            crate, fn = parts
            exports.setdefault(crate, []).append(fn)

found = set()

for crate, fns in exports.items():
    lib_path = os.path.join(repo_root, crate, 'src', 'lib.rs')
    if not os.path.exists(lib_path):
        continue
    with open(lib_path, 'r', errors='replace') as f:
        lines = f.readlines()

    # Find all line numbers with "Wine ref:"
    wine_ref_lines = set(i for i, ln in enumerate(lines) if 'Wine ref:' in ln)
    if not wine_ref_lines:
        # Check other src files for any Wine ref — if crate has any at all,
        # mark all exports as having a wine ref (coarse but fast).
        src_dir = os.path.join(repo_root, crate, 'src')
        crate_has_wine_ref = False
        for fname in os.listdir(src_dir) if os.path.isdir(src_dir) else []:
            if fname.endswith('.rs') and fname != 'lib.rs':
                fpath = os.path.join(src_dir, fname)
                with open(fpath, 'r', errors='replace') as ff:
                    if 'Wine ref:' in ff.read():
                        crate_has_wine_ref = True
                        break
        if not crate_has_wine_ref:
            continue
        # If other src files have Wine refs, credit all exports in this crate
        # (they're defined in those files, not lib.rs)
        for fn in fns:
            found.add((crate, fn))
        continue

    # Build map from fn_name → line number of its match arm in lib.rs
    arm_re = re.compile(r'"([A-Za-z][A-Za-z0-9_]+)"\s*=>')
    fn_to_line = {}
    for i, ln in enumerate(lines):
        m = arm_re.search(ln)
        if m:
            fn_to_line[m.group(1)] = i

    # For each export, check if any Wine ref line is within 300 lines
    WINDOW = 300
    for fn in fns:
        arm_line = fn_to_line.get(fn)
        if arm_line is None:
            continue
        lo = max(0, arm_line - WINDOW)
        hi = arm_line + 50
        for wl in wine_ref_lines:
            if lo <= wl <= hi:
                found.add((crate, fn))
                break

with open(out_file, 'w') as f:
    for crate, fn in sorted(found):
        f.write(f"{crate}\t{fn}\n")
PYEOF

WINEREF_COUNT=$(wc -l < "$WINEREF_SET" | tr -d ' ')
echo "Step 2 — With Wine ref (criterion a):  $WINEREF_COUNT"

# ── Step 3: Not-sole-panic-body (criterion c) ───────────────────────────────
# From WINEREF_SET, remove entries where the resolved Rust function has ONLY
# panic!/unimplemented!()/todo!() in its first 12 lines.
# Batch via Python for speed.

python3 - "$REPO_ROOT" "$WINEREF_SET" "$PANIC_SET" <<'PYEOF'
import sys, os, re

repo_root = sys.argv[1]
wineref_file = sys.argv[2]
out_file = sys.argv[3]

# Load wine-ref set: {crate: [fn_name, ...]}
wineref = {}
with open(wineref_file) as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) == 2:
            wineref.setdefault(parts[0], []).append(parts[1])

STUB_ONLY_RE = re.compile(
    r'^\s*(unimplemented!\s*\(|todo!\s*\(|panic!\s*\()'
)
REAL_CODE_RE = re.compile(
    r'^\s*(?!//|/\*|\*|$|\{|\}|unimplemented|todo|panic)[^\s]'
)

results = []

for crate, fns in wineref.items():
    lib_path = os.path.join(repo_root, crate, 'src', 'lib.rs')
    if not os.path.exists(lib_path):
        results.extend((crate, fn) for fn in fns)
        continue
    with open(lib_path, 'r', errors='replace') as f:
        lines = f.readlines()

    # Build fn_name → match arm line
    arm_re = re.compile(r'"([A-Za-z][A-Za-z0-9_]+)"\s*=>')
    fn_to_armline = {}
    for i, ln in enumerate(lines):
        m = arm_re.search(ln)
        if m:
            fn_to_armline[m.group(1)] = i

    # For each export, extract the resolved fn name from the match arm,
    # then find its body and check for sole-panic.
    rust_fn_re = re.compile(r'\b([a-z_][a-z0-9_]+)\s+as\b|\bSome\(\s*([a-z_][a-z0-9_]+)\b')
    fn_def_re = re.compile(r'^\s*(pub\s+)?(unsafe\s+)?(?:extern\s+"[^"]+"\s+)?fn\s+([a-z_][a-z0-9_]+)')

    # Build fn_name → def line map
    fn_def_lines = {}
    for i, ln in enumerate(lines):
        m = fn_def_re.match(ln)
        if m:
            fn_def_lines[m.group(3)] = i

    for fn in fns:
        arm_line = fn_to_armline.get(fn)
        if arm_line is None:
            results.append((crate, fn))
            continue

        arm_text = lines[arm_line]
        # Extract rust fn name from match arm
        rust_fn = None
        # Pattern: Some(fn_name as ...)  or  Some(fn_name)
        m = re.search(r'Some\(\s*([a-z_][a-z0-9_]+)\b', arm_text)
        if m:
            rust_fn = m.group(1)
        else:
            # Try: => Some(fn_ptr as ...) across next 3 lines
            chunk = ''.join(lines[arm_line:arm_line+3])
            m = re.search(r'Some\(\s*([a-z_][a-z0-9_]+)\b', chunk)
            if m:
                rust_fn = m.group(1)

        if rust_fn is None:
            results.append((crate, fn))
            continue

        def_line = fn_def_lines.get(rust_fn)
        if def_line is None:
            results.append((crate, fn))
            continue

        # Check body (next 12 lines after fn declaration)
        body = lines[def_line+1:def_line+13]
        has_panic = any(STUB_ONLY_RE.match(ln) for ln in body)
        if not has_panic:
            results.append((crate, fn))
            continue
        # Has panic — check if there's real logic too
        has_real = any(REAL_CODE_RE.match(ln) for ln in body)
        if has_real:
            results.append((crate, fn))
        # else: sole-panic body — excluded

with open(out_file, 'w') as f:
    for crate, fn in sorted(results):
        f.write(f"{crate}\t{fn}\n")
PYEOF

NOT_PANIC_COUNT=$(wc -l < "$PANIC_SET" | tr -d ' ')
echo "Step 3 — Not sole-panic body (criterion c):  $NOT_PANIC_COUNT"

# ── Step 4: Milestone mention counts (criterion d) ──────────────────────────
# Count occurrences of each export name across all docs/milestones/**/*.md

python3 - "$REPO_ROOT" "$EXPORTS_TMP" "$MILESTONE_COUNTS" <<'PYEOF'
import sys, os, glob, re

repo_root = sys.argv[1]
exports_file = sys.argv[2]
out_file = sys.argv[3]

# Load all exports
exports = []
with open(exports_file) as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) == 2:
            exports.append((parts[0], parts[1]))

# Load all milestone text into one big blob
milestone_dir = os.path.join(repo_root, 'docs', 'milestones')
milestone_text = ''
for md in glob.glob(os.path.join(milestone_dir, '**', '*.md'), recursive=True):
    with open(md, 'r', errors='replace') as f:
        milestone_text += f.read() + '\n'

# Count occurrences of each fn name (whole-word to reduce noise)
# Use simple string occurrence count (not regex word boundary — faster)
fn_counts = {}
for _, fn in exports:
    if fn not in fn_counts:
        fn_counts[fn] = milestone_text.count(fn)

with open(out_file, 'w') as f:
    for crate, fn in exports:
        count = fn_counts.get(fn, 0)
        f.write(f"{crate}\t{fn}\t{count}\n")
PYEOF

MILESTONE_MENTIONED=$(awk -F'	' '$3 >= 1' "$MILESTONE_COUNTS" | wc -l | tr -d ' ')
echo "Step 4 — Mentioned in milestone docs (criterion d):  $MILESTONE_MENTIONED / $TOTAL_EXPORTS"

# ── Step 5+6: Compute implemented set and weighted/unweighted scores ─────────

python3 - "$PANIC_SET" "$MILESTONE_COUNTS" "$IMPLEMENTED_SET" <<'PYEOF'
import sys

panic_file = sys.argv[1]
ms_file = sys.argv[2]
impl_out = sys.argv[3]

# Load not-panic set
not_panic = set()
with open(panic_file) as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) == 2:
            not_panic.add((parts[0], parts[1]))

# Load milestone counts: {(crate, fn): count}
ms_counts = {}
with open(ms_file) as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) == 3:
            try:
                ms_counts[(parts[0], parts[1])] = int(parts[2])
            except ValueError:
                ms_counts[(parts[0], parts[1])] = 0

# Implemented = in not_panic AND milestone count >= 1
implemented = set()
for key in not_panic:
    if ms_counts.get(key, 0) >= 1:
        implemented.add(key)

with open(impl_out, 'w') as f:
    for crate, fn in sorted(implemented):
        f.write(f"{crate}\t{fn}\n")
PYEOF

IMPL_COUNT=$(wc -l < "$IMPLEMENTED_SET" | tr -d ' ')
DRAFTED_COUNT=$((NOT_PANIC_COUNT - IMPL_COUNT))

echo "Step 4d — Implemented (all 3 criteria met):  $IMPL_COUNT"
echo "       — Drafted (wine-ref + not-panic, no milestone gate):  $DRAFTED_COUNT"

# ── Weighted gauge ──────────────────────────────────────────────────────────

GAUGE_OUT=$(python3 - "$EXPORTS_TMP" "$MILESTONE_COUNTS" "$IMPLEMENTED_SET" <<'PYEOF'
import sys

exports_file = sys.argv[1]
ms_file = sys.argv[2]
impl_file = sys.argv[3]

# Load all exports
all_exports = []
with open(exports_file) as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) == 2:
            all_exports.append((parts[0], parts[1]))

# Load milestone counts
ms_counts = {}
with open(ms_file) as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) == 3:
            try:
                ms_counts[(parts[0], parts[1])] = int(parts[2])
            except ValueError:
                pass

# Load implemented set
implemented = set()
with open(impl_file) as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) == 2:
            implemented.add((parts[0], parts[1]))

total_weight = 0
impl_weight = 0
for key in all_exports:
    w = max(1, ms_counts.get(key, 0))
    total_weight += w
    if key in implemented:
        impl_weight += w

if total_weight > 0:
    pct = (impl_weight / total_weight) * 100
    print(f"{impl_weight} {total_weight} {pct:.1f}")
else:
    print("0 0 0.0")
PYEOF
)

WEIGHTED_IMPL=$(echo "$GAUGE_OUT" | awk '{print $1}')
WEIGHTED_TOTAL=$(echo "$GAUGE_OUT" | awk '{print $2}')
WEIGHTED_PCT=$(echo "$GAUGE_OUT" | awk '{print $3}')
UNWEIGHTED=$(awk -v total="$TOTAL_EXPORTS" -v impl="$IMPL_COUNT" \
    'BEGIN { if (total > 0) printf "%.1f", (impl / total) * 100; else print "0.0" }')

# ── Per-crate table ─────────────────────────────────────────────────────────

echo ""
echo "────────────────────────────────────────────────────────────"
echo "  Per-crate breakdown"
echo "────────────────────────────────────────────────────────────"
printf "  %-25s  %7s  %7s  %7s  %7s\n" "Crate" "Exports" "WineRef" "NotPanic" "Impl(d)"
echo "  ─────────────────────────────────────────────────────────"

for lib in "$REPO_ROOT"/weave-*/src/lib.rs; do
    crate=$(basename "$(dirname "$(dirname "$lib")")")
    exports=$(awk -F'	' -v c="$crate" '$1==c' "$EXPORTS_TMP" | wc -l | tr -d ' ')
    if [ "${exports:-0}" -eq 0 ] 2>/dev/null; then continue; fi
    wineref=$(awk -F'	' -v c="$crate" '$1==c' "$WINEREF_SET" | wc -l | tr -d ' ')
    notpanic=$(awk -F'	' -v c="$crate" '$1==c' "$PANIC_SET" | wc -l | tr -d ' ')
    impl=$(awk -F'	' -v c="$crate" '$1==c' "$IMPLEMENTED_SET" | wc -l | tr -d ' ')
    printf "  %-25s  %7d  %7d  %7d  %7d\n" \
        "$crate" "${exports:-0}" "${wineref:-0}" "${notpanic:-0}" "${impl:-0}"
done

echo "  ─────────────────────────────────────────────────────────"
printf "  %-25s  %7d  %7d  %7d  %7d\n" \
    "TOTAL" "$TOTAL_EXPORTS" "$WINEREF_COUNT" "$NOT_PANIC_COUNT" "$IMPL_COUNT"
echo ""

# ── Global summary ──────────────────────────────────────────────────────────

echo "============================================================"
echo "  Global Coverage (Strategy B — milestone-weighted)"
echo "============================================================"
echo ""
echo "  Unweighted:  ${IMPL_COUNT} / ${TOTAL_EXPORTS} exports = ${UNWEIGHTED}%"
echo "  Weighted:    ${WEIGHTED_IMPL} / ${WEIGHTED_TOTAL} weight-points = ${WEIGHTED_PCT}%"
echo ""
echo "  Strategy B: weight(fn) = max(1, count of fn name in docs/milestones/**/*.md)"
echo "  Rationale: functions exercised by milestone gates count more toward coverage"
echo "  than unmentioned stubs. Floor=1 so implemented-but-unmentioned work is"
echo "  not invisible."
echo ""

# ── Known Limits ────────────────────────────────────────────────────────────

echo "------------------------------------------------------------"
echo "  Known limits"
echo "------------------------------------------------------------"
echo "  1. Denominator = resolver match arms in lib.rs only. Multi-file crates"
echo "     (user32: api.rs and submodules) count only exports registered in lib.rs."
echo "  2. Wine-ref detection uses a 300-line window around the match arm line"
echo "     in lib.rs, plus a coarse whole-crate fallback for multi-file crates."
echo "     False positives possible in dense resolve() blocks; false negatives"
echo "     unlikely since Wine ref comments appear near the function definition."
echo "  3. Criterion (c) sole-panic heuristic checks the first 12 lines after"
echo "     the fn declaration. Conditional panics deeper in the body are not"
echo "     flagged (conservative — may over-count implemented)."
echo "  4. Milestone mention uses raw string count of the export name across"
echo "     all .md files in docs/milestones/**. Short names may match non-fn text."
echo "  5. Strategy B weights are milestone docs only (no SESSION-STATUS, git"
echo "     notes, or CI logs)."
echo "  6. 'Implemented' requires ALL of (a) wine ref, (c) not sole-panic, AND"
echo "     (d) milestone mention >= 1. Criterion (b) SAFETY: comments are NOT"
echo "     checked by this script — that requires AST analysis."
echo "------------------------------------------------------------"
echo ""

exit 0
