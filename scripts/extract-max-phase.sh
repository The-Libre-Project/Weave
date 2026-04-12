#!/usr/bin/env bash
# extract-max-phase.sh — parse PHASE: lines from test output (stdin) and
# emit the highest ordinal seen as: max_phase=<N> name=<phase_name>
#
# Usage:
#   cargo test ... 2>&1 | scripts/extract-max-phase.sh
#
# Phase ordinals (defined in weave-core/src/progress.rs):
#   1  loaded_pe
#   2  wWinMain_entered
#   3  register_class_first
#   4  create_window_first
#   5  get_message_first
#   6  wm_paint_dispatched_first
#   7  create_file_user_arg
#   8  sci_getlength_probed

set -euo pipefail

phase_ordinal() {
    case "$1" in
        loaded_pe)                  echo 1 ;;
        wWinMain_entered)           echo 2 ;;
        register_class_first)       echo 3 ;;
        create_window_first)        echo 4 ;;
        get_message_first)          echo 5 ;;
        wm_paint_dispatched_first)  echo 6 ;;
        create_file_user_arg)       echo 7 ;;
        sci_getlength_probed)       echo 8 ;;
        *)                          echo 0 ;;
    esac
}

max_ord=0
max_name="none"

while IFS= read -r line; do
    # Match lines of the form: PHASE: <name> t=<ms>
    if [[ "$line" =~ ^PHASE:[[:space:]]+([^[:space:]]+)[[:space:]]+t= ]]; then
        name="${BASH_REMATCH[1]}"
        ord="$(phase_ordinal "$name")"
        if [[ "$ord" -gt "$max_ord" ]]; then
            max_ord="$ord"
            max_name="$name"
        fi
    fi
done

echo "max_phase=${max_ord} name=${max_name}"
