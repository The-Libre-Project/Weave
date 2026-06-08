#!/usr/bin/env bash
# Install Weave git hooks (auto git-notes on commit + sync on push).
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

chmod +x .githooks/post-commit .githooks/pre-push

git config core.hooksPath .githooks
git config notes.rewriteref refs/notes/commits
git config --add remote.origin.fetch '+refs/notes/*:refs/notes/*' 2>/dev/null \
    || git config remote.origin.fetch '+refs/notes/*:refs/notes/*'

# The old notes-only push default made bare `git push` skip the current branch.
# pre-push now syncs notes on every branch push; drop the broken override.
if [ "$(git config --get-all remote.origin.push 2>/dev/null | wc -l | tr -d ' ')" -eq 1 ]; then
    only_push=$(git config --get remote.origin.push 2>/dev/null || true)
    if [ "$only_push" = "refs/notes/commits:refs/notes/commits" ]; then
        git config --unset-all remote.origin.push
    fi
fi

echo "Git hooks installed (core.hooksPath=.githooks)"
echo "  post-commit — stub note on every commit"
echo "  pre-push    — backfill + push refs/notes/commits with branch pushes"

if [ "${1:-}" = "--backfill" ]; then
    count=${2:-30}
    # shellcheck source=/dev/null
    source "${ROOT}/.githooks/lib/notes-common.sh"
    added=0
    while read -r commit; do
        if weave_note_exists "$commit"; then
            continue
        fi
        weave_add_stub_note "$commit"
        added=$((added + 1))
    done < <(git log --format='%H' -"$count")
    echo "Backfilled stub notes on ${added} commit(s) (last ${count} checked)."
    weave_push_notes_ref
fi
