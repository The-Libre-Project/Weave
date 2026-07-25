#!/usr/bin/env bash
# copy-demo-to-desktop.sh
#
# Copies Weave demo .exe files from /usr/share/weave/demo/ to the live user's
# desktop so testers can double-click them or run them via terminal.
#
# Called by the LibreWin-OS ISO build after the RPM is installed and the
# live user home directory has been seeded.
#
# Usage: bash copy-demo-to-desktop.sh [dest_dir]
#   dest_dir defaults to /home/liveuser/Desktop/Test\ EXEs/

set -euo pipefail

SRC="/usr/share/weave/demo"
DEST="${1:-/home/liveuser/Desktop/Test EXEs}"

if [ ! -d "$SRC" ]; then
  echo "ERROR: Weave demo directory not found at $SRC" >&2
  echo "Is the weave RPM installed?" >&2
  exit 1
fi

mkdir -p "$DEST"

# Copy all .exe files plus README
find "$SRC" -maxdepth 1 -name '*.exe' -exec cp {} "$DEST/" \;
cp "$SRC/README.txt" "$DEST/" 2>/dev/null || true

# Make sure they're executable
chmod 755 "$DEST"/*.exe 2>/dev/null || true

echo "Copied $(find "$DEST" -maxdepth 1 -name '*.exe' | wc -l) .exe files to $DEST"
ls -lh "$DEST"/
