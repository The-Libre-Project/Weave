#!/usr/bin/env python3
"""Create test archives in tests/fixtures/bin/ for integration tests.

Produces:
  test.zip  — ZIP archive (two entries)
  test.7z   — 7z archive (same two entries), requires py7zr
"""
import pathlib, zipfile

bin_dir = pathlib.Path(__file__).parent.parent / "bin"

# --- ZIP ---
zip_out = bin_dir / "test.zip"
with zipfile.ZipFile(zip_out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("hello.txt", "Hello from inside the archive!\n")
    zf.writestr("subdir/world.txt", "Another file in a subdirectory.\n")
print(f"Created {zip_out}")

# --- 7z ---
try:
    import py7zr
    sz_out = bin_dir / "test.7z"
    with py7zr.SevenZipFile(sz_out, mode="w") as zf:
        zf.writestr(b"Hello from inside the archive!\n", "hello.txt")
        zf.writestr(b"Another file in a subdirectory.\n", "subdir/world.txt")
    print(f"Created {sz_out}")
except ImportError:
    print("py7zr not installed — skipping test.7z (run: pip install py7zr)")
