#!/usr/bin/env python3
"""Create tests/fixtures/bin/test.zip with two sample entries."""
import zipfile, os, pathlib

out = pathlib.Path(__file__).parent.parent / "bin" / "test.zip"
with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("hello.txt", "Hello from inside the archive!\n")
    zf.writestr("subdir/world.txt", "Another file in a subdirectory.\n")
print(f"Created {out}")