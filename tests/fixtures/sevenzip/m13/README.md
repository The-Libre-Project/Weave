# M13 — Round-trip 7z fixture

Source files for the `sevenzip_m13_roundtrip_gate` end-to-end gate.

The gate creates `roundtrip.7z` at test time by invoking
`weave 7za.exe a roundtrip.7z hello.txt lorem.txt bytes.bin`, then extracts
the archive back out and asserts byte-for-byte equality against these
canonical fixtures via `include_bytes!()`.

## Files

| File         | Size      | Content                                    |
|--------------|-----------|--------------------------------------------|
| `hello.txt`  | 71 bytes  | Small ASCII, exact content fixed.          |
| `lorem.txt`  | 446 bytes | Lorem ipsum, single line + LF terminator.  |
| `bytes.bin`  | 256 bytes | Deterministic binary: `bytes(range(256))`. |

All three files are **deterministic byte-for-byte across machines** — no
timestamps, no random data, no platform-specific content. `bytes.bin` is
generated as `(0..=255).collect::<Vec<u8>>()` so the M13 gate can compare
the round-tripped bytes against an in-test fixed expectation.

## Determinism

This fixture set tests the round-trip semantics of the 7z create + extract
path; archive bytes are not asserted on. Only the extracted byte streams
are checked, identically to how M8a handles `test.7z` (LZMA defaults shift
across 7-Zip versions — archive bytes are not stable).

## Round-trip verification

Procedure (host sanity check):

```
cd tests/fixtures/sevenzip/m13
7zz a /tmp/m13-host.7z hello.txt lorem.txt bytes.bin
mkdir -p /tmp/m13-extract
7zz x /tmp/m13-host.7z -o/tmp/m13-extract -y
cmp hello.txt /tmp/m13-extract/hello.txt
cmp lorem.txt /tmp/m13-extract/lorem.txt
cmp bytes.bin /tmp/m13-extract/bytes.bin
rm -rf /tmp/m13-host.7z /tmp/m13-extract
```
