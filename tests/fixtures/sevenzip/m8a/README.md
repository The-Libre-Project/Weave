# M8a — Synthetic 7z fixture

Synthetic 7z archive fixture for the M8a byte-compare gate.

## Source binary

Compressed with `7zz` (7-Zip 26.00 arm64, 2026-02-12 build, from Homebrew on macOS).

Compression command (run from this directory):

```
7zz a test.7z plaintext.txt
```

Default LZMA settings — no flags tuned. The goal is a real, valid 7z archive,
not a particular compression configuration.

## plaintext.txt

Exact content (18 bytes, single line terminated with one LF / 0x0a):

```
weave-m8a-fixture
```

(The trailing newline is a real LF byte; the file is 18 bytes total. The
original brief stated 19 bytes — that was an off-by-one in the brief; the
literal string `weave-m8a-fixture\n` is 18 bytes. The content matches the
brief's explicit content spec, which is the source of truth for the
`include_bytes!()` assertion in M8a/b.)

sha256: `0c7bec7e9655ba76ee4887f483fb5a4e0d5b3b94b2b27925bbcecfd3792ea7fc`

## test.7z

sha256: `c51420bc94a3e76c9b57a746e6d983799dbb794a2c9fa799b6d7863ff2c4f770`

Size: 152 bytes.

## Round-trip verification

Round-tripped on host with `cmp` exit 0 on 2026-04-28.

Procedure:

```
mkdir -p /tmp/m8a-roundtrip
7zz x test.7z -o/tmp/m8a-roundtrip -y
cmp plaintext.txt /tmp/m8a-roundtrip/plaintext.txt   # exit 0
rm -rf /tmp/m8a-roundtrip
```

## Stability note

7-Zip compression output is **not** byte-stable across different 7-Zip
versions or builds (LZMA defaults shift, archive headers carry version
metadata, etc.). The M8a gate test verifies round-trip equality of the
**extracted** bytes against the canonical `plaintext.txt` — it does NOT
compare archive bytes.

The `test.7z` sha256 is recorded here for tracking and incident triage,
but it is **not load-bearing** for the gate. If a future regen of `test.7z`
produces a different sha256 but still round-trips cleanly, that's
expected.
