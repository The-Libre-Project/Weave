# Contributing to Weave

Weave is open source for transparency and security auditability. The full codebase, commit history, and architecture are public under GPL-3.0. Read it, audit it, fork it.

**Weave does not accept external code contributions.** This is deliberate, not a lack of capacity.

Weave is agent-assisted software. Raw code is not the scarce resource — judgment, verification, and behavioral correctness against a moving reference are. Merging outside code would add review and provenance burden without moving Weave toward its goal, and it would compromise the clean-room guarantee below: the value of an independent reimplementation is that we can account for the origin of every line. The project is built to finish, not to accumulate contributors.

If you have found a security issue, see [SECURITY.md](SECURITY.md) for the disclosure process. Bug reports and questions are welcome via GitHub Issues — a reproducible report of a Windows app that misbehaves under Weave is worth far more to us than a patch.

If your goals differ from this roadmap, fork it. That is what GPL-3.0 is for.

---

## License

Weave is licensed under the **GNU General Public License v3 (GPL-3.0)**. Any fork or derivative work must also be distributed under GPL-3.0 with the full source available.

---

## Building locally

```bash
# Prerequisites: Rust 1.70+, Linux x86-64 target
rustup target add x86_64-unknown-linux-gnu

# Clone
git clone https://github.com/The-Libre-Project/Weave.git
cd Weave

# Check it compiles
cargo check

# Cross-compile from macOS
cargo zigbuild --target x86_64-unknown-linux-gnu

# Unit tests (any platform)
make test-unit

# Full test suite (Linux or Docker/OrbStack)
make test
```

## Clean-room process

Weave is an independent reimplementation. Wine's source is consulted as a behavioral reference to understand what Win32 functions must do — including undocumented edge cases that real applications depend on. No Wine code is copied. Every function implementation is original Rust, written from a behavioral specification derived from Wine's reverse engineering work.
