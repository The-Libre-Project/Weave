# Contributing to Weave

Thank you for your interest in contributing to Weave. This guide covers the process for submitting code, the technical setup, and the legal requirements.

---

## Quick Start

1. Fork the repo (or ask for contributor access)
2. Create a branch: `git checkout -b feat/your-feature`
3. Make changes and test locally (see **Testing** below)
4. Run `cargo clippy --all-targets` and `cargo fmt` to lint
5. Commit with a descriptive message: `git commit -s -m "feat(kernel32): implement CreateFileW with Wine-ref parity"`
6. Push and open a Pull Request
7. Sign the Contributor License Agreement (CLA) via the bot link in the PR
8. Address review feedback and iterate until approved
9. Maintainer merges when ready

---

## License & Contributor Agreement

**License:** Weave is licensed under the **GNU General Public License v3 (GPL-3.0)**.

By submitting a pull request, you agree that:
1. Your contributions will be licensed under GPL-3.0
2. You have the right to submit the code (it is original work or properly attributed)
3. You certify the above by signing off your commits with `git commit -s`

### Contributor License Agreement (CLA)

The first time you open a PR, you'll be asked to sign a Contributor License Agreement via GitHub. This is a one-time requirement that grants the project the right to relicense and maintain your contributions commercially if needed in the future.

The CLA is non-exclusive — you retain all rights to your work. It simply protects the project's long-term flexibility.

---

## Development Setup

### Prerequisites

- **Rust 1.70+** — install via [rustup.rs](https://rustup.rs/)
- **Linux x86-64 target** — `rustup target add x86_64-unknown-linux-gnu`
- **Docker or OrbStack** — required for full test suite (see Testing below)
- **jcodemunch** — optional but recommended for Wine reference lookups

### Build & Verify

```bash
# Clone and set up
git clone https://github.com/libre-project/Weave.git
cd Weave
git submodule update --init --recursive

# Verify code compiles
cargo check

# Build for Linux (cross-compile if on macOS)
cargo zigbuild --target x86_64-unknown-linux-gnu
```

### macOS Developers

**Do NOT run `cargo test` directly on macOS.** This project cross-compiles to Linux. Use the provided Makefile:

```bash
# macOS unit tests only (no linker errors)
make test-unit

# Full cross-compiled build verification
cargo zigbuild --target x86_64-unknown-linux-gnu
```

See `CLAUDE.md` for why and full details.

---

## Testing

### Unit Tests (any platform)

```bash
make test-unit
```

Runs Rust unit tests locally. These should pass on any platform.

### Full Test Suite (Linux or Docker/OrbStack)

```bash
make test
```

Runs the complete test suite including Wine conformance tests, app smoke tests, and integration tests. Requires Linux or a container environment. This is what CI runs.

### Before Submitting a PR

1. Run unit tests: `make test-unit`
2. Run linting: `cargo clippy --all-targets` and `cargo fmt`
3. Verify the code compiles: `cargo check`

If all pass, your PR is ready.

---

## Code Standards

### Rust Style

- **Use standard Rust idioms.** Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).
- **cargo clippy must pass:** `cargo clippy --all-targets -- -D warnings`
- **cargo fmt must pass:** `cargo fmt` (enforced in CI)
- **No unsafe code without documentation.** Unsafe blocks must explain why they're necessary and what invariants they maintain.

### Module Organization

- **Group platform-specific code into modules** using `#[cfg(...)]` at the module level, not item-by-item.
  - Good: Create a `windows/` module and gate the whole module with `#[cfg(target_os = "windows")]`
  - Bad: Sprinkling `#[cfg(...)]` on individual functions
- **Use meaningful module names.** A module for GDI32 functions should be `pub mod gdi32`, not `pub mod dll_funcs`.
- **Document public APIs.** Public types and functions should have docstrings explaining what they do.

### Wine Reference Documentation

Every Win32 API function implementation **must include a Wine reference comment:**

```rust
// Wine ref: dlls/kernel32/file.c:CreateFileW — handles X edge case, returns Y on Z condition
pub fn create_file_w(/* ... */) -> HANDLE {
    // implementation
}
```

This comment must be:
- Added **after** consulting Wine source via jcodemunch (not from memory)
- Specific enough to be verifiable (cite a behavioral detail, not obvious behavior)
- A receipt of a real lookup (if the commit history shows no jcodemunch call, the comment is fake)

See `CLAUDE.md` for full details on Wine reference workflow.

---

## The Clean-Room Process

Weave is built entirely from original Rust code informed by reading Wine's source as a behavioral reference. **You cannot directly copy code from Wine, ReactOS, or other proprietary/leaked Windows source.**

### What You CAN Do

- Read Wine source to understand what an API function should do
- Rewrite the behavior in original Rust code
- Test against Wine's conformance tests to verify correctness

### What You CANNOT Do

- Copy code directly from Wine or ReactOS (even small snippets)
- Reference decompiled or disassembled Windows binaries
- Use proprietary Windows source (leaked source code)
- Link against Wine libraries (we reimplement, not wrap)

**Every PR will be checked for clean-room compliance.** If you're unsure whether a specific implementation crosses the line, ask in an issue first.

See `active/projects/weave/CLEAN_ROOM.md` in the Business-OS repo for full clean-room guidelines.

---

## Submitting a PR

### Before You Open a PR

1. Check that your code passes:
   - `cargo clippy --all-targets`
   - `cargo fmt`
   - `cargo check` (or `make test-unit`)
2. Write a descriptive commit message:
   - Format: `type(scope): description` (e.g., `feat(kernel32): implement CreateFileW`)
   - Body: explain *why* the change, not just *what* changed
3. Ensure your commit is signed: `git commit -s`

### PR Title & Description

**Title:** One line, summary of the change (e.g., "Implement GDI32 polygon drawing functions")

**Description template:**

```markdown
## What This Does
Brief explanation of what the PR accomplishes.

## Wine Reference
- dlls/gdi32/graphics.c:Polygon — handles self-intersecting paths with even-odd fill rule
- dlls/gdi32/graphics.c:Polyline — tested against conformance suite

## Testing
- Unit tests added/updated: [list them]
- Conformance test results: [did any change?]
- Tested with app: [Notepad++, PuTTY, etc.]

## Checklist
- [ ] Code passes `cargo clippy` and `cargo fmt`
- [ ] Tests pass (`make test-unit` or `make test`)
- [ ] Wine references documented for each function
- [ ] Clean-room process followed (original Rust code)
- [ ] CLA signed (if this is your first PR)
```

### Review & Iteration

- Expect feedback on code style, clean-room compliance, and architecture
- Respond to comments and push updates to the same branch
- The PR stays open until maintainer approval

---

## Tips for Success

- **Start small.** Implement a single function or a small group of related functions first.
- **Use Wine as a guide.** Consult Wine's implementation *before* writing code, not after.
- **Document your references.** The `// Wine ref:` comment is a gift to the next person (future you included).
- **Test early.** Run conformance tests against your implementation — they'll catch behavioral gaps.
- **Ask questions.** If something is unclear about the architecture or the process, open an issue or ask in a draft PR.

---

## Questions?

- **Architecture or design:** Open an issue
- **Process or setup:** See `CLAUDE.md` for deeper architecture docs and the test strategy
- **Clean-room questions:** See `active/projects/weave/CLEAN_ROOM.md`
- **Legal/CLA questions:** See `active/docs/CORPORATE_OPERATIONS.md` in the Business-OS repo

---

## Code of Conduct

Be respectful and collaborative. This is a volunteer open-source project built by people who care about free software.
