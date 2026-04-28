# Weave — Security Posture

This is the project-level security framing for Weave. For the audit log of code-level findings (PE parser fuzzing, pointer validation passes, etc.) see [`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md). For portfolio-wide security policy across the Libre product family see [`Business-OS/SECURITY.md`](../Business-OS/SECURITY.md).

---

## What Rust does and doesn't buy you

Weave is written in Rust, and Rust eliminates entire categories of memory-safety bugs — use-after-free, double-free, buffer overruns from missed bounds checks — that have lived in Wine's C codebase for decades. That matters. It is also not the whole story, and overstating it is a credibility problem.

A Win32 compatibility host necessarily handles **guest-controlled pointers, ABI shims, and FFI across a trust boundary**. The unsafe surface is structural, not incidental:

- Every Win32 function that takes a `LPVOID`, `LPCSTR`, or HANDLE receives a value the guest controls. The host has to validate it before dereferencing.
- The PE loader parses attacker-controllable file structure before any sandbox is fully sealed.
- FFI into C libraries (DXVK, system libraries, the host kernel) crosses out of Rust's safety guarantees by definition.
- ABI shims that translate stdcall/cdecl/MS-x64 calling conventions are inherently `unsafe { }`.

The actual safety story is therefore **Rust + strict pointer validation + sandboxing reduces the blast radius of an exploited bug**. Each layer does part of the work:

- **Rust** removes the easiest, most common memory-safety bugs and makes the remaining unsafe surface auditable (it's the `unsafe { }` blocks; you can grep for it).
- **Strict pointer validation** at every Win32 entry point ensures guest-supplied pointers are bounds-checked, alignment-checked, and zero-checked before any host code dereferences them.
- **Sandboxing** ensures that *even when something goes wrong in the host*, the guest's reach is reduced. Today this is **Landlock filesystem isolation only**, applied before guest code runs; bubblewrap process containment, seccomp syscall filtering, and per-app network isolation are roadmap, not shipped. The current Landlock layer prevents the guest from reading or writing paths outside its prefix and the explicitly bridged user-data dirs, but does not constrain network or syscall surface.

Sandboxing is the load-bearing piece. Rust is the multiplier. Neither alone is the claim, and we don't make either alone.

This framing applies anywhere Weave's safety properties are described — in the README, in talks, in funding pitches. "Memory-safe Rust" by itself is not a claim Weave can defend; "sandboxed by default, written in Rust, with strict pointer validation at the trust boundary" is.

---

## Audit posture

- PE parser fuzzing and pointer validation pass: complete (Phase 6b WS3, 2026-04-05). See [`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md).
- In-process execution model: this is an accepted architectural limitation. Sub-process / out-of-process guest isolation is documented under guest-isolation analysis in `docs/STRATEGIC-AUDIT.md`.
- Reproducible builds + signing: tracked at the portfolio level — see `Business-OS/SECURITY.md`.

## Reporting a vulnerability

Open a private security advisory on the Weave GitHub repo, or email the maintainer directly. Do not open a public issue for unpatched vulnerabilities.
