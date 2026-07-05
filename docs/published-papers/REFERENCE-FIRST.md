# Weave Reference-First Policy

How the Weave project references existing work, what boundaries exist, and why. A public statement of method: both an engineering discipline and the basis for Weave's reference-first methodology as an independent Rust reimplementation of the Windows API.

---

## 1. Legal Landscape

**APIs are not copyrightable.** The Supreme Court settled this in *Oracle v. Google* (2021). Reimplementing the Windows API (function signatures, parameter names, return values, error codes) is legal regardless of how those interfaces were learned.

**Wine is LGPL. Weave is GPL-3.0.** The licenses are compatible. Reading Wine source to understand behavior: allowed. Using Wine as a behavioral reference for reimplementation: allowed. Writing original Rust code informed by Wine's approach: allowed. Copying Wine code verbatim into Weave: not allowed, and unnecessary, the languages differ, the architecture differs, and the entire point is a ground-up Rust implementation.

**ReactOS is GPL.** Same compatibility. Its source is readable as a reference for NT internals. Do not copy code.

**Windows source code is proprietary.** Never access leaked Windows source, decompiled binaries, or disassembled binaries. This is the one hard boundary, and it holds regardless of Weave's license.

## 2. The Reference Hierarchy

Weave is built from a layered reference approach, in strict order of authority.

### Primary: MSDN and public documentation

Microsoft Learn (MSDN) is the first stop for any function: official signatures, parameters, return values, error codes, and behavioral remarks. The Windows SDK headers provide struct definitions, constants, and flag values. Other official sources include Microsoft Open Specifications, the Windows API Index, and the *Windows Internals* book.

### Secondary: Wine and ReactOS as behavioral references

Wine's roughly 10 million lines of C represent 30 years of reverse engineering. Weave consults it to understand what a function should do, especially for undocumented edge cases MSDN does not cover. ReactOS serves the same role for NT-layer internals. References are queried through jcodemunch, an MCP server that indexes codebases into queryable symbol databases.

| Index | Contents | Used for |
|---|---|---|
| Wine | User-space Windows API in C | Primary reference for Win32 behavior |
| ReactOS | NT kernel, ntdll, ntoskrnl, HAL | NT-layer internals below the Win32 layer |
| DXVK | D3D 9/10/11 to Vulkan | DirectX translation edge cases |
| VKD3D-Proton | D3D 12 to Vulkan (Valve fork) | D3D12 translation |
| Samba | SMB/CIFS, named pipes, RPC, auth | Windows networking protocols |

When a reference and MSDN disagree, MSDN wins. When both are ambiguous, black-box testing on real Windows wins. No reference code is copied; the languages and architectures are fundamentally different, so there is nothing to copy even if someone tried.

### Tertiary: black-box observation

For undocumented behavior where MSDN is silent and Wine might be wrong, the authoritative source is Windows itself. Run minimal test programs on a licensed Windows 10/11 VM, record inputs, outputs, error codes, and side effects, and commit the test programs and results to the test suite.

## 3. The One Hard Rule

**Never access proprietary Windows source code.** This means no leaked Windows source (any version, any component), no decompiled Windows binaries (IDA, Ghidra, or similar output), and no disassembled Windows binaries.

Reading MSDN, reading Wine, reading ReactOS, reading reference books, and running test programs on Windows are all fine. Reading Microsoft's proprietary implementation is never fine. Anyone who has seen leaked Windows source for a specific component should not implement that component in Weave. This is the only disqualifying factor.

## 4. The Wine Test Suite

Wine ships roughly 90,000 unit tests. These are LGPL-licensed separate programs that test Windows API behavior, and they are a critical validation tool.

| Action | Status |
|---|---|
| Running Wine tests against Weave to measure conformance | Allowed |
| Reading Wine test source to understand expected behavior | Allowed |
| Using Wine test pass/fail results as a behavioral spec | Allowed |
| Copying Wine test code into Weave's source tree | Do not. Keep tests in a separate directory with LGPL headers intact |

The boundary: Wine tests validate Weave; they do not become part of Weave.

## 5. Per-Function Documentation

For non-trivial functions, the implementation documents which references were used:

```rust
/// # CreateFileW
///
/// ## References
/// - MSDN: fileapi/nf-fileapi-createfilew
/// - Windows SDK header: fileapi.h
/// - Wine behavioral ref: dlls/kernel32/file.c (read-only + CREATE_ALWAYS)
/// - Black-box test: tests/blackbox/kernel32/createfile_readonly.rs
///
/// ## Behavior notes
/// - CREATE_ALWAYS on existing read-only file: fails with
///   ERROR_ACCESS_DENIED (undocumented on MSDN)
```

This is not about legal defense. It is about engineering quality. When a function breaks months later, the reference trail says exactly where the behavioral spec came from and how to re-verify it, so the question "was the spec wrong or did the implementation drift?" has an answer.

## 6. Summary

Weave is GPL-3.0. Wine is LGPL. The licenses are compatible. Weave uses Wine and ReactOS as behavioral references, writes original Rust code, and never touches proprietary Windows source. The discipline around it, documenting references, black-box testing, keeping Wine tests separate, is not about avoiding lawsuits. It is about building software that can be debugged, verified, and maintained, and whose provenance can be shown rather than asserted.

*Weave is free software licensed under GPL-3.0. Built by IronTree Software as the founding asset of the Libre Commons.*
