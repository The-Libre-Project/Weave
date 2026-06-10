# Weave

**A Rust-native Windows compatibility layer for Linux — built from scratch, not from Wine.**

---

## What Weave is today

Weave is an experimental Rust reimplementation of the Win32 API. It is early-stage. The wedge is narrow on purpose: **single-binary native Win32 desktop apps and SDL-era games that Wine handles poorly or insecurely, with sandboxing as the differentiator.**

Concretely, today:

- A Rust PE loader and ntdll syscall gateway exist and work end-to-end on the supported corpus.
- A small set of Win32 DLLs is implemented as separate Rust crates (kernel32, user32, gdi32, ntdll, ws2_32, comctl32, oleaut32, shlwapi, gdiplus, ucrt, etc.). Coverage within each is partial; many functions are stubs.
- Every app runs inside a Landlock filesystem sandbox by default. Bubblewrap process containment, seccomp syscall filtering, and per-app network isolation are roadmap, not shipped. Relaxing the Landlock allowlist is opt-in.
- The supported-app list is short and per-release-tier. The current end-to-end gates that are green in CI (not `#[ignore]`'d) are: **NXEngine-evo** (SDL2 game, software renderer, dummy audio), **SDL2 testsprite2** (rendering smoke), and a **Notepad++ resource walk**. Apps not on the list are not supported. See [`PROJECT-TRUTH.md`](PROJECT-TRUTH.md) for the live list and known gaps.
- DXVK / VKD3D, ARM64, GUI manager, plugin system, compat DB, hardware-accelerated games, real network clients, and the install flow are scaffolded or in progress — not shipped. See [`ROADMAP.md`](ROADMAP.md) for honest per-phase status.

This is not "a Wine alternative." It is a small, narrow, experimental project doing real work on a specific corpus.

### The supported-app list

Weave ships with a hard supported-app list per release tier. Apps not on the list don't run. **There is no fallback layer.** A fallback would hide Weave's actual gaps from both users and engineers — every fallback hit is really "Weave didn't work" papered over. Adoption succeeds by growing the list, not by hiding failure. See [`Business-OS/COMPAT-TIERS.md`](../Business-OS/COMPAT-TIERS.md) for tier definitions.

### Security framing — what Rust does and doesn't buy you

Rust eliminates entire categories of memory-safety bugs that have lived in Wine's C codebase for decades. But Rust alone does not make Win32 compatibility safe. A Win32 host necessarily handles guest-controlled pointers, ABI shims, and FFI across a trust boundary — the unsafe surface is structural, not incidental. The real safety story is **Rust + strict pointer validation + sandboxing reduces the blast radius of an exploited bug**: even when something goes wrong in the host, the guest can't reach your home directory, your network, or your system without explicit permission. Sandboxing is the load-bearing piece. Rust is the multiplier. Neither alone is the claim.

---

## Vision

The sections below describe where the project is aimed, not where it is. Treat everything here as long-arc intent.

### The idea

Wine spent 30 years reverse-engineering the Windows API — figuring out what every function does, including the undocumented behaviors and edge cases that real applications depend on. That work is extraordinary, and it's irreplaceable.

But Wine is also 30 years old. It's 10 million lines of C with no memory safety, no sandboxing, an architecture that predates containers and Vulkan, and the kind of accumulated complexity that comes from maintaining any large C project across three decades.

Weave is a fresh answer to the same question Wine answered in 1993: *how do you run Windows applications on Linux?* Wine's body of knowledge is the reference; the Rust implementation is new.

The relationship is something like Firefox to Netscape: same problem, same era of users, no code in common. Built fresh because the old way accumulated too much debt to fix from the inside.

### Why this matters technically

A few things that fall out of starting over:

**The graphics stack is simpler than it looks.** DXVK — the battle-tested DirectX-to-Vulkan translation layer that ships inside Steam's Proton — has a fully maintained native Linux build mode (`dxvk-native`) that has *zero* Wine dependencies. It loads `libvulkan.so` directly. The Wine-specific code paths are simply absent in the native build. This means Weave can host DXVK directly. (Wired up in scaffolding; no game has rendered a frame through it yet — see ROADMAP Phase 3.)

**Sandboxing is a default, not a feature.** Wine runs with full user permissions. In Weave, isolation is the starting state. Today this means Landlock filesystem restrictions applied before guest code runs; bubblewrap process containment and seccomp syscall filtering are roadmap. Relaxing the Landlock allowlist requires explicit action.

**Modularity is structural.** Every Windows DLL is a separate Rust crate. Adding a function to `kernel32` doesn't require understanding `user32`. Contributors can own individual shims, publish independent patches, and test in isolation.

### Core principles

**Rust-native.** The entire core — PE loader, ntdll gateway, syscall dispatcher — is written in Rust. Memory safety eliminates entire classes of bugs that have existed in Wine for decades. (See the "Security framing" note above for what this does and doesn't buy you.)

**Sandboxed by default.** Every Windows application runs with Landlock filesystem restrictions applied before guest code begins executing — paths outside the allowlisted prefix and bridged user-data dirs are blocked at the kernel level. Bubblewrap process containment and user-namespace isolation are roadmap, not shipped today.

**Cross-architecture (planned).** Native x86_64 today; first-class ARM64 via integrated FEX/Box64 CPU translation is a roadmap target, not a shipped capability.

**Community-extensible.** Each major Windows DLL is implemented as a separate Rust crate. Contributors can build, test, and publish individual API shims without touching core code. AI-assisted stub generation from Microsoft's public API documentation accelerates coverage.

### Architecture

Weave's runtime is structured in two layers, both always active:

#### Weave Native — API translation

Rust-based API translation maps Windows system calls to Linux equivalents. Graphics target Vulkan (via DXVK / VKD3D when those paths are wired up). Audio targets PipeWire. Filesystem calls route through a virtual prefix.

#### Weave Sandbox — isolation

What's actually shipped today:
- **Landlock filesystem restrictions** — applied after the PE is loaded and the IAT is patched but before guest code runs; the app sees only its own prefix plus explicitly bridged user-data directories. Requires Linux 5.13+; on older kernels the restriction is silently skipped and a diagnostic line is printed.

What's *not* shipped today (roadmap):
- **Bubblewrap process containment** and **user-namespace isolation** — Phase 4+ target. The current model runs the guest PE in Weave's own address space.
- **seccomp syscall filtering** — incompatible with the current in-process model. Because the PE shares Weave's address space, any seccomp filter would have to allowlist every syscall Weave itself uses (mmap, write, exit, …), which gives the guest the same syscall surface anyway. Real syscall isolation requires the out-of-process redesign. (See [`weave-sandbox/src/lib.rs`](weave-sandbox/src/lib.rs) lines 7–12.)
- **Per-app network isolation** — not implemented; guest code uses the host network stack.

The Landlock layer is not optional and is on by default. Users can adjust the path allowlist, but the safe default requires no configuration.

If an app on the supported list doesn't work, the right answer is to fix the underlying gap — not to hide it behind a fallback runtime.

### Modular DLL system

The Windows API surface is vast — thousands of functions across hundreds of DLLs. Weave handles this with a modular crate system:

```
weave-core/          # PE loader, syscall dispatcher, process management
weave-ntdll/         # NT layer primitives
weave-kernel32/      # File I/O, process/thread management, memory
weave-user32/        # Window management, input, messaging
weave-gdi32/         # 2D graphics (mapped to Cairo/Skia)
weave-advapi32/      # Registry, security, crypto
weave-ws2_32/        # Winsock networking
weave-shell32/       # Shell integration, file dialogs
weave-ole32/         # COM/OLE automation
weave-d3d/           # DirectX → Vulkan translation (wraps DXVK/VKD3D)
weave-mmdevapi/      # Audio → PipeWire
weave-winspool/      # Printing → CUPS
```

Each crate is independently versioned, tested, and publishable. Community contributors can implement a single DLL function without understanding the full system. AI-assisted tooling generates initial stubs from Microsoft's public documentation, which contributors then refine and test.

#### Plugin system (disabled)

Third-party `.so` plugins were intended to register custom API implementations at runtime. The loader is **currently disabled**: prefix-local `.so` loading from a user-writable directory was unsafe by design (it ran before the Landlock sandbox and would dlopen arbitrary native code without signature verification), and no plugins are shipped. The loader crate is preserved for a future signed-plugin model and is not wired up to any binary.

### Compatibility approach

Weave does **not** maintain a crowd-sourced "anything might work" compatibility database in the Wine AppDB sense. The model is the opposite: a small, hard, **named** supported-app list per release tier, with end-to-end CI gates that have to be green and not `#[ignore]`'d for an app to be on the list. The list grows as gates close.

Static analysis of application binaries to predict required APIs and pre-load shims is a future tooling target, not a shipped capability.

### Graphics pipeline (target)

- **DirectX 9/10/11** — translate to Vulkan via DXVK
- **DirectX 12** — translate to Vulkan via VKD3D-Proton
- **OpenGL** — host OpenGL or Zink
- **Vulkan** — passthrough
- **GDI/GDI+** — Cairo/Skia for 2D rendering

All graphics paths target Vulkan as the common backend. Today, the only validated graphics path is the SDL software renderer for NXEngine-evo and SDL2 testsprite2; hardware-accelerated games are not yet validated.

### What Weave is not

- **Not a Windows VM.** The path is API translation, not virtualization. There is no VM fallback.
- **Not a Wine fork.** Weave is a clean-room implementation. No Wine code is used in the core. Wine's reverse engineering informs *what* needs to be implemented; the implementation is new.
- **Not a drop-in Wine replacement.** Weave's wedge is small native Win32 apps Wine handles poorly or insecurely. Anything outside the supported-app list is not supported.
- **Not cloud-dependent.** Everything runs locally. No internet required. No telemetry without explicit opt-in.

---

## Releases

Tagged releases (`v*`) publish a Linux x86-64 binary as `weave-x86_64` plus `weave-x86_64.sha256` on GitHub Releases. Weave runs x86-64 Windows PE code natively and does not ship an aarch64 Linux build. To cut a release: tag `vX.Y.Z` on `main` after CI is green; the release workflow builds with `--release` and attaches both files. Dry-run without creating a release: `gh workflow run release.yml`.

## Roadmap

For honest per-phase status (what's complete vs. code-exists vs. scaffolded vs. not started), see [`ROADMAP.md`](ROADMAP.md). The summary is: PE loader and minimal kernel32 / user32 / gdi32 plus sandboxing work end-to-end on a small corpus; DXVK/VKD3D, ARM64, GUI manager, install flow, real network clients, and hardware-accelerated games are open work.

---

## Security model

| Layer | Status today |
|-------|-------------|
| Filesystem | **Implemented.** Landlock restrictions — guest sees only its prefix + bridged user-data dirs. Requires Linux 5.13+; silently skipped (with diagnostic) on older kernels. |
| Process isolation | **Roadmap.** Bubblewrap + user namespaces — Phase 4+ (out-of-process model). |
| Syscalls | **Roadmap.** seccomp filtering — blocked by the current in-process design (see footnote). |
| Network | **Roadmap.** Per-app network isolation — not implemented; guest uses the host network stack. |
| No root required | **Implemented.** Weave never needs elevated privileges. |

Footnote on seccomp: the PE binary today shares Weave's address space, so a seccomp filter would have to allowlist every syscall Weave itself needs (mmap, write, exit, …) — which gives the guest the same syscall surface anyway. Meaningful syscall isolation requires moving the guest into a separate process; that's Phase 4+. See [`weave-sandbox/src/lib.rs`](weave-sandbox/src/lib.rs) lines 7–12.

Today, Landlock restricts path-based filesystem access outside the allowlisted prefix and the explicitly bridged user-data directories (see [`docs/design/USER-DATA-BRIDGE-POLICY.md`](docs/design/USER-DATA-BRIDGE-POLICY.md) for the trade-off between isolation and the user-data bridge). Network and syscall isolation are not yet implemented. Containment of file access is real; broader containment of network and kernel surface is roadmap, not shipped.

For the security audit posture see [`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md) and [`SECURITY.md`](SECURITY.md).

---

## Tech stack

- **Language:** Rust (core), with C FFI where needed for existing libraries
- **Build:** Cargo workspace
- **Graphics:** Vulkan (via ash/vulkano), DXVK, VKD3D-Proton (target)
- **Audio:** PipeWire (via pipewire-rs) (target)
- **Sandbox:** Landlock (bubblewrap and seccomp are roadmap)
- **Cross-arch (planned):** FEX-Emu / Box64 for ARM64 → x86_64 translation
- **GUI (planned):** Tauri 2 (Rust + Svelte)
- **License:** MIT

---

## Development infrastructure — Wine symbolic compression

Weave is a clean-room reimplementation, but Wine's 30 years of reverse engineering is an invaluable reference for *what* the Windows API actually does — especially undocumented behaviors that real applications depend on. The challenge is that Wine's codebase is roughly 10 million lines of C across thousands of files. Reading it traditionally burns context windows and tokens at an unsustainable rate.

### jcodemunch MCP — symbolic indexing

[jcodemunch-mcp](https://github.com/jgravelle/jcodemunch-mcp) is an MCP server that parses a codebase using AST (abstract syntax tree) analysis, indexes every function, struct, and symbol, and stores them in a local SQLite database with byte-level precision. Instead of reading entire files, AI agents query by symbol name and get just that function's source code.

**Setup (one-time):**

```bash
git clone https://gitlab.winehq.org/wine/wine.git ~/wine-reference
claude mcp add jcodemunch uvx jcodemunch-mcp
# index the Wine source — runs once, persists in SQLite
```

**Impact:**

| Operation | Without indexing | With jcodemunch |
|-----------|-----------------|-----------------|
| "Show me Wine's `CreateFileW`" | Read entire `kernel32/file.c` (~2000 lines, ~8000 tokens) | Return just the function (~80 lines, ~400 tokens) |
| Token reduction | — | ~95% per lookup |
| Full API surface scan | Read hundreds of files | Query the index |

Over the lifetime of Weave development — tens of thousands of Wine reference lookups — this turns Wine from "a codebase you have to read" into "a database you can query."

### The AI-assisted reimplementation loop

This is the core development cycle for every DLL function in Weave:

1. **Reference** — Query jcodemunch: "Show me Wine's `NtCreateFile`" → get the C implementation in ~400 tokens
2. **Understand** — AI reads the C implementation, identifies the behavioral contract including undocumented side effects
3. **Rewrite** — AI generates a Rust reimplementation using Weave's architecture, sandbox constraints, and modern Linux primitives
4. **Test** — Run against real Windows behavior (captured in test suites) to verify correctness
5. **Iterate** — If behavior diverges, query Wine's implementation for edge cases, adjust, retest

Steps 1–3 are heavily AI-assisted. Step 4 requires real Windows reference output (automated CI against a Windows VM). Step 5 is where human contributors add the most value — understanding *why* an edge case exists.

### Coverage mapping

The Wine index also enables project-wide coverage analysis before writing any code:

- **"Which kernel32 functions does Wine implement?"** → full symbol list from the index
- **"Which are stubs vs. real implementations?"** → grep for `FIXME` and `stub` markers across the indexed source
- **"What does Wine's implementation of X call internally?"** → trace the dependency graph through symbol references

This produces a prioritized implementation roadmap: start with the most-called functions that have real Wine implementations, skip the stubs, defer the rare APIs. Data-driven development from day one.

---

## Contributing

Weave's modular DLL crate system is designed for distributed contribution. Pick a DLL, pick a function, implement it, test it, submit a PR. You don't need to understand the entire system to make a meaningful contribution.

- [Validation tiers](docs/VALIDATION-TIERS.md) — binary-contract gate model for milestones

The AI-assisted stub generation pipeline produces initial function signatures and basic implementations from Microsoft's public documentation. Contributors review, correct, and extend these stubs with real-world testing.

Priority areas:
- Kernel engineers — syscall translation, PE loader, process management
- Graphics engineers — DirectX translation, Vulkan integration
- Application developers — DLL implementations, compatibility testing
- Security researchers — sandbox hardening, malware containment testing

---

## Related projects

- **[Warden](https://github.com/eldo9000/Warden)** — Open-source, cross-platform anti-cheat for game developers. Native Linux + Windows support. Designed to work with Weave for gaming use cases.
- **[LibreWin OS](https://github.com/eldo9000/LibreWin-OS)** — A polished Linux desktop aimed at Windows/macOS switchers. Weave is designed to be the Windows compatibility layer for LibreWin.

---

*Weave is free, open-source software under the MIT license.*
