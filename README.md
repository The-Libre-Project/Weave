# Weave

**A Rust-native Windows compatibility layer for Linux — built from scratch, not from Wine.**

Run Windows applications on Linux with memory safety, default sandboxing, and cross-architecture support. No Windows license required.

---

## The idea

Wine spent 30 years reverse-engineering the Windows API — figuring out what every function does, including the undocumented behaviors and edge cases that real applications depend on. That work is extraordinary, and it's irreplaceable.

But Wine is also 30 years old. It's 10 million lines of C with no memory safety, no sandboxing, an architecture that predates containers and Vulkan, and the kind of accumulated complexity that comes from maintaining any large C project across three decades.

Weave is not a Wine replacement. It's a fresh answer to the same question Wine answered in 1993: *how do you run Windows applications on Linux?*

Wine did the hard work of figuring out what Windows actually does. Weave uses that knowledge as a reference — not code — to build the same thing from scratch in Rust, with 2020s infrastructure, 2020s security defaults, and 2020s architecture.

The relationship is something like Firefox to Netscape: same problem, same era of users, no code in common. Built fresh because the old way accumulated too much debt to fix from the inside.

---

## Why this matters technically

A few things that fall out of starting over:

**The graphics stack is simpler than it looks.** DXVK — the battle-tested DirectX-to-Vulkan translation layer that ships inside Steam's Proton — has a fully maintained native Linux build mode (`dxvk-native`) that has *zero* Wine dependencies. It loads `libvulkan.so` directly. It doesn't call `__wine_get_vulkan_driver`. It doesn't need winevulkan. It doesn't import anything from Wine's ntdll. The Wine-specific code paths are simply absent in the native build. This means Weave can host DXVK directly — the hardest part of a Windows compatibility layer for gaming turned out to be largely solved by a library that doesn't require Wine at all.

**Sandboxing is a default, not a feature.** Wine runs with full user permissions — every Windows application gets access to everything your Linux user account can touch. In Weave, isolation is the starting state. Each application runs in its own namespace with Landlock filesystem restrictions and seccomp syscall filtering. Relaxing permissions requires explicit action. This matters for running untrusted software, which is exactly what a Windows compatibility layer does.

**Modularity is structural.** Every Windows DLL is a separate Rust crate. Adding a function to `kernel32` doesn't require understanding `user32`. Contributors can own individual shims, publish independent patches, and test in isolation. The Windows API surface is enormous — the only way to cover it is to make contribution easy.

---

## Core principles

**Rust-native.** The entire core — PE loader, ntdll gateway, syscall dispatcher — is written in Rust. Memory safety eliminates entire classes of bugs that have existed in Wine for decades. Modern concurrency primitives (io_uring, futex2) replace legacy approaches.

**Sandboxed by default.** Every Windows application runs in its own isolated environment using Landlock, bubblewrap, and user namespaces. No Windows program gets access to your home directory unless you explicitly allow it. Wine runs with full user permissions. Weave doesn't.

**Cross-architecture.** Native x86_64 support plus first-class ARM64 via integrated FEX/Box64 CPU translation. Windows apps run on Apple Silicon Linux VMs, Snapdragon laptops, and Raspberry Pi — not as an afterthought, but as a core design target.

**Community-extensible.** Each major Windows DLL is implemented as a separate Rust crate with traits for POSIX mapping. Contributors can build, test, and publish individual API shims without touching core code. AI-assisted stub generation from Microsoft's public API documentation accelerates coverage.

---

## Architecture

Weave operates in three tiers, transparent to the user. You double-click an `.exe`. Weave handles the rest.

### Tier 1 — Weave Native

The primary path. Rust-based API translation maps Windows system calls to Linux equivalents at near-native speed. Graphics go through DXVK/VKD3D-style Vulkan translation. Audio maps to PipeWire. Filesystem calls route through a virtual prefix.

This is equivalent to what Wine does, but in Rust, with modern Linux primitives, and with sandboxing enforced at every layer.

### Tier 2 — Weave Sandbox

Always active. Every application runs inside a bubblewrap container with:
- Its own user namespace (no access to host user context)
- Landlock filesystem restrictions (app sees only its own prefix + explicitly shared directories)
- seccomp syscall filtering (blocks dangerous kernel calls)
- Network isolation available per-app

This is not optional. Sandboxing is the default state. Users can relax permissions per-app if needed, but the safe path requires no configuration.

### Tier 3 — Weave VM

When native API translation can't handle an application, Weave falls back to a lightweight ReactOS micro-VM running inside KVM. ReactOS is a free, open-source reimplementation of the Windows NT kernel — no Windows license required.

The VM runs headless with virtio-gpu for display, virtiofs for file sharing, and shared clipboard. The application window composites seamlessly into the Linux desktop. The user never knows which tier is running — they just see their app.

---

## Modular DLL system

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

Each crate is independently versioned, tested, and publishable. Community contributors can implement a single DLL function without understanding the full system. AI-assisted tooling generates initial stubs from Microsoft's public API documentation, which contributors then refine and test.

### Plugin system

Third-party `.so` plugins can register custom API implementations at runtime. This allows:
- Game-specific compatibility patches without core changes
- Engine-specific optimizations (Unity, Unreal, Electron detection + fast paths)
- Vendor-contributed shims for proprietary software

---

## Compatibility database

Weave maintains a crowd-sourced compatibility database — similar to Wine's AppDB but automated:

- Applications report their import tables on first launch (with user consent)
- The database tracks which DLL functions each application calls and whether they succeed
- When a new shim is published, every affected application's compatibility status updates automatically
- Users can download pre-tested app configurations (prefix settings, required shims, known workarounds) in one click

Static analysis of application binaries predicts which APIs are needed before launch, pre-loading the right shims and flagging missing coverage upfront instead of crashing mid-run.

---

## Graphics pipeline

- **DirectX 9/10/11** — translated to Vulkan via DXVK (proven, shipping in Proton today)
- **DirectX 12** — translated to Vulkan via VKD3D-Proton
- **OpenGL** — mapped to host OpenGL or translated to Vulkan via Zink
- **Vulkan** — passthrough (Windows Vulkan apps run with zero translation overhead)
- **GDI/GDI+** — mapped to Cairo/Skia for 2D rendering

All graphics paths target Vulkan as the common backend, which runs on Intel, AMD, and NVIDIA GPUs across x86_64 and ARM64.

---

## What Weave is not

- **Not a Windows VM.** The primary path is API translation, not virtualization. The VM tier is a fallback, not the default.
- **Not a Wine fork.** Weave is a clean-room implementation. No Wine code is used in the core. Wine's decades of reverse engineering inform what needs to be implemented, but the implementation is new.
- **Not a game-first tool.** Games are supported, but Weave targets the full Win32 desktop application surface — productivity apps, creative tools, utilities, and games.
- **Not cloud-dependent.** Everything runs locally. No internet required. No telemetry without explicit opt-in.

---

## Roadmap

### Phase 1 — Foundation
- Rust PE loader + ntdll syscall dispatcher
- Minimal kernel32 (file I/O, process management, memory)
- Bubblewrap sandbox integration
- Can launch simple Win32 console applications

### Phase 2 — Desktop apps
- user32 + gdi32 (window management, 2D graphics)
- Shell integration (file dialogs, drag-and-drop, clipboard)
- Registry emulation
- COM/OLE basics
- Can launch simple GUI applications (Notepad-class)

### Phase 3 — Graphics + audio
- DXVK/VKD3D integration for DirectX
- PipeWire audio backend
- Input handling (XInput, DirectInput)
- Can run games and media applications

### Phase 4 — Ecosystem
- Compatibility database + crowd-sourced configs
- AI-assisted stub generation pipeline
- Plugin system for third-party shims
- ReactOS micro-VM fallback tier
- ARM64 via FEX/Box64 integration

### Phase 5 — Polish
- One-click app install from curated database
- Tauri-based GUI for managing applications and prefixes
- Desktop integration (Wayland fractional scaling, HiDPI, taskbar icons)
- Performance optimization (eBPF-assisted syscall fast paths where beneficial)

---

## Security model

| Layer | Protection |
|-------|-----------|
| Process isolation | Each app in its own user namespace |
| Filesystem | Landlock restrictions — app sees only its prefix + shared dirs |
| Syscalls | seccomp filtering blocks dangerous kernel calls |
| Network | Per-app network isolation available |
| VM fallback | ReactOS guest provides full kernel-level containment |
| No root required | Weave never needs elevated privileges |

Windows malware that runs through Weave is contained by default. It cannot access your files, your network, or your system without explicit permission. This is a fundamental improvement over Wine, where every Windows application has the same access as your Linux user account.

---

## Tech stack

- **Language:** Rust (core), with C FFI where needed for existing libraries
- **Build:** Cargo workspace
- **Graphics:** Vulkan (via ash/vulkano), DXVK, VKD3D-Proton
- **Audio:** PipeWire (via pipewire-rs)
- **Sandbox:** bubblewrap, Landlock, seccomp
- **VM fallback:** KVM/QEMU with ReactOS guest, virtio-gpu, virtiofs
- **Cross-arch:** FEX-Emu / Box64 for ARM64 → x86_64 translation
- **GUI:** Tauri 2 (Rust + Svelte)
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
- **"Which functions are most commonly imported by Win32 apps?"** → cross-reference with the compatibility database import tables

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
