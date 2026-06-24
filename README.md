# Weave

**A Rust-native Windows compatibility layer for Linux. Built from scratch, not from Wine, and deliberately an order of magnitude smaller.**

Weave is a clean-room Rust reimplementation of the Win32 API surface. The Windows API is the dominant application binary interface on the planet: billions of devices, decades of software, and no open implementation that is memory-safe, sandboxed by default, or auditable at a fraction of the legacy codebase's complexity. Weave is that implementation, built to give Linux-based operating systems a secure, maintainable, freedom-respecting path to Windows application compatibility.

Licensed under GPL-3.0. Open for security auditing, research, and fork-under-GPL. Not accepting code contributions at this time (see [Contributing](#contributing)).

> **New here?** Read the [architecture paper](docs/ARCHITECTURE.md) for how Weave works and why it is so much smaller than Wine. For honest, per-phase status, see [ROADMAP.md](ROADMAP.md). This README is the engineering front matter: what exists today, how the repo is laid out, and how to build it.

---

## Why it's smaller

Wine does not translate Windows calls into Linux calls. It reimplements the entire Windows subsystem stack in userspace: its own window manager, compositor, software blitter, audio mixer, shell, registry parser, and OLE infrastructure. That is roughly **6.5 million lines of C** with the complexity surface of a 30-year-old OS kernel. It was the right design in 1993, when Linux had no Vulkan, no PipeWire, no Wayland, no Landlock, and no container ecosystem. Wine had to build those subsystems because the host didn't have them.

The host has them now. Weave delegates to them instead of reimplementing them.

| Subsystem | Wine | Weave |
|---|---|---|
| Graphics | Own window manager, software blitter, GL wrappers | Delegate to DXVK/VKD3D over host Vulkan |
| Windowing | `winex11` owns the full window tree (~1.5M lines) | Map `CreateWindowEx` to xcb; host compositor owns the tree (~17K) |
| Audio | Own ALSA/Pulse driver stack with mixer (~400K) | Map to PipeWire streams (~1.2K) |
| Shell | Full `explorer.exe` reimplementation (~800K) | None; the app runs in the host desktop |
| NT kernel | Own `ntoskrnl` (~600K) | ntdll shim for the syscalls real apps actually call (~2.5K) |

Wine inserts a complete Windows OS boundary between the app and the host kernel. Weave is a translation shim: it converts Windows calling conventions and data structures into native Linux syscalls and libraries, and lets the host do the heavy lifting. That architectural leverage is why Weave can cover a comparable application surface at roughly **5 to 10 percent of Wine's code volume**. The full reasoning, line-count projections, and debuggability analysis are in the [architecture paper](docs/ARCHITECTURE.md).

This is not a claim that Weave will ever support everything Wine supports. It will not. The wedge is narrow by design: the apps that matter for a specific audience, implemented well, sandboxed by default, in a fraction of the code.

---

## What works today

Weave is early-stage and experimental. The wedge is single-binary native Win32 desktop apps and SDL-era games that Wine handles poorly or insecurely, with sandboxing as the differentiator.

- A Rust PE loader and ntdll syscall gateway work end-to-end on the supported corpus.
- **1,661 Win32 exports are registered across 26 DLL emulation crates; 75 are fully implemented** per the [SHIM-CONTRACT](docs/SHIM-CONTRACT.md) (Wine-referenced behavior, non-panic body, exercised by a milestone gate). The rest are Phase A stubs: present in the resolver, returning sentinels, awaiting implementation. This staging is deliberate, not a sign of incompleteness; see the [architecture paper](docs/ARCHITECTURE.md) for why.
- Every app runs inside a Landlock filesystem sandbox by default. Bubblewrap process containment, seccomp filtering, and per-app network isolation are roadmap, not shipped.
- The supported-app list is short and per-release-tier. Green end-to-end CI gates today: **NXEngine-evo** (SDL2 game), **SDL2 testsprite2**, **Notepad++**, **7-Zip**, **IrfanView**, and **Q-Dir**. Apps not on the list are not supported.

**Real-desktop validation** (Fedora 41, GNOME Wayland, AMD RX 6700 XT, 2026-06-13):

- **7-Zip**: Supported. Full extraction, archive browsing, GUI browse-for-folder.
- **Notepad++**: CI gates green; editor save-roundtrip proven.
- **IrfanView**: BMP/JPEG/PNG/GIF open and PNG save proven; folder navigation proven.

DXVK/VKD3D, ARM64, the GUI manager, plugin system, compat DB, hardware-accelerated games, real network clients, and the install flow are scaffolded or in progress, not shipped. See [ROADMAP.md](ROADMAP.md) for honest per-phase status.

### What Rust does and doesn't buy you

Rust eliminates entire categories of memory-safety bugs that have lived in Wine's C codebase for decades. But Rust alone does not make Win32 compatibility safe. A Win32 host necessarily handles guest-controlled pointers and FFI across a trust boundary; the unsafe surface is structural. The real safety story is **Rust plus strict pointer validation plus sandboxing reduces the blast radius of an exploited bug**. Even when something goes wrong in the host, the guest can't reach your home directory, your network, or your system without explicit permission. Sandboxing is the load-bearing piece; Rust is the multiplier.

---

## Repo layout

Weave is a Cargo workspace of ~38 crates. The core principle: **every Windows DLL is a separate Rust crate**, independently versioned and testable. Adding a function to `kernel32` does not require understanding `user32`.

```
weave-core/          # PE loader, syscall dispatcher, process management
weave-kernel32/      # File I/O, process/thread/memory (~19K LoC, 450 exports)
weave-user32/        # Window management, input, messaging (~17K LoC, 329 exports)
weave-ntdll/         # NT layer primitives (~2.5K LoC)
weave-gdi32/         # 2D graphics via Cairo/Skia (~6K LoC, 128 exports)
weave-gdiplus/       # GDI+ surface (~2.9K LoC, 181 exports)
weave-advapi32/      # Registry, security, crypto (~4K LoC)
weave-ws2_32/        # Winsock networking (~2.4K LoC, 48 exports)
weave-shell32/       # Shell integration, file dialogs (~3.5K LoC, 36 exports)
weave-ucrt/          # Universal C runtime (~5.4K LoC, 139 exports)
weave-vulkan/        # Vulkan passthrough (~3.3K LoC, 291 exports)
weave-sandbox/       # Landlock isolation
...
```

Plus crates for comctl32, ole32, oleaut32, d3d12, ddraw, mmdevapi, shlwapi, winmm, xinput, and ~18 smaller ones (bcrypt, crypt32, imm32, secur32, setupapi, wldap32, normaliz, msvcp140, and others). Full crate list in [`weave-cli/src/main.rs`](weave-cli/src/main.rs).

The runtime has two always-active layers: **Weave Native** (API translation, mapping Windows syscalls to Linux equivalents, graphics to Vulkan, audio to PipeWire) and **Weave Sandbox** (Landlock filesystem isolation, on by default, no root required). The full architecture, sandbox threat model, and graphics pipeline are documented in the [architecture paper](docs/ARCHITECTURE.md).

---

## Clean-room methodology

APIs are not copyrightable (*Oracle v. Google*, 2021). Weave is an independent reimplementation: Wine's 30 years of reverse engineering is consulted as a behavioral reference for *what* each Win32 function must do, including the undocumented edges real apps depend on, but **no Wine code is copied**. Every implementation is original Rust, written from a behavioral spec derived from MSDN, Wine and ReactOS references, and black-box testing on real Windows.

The one hard rule: **never access proprietary Windows source** (leaked source, decompiled or disassembled binaries). The full reference policy, IP boundaries, and per-function documentation standard are in [docs/CLEAN-ROOM.md](docs/CLEAN-ROOM.md).

---

## What Weave is not

- **Not a Windows VM.** API translation, not virtualization. No VM fallback.
- **Not a Wine fork.** Independent implementation; no Wine code is used.
- **Not a drop-in Wine replacement.** The wedge is small native Win32 apps for a specific audience. Anything off the supported list is unsupported until it's on the list.
- **Not cloud-dependent.** Everything runs locally. No telemetry without explicit opt-in.

---

## Building

```bash
# Prerequisites: Rust 1.70+, Linux x86-64 target
rustup target add x86_64-unknown-linux-gnu

git clone https://github.com/The-Libre-Project/Weave.git
cd Weave

cargo check                                      # compiles
cargo zigbuild --target x86_64-unknown-linux-gnu # cross-compile from macOS
make test-unit                                   # unit tests, any platform
make test                                        # full suite (Linux or Docker)
```

Tagged releases (`vX.Y.Z` on `main`, after CI is green) publish a Linux x86-64 binary as `weave-x86_64` plus its `.sha256` on GitHub Releases. Weave runs x86-64 Windows PE code natively and does not ship an aarch64 build.

---

## Contributing

Weave is open source for transparency and security auditability. The codebase, commit history, and architecture are fully public under GPL-3.0 so researchers, auditors, and downstream projects can inspect and build on the work.

**We are not accepting external code contributions at this time.** Issues are welcome for bug reports and security disclosures. See [SECURITY.md](SECURITY.md) for the security contact.

---

## Stewardship

Weave is built and maintained by [IronTree Software](https://github.com/The-Libre-Project) as the founding asset of the [Libre Commons](https://github.com/The-Libre-Project/Commons), a public-infrastructure stewardship framework with a hard boundary between commons-scope work and product work: if the work benefits any Linux platform, developer, public institution, refurbisher, or downstream OS, it belongs to the Commons; if it creates IronTree-specific product leverage, it belongs to IronTree. Commons outputs (compatibility gates, sandbox architecture, validation data, reproducible builds, clean-room documentation) are public by rule.

---

*Weave is free software licensed under the GNU General Public License v3 (GPL-3.0).*
