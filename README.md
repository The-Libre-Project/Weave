# Weave

**A Rust-native Windows compatibility layer for Linux. Built from scratch, not from Wine — and deliberately an order of magnitude smaller.**

---

## The architectural insight

Thirty years of reverse engineering gives you an irreplaceable body of knowledge about what every Win32 function actually does, including the undocumented edges that real applications depend on. That is Wine's gift to the world, and Weave is built on it.

But the mechanism matters. Wine does not *translate* Windows calls into Linux calls. Wine **reimplements the entire Windows subsystem stack in userspace on Linux** — its own window manager, its own compositor, its own software blitter, its own audio mixer, its own shell, its own registry hive parser, its own OLE infrastructure. Each of these is a full OS subsystem re-expressed in C, which is why Wine clocks in at roughly **6.5 million lines of code** and has the complexity surface of a 30-year-old operating system kernel written in C.

That is not the only way to build a compatibility layer.

| Subsystem | Wine approach | Weave approach | What this means |
|---|---|---|---|
| Graphics | Wine's own `winex11` window manager + software blitter + OpenGL wrappers | Delegate to DXVK/VKD3D, which speaks Vulkan directly on the host | No reimplemented compositor; Vulkan drivers already exist on Linux |
| Windowing | `winex11` — Wine owns `CreateWindow`, `DispatchMessage`, window Z-order, focus, clipping, region management, and every pixel of the non-client area | Map `CreateWindowEx` to xcb; let X11/Wayland own the compositor tree | ~1.5M lines of Wine window management replaced by ~17K lines of xcb bridge |
| Audio | Wine's own ALSA/OSS/PulseAudio driver stack with per-app mixer, position APIs, format conversion, and resampling | Map `PlaySound`, `waveOut*` to PipeWire streams | ~400K lines of audio drivers replaced by ~1.2K lines of PipeWire bridge |
| Shell | Wine's `explorer.exe` reimplementation — taskbar, tray, desktop icons, start menu, file manager | None. The app runs in the host desktop; the host shell is the shell | ~800K lines of shell code that don't exist in Weave |
| NT kernel | Wine's ntoskrnl — memory manager, object manager, I/O manager, process manager, configuration manager, security reference monitor, LPC | ntdll shim for the handful of NT syscalls that real apps call through the DLL boundary | ~600K lines trimmed to ~2.5K |

Wine is a **boundary OS** — it inserts a complete Windows operating system boundary between the guest binary and the host kernel. Weave is a **translation shim** — it translates Windows calling conventions and data structures into native Linux syscalls and libraries. The host does the heavy lifting. Weave is the adapter.

This is not a value judgment. Wine's approach was the right one in 1993 when Linux had no Vulkan, no PipeWire, no Wayland compositor, no namespaces, no Landlock, and no container ecosystem. Wine had to build all of those subsystems because they did not exist on the host side.

They exist now. Weave uses them.

### The line-count consequence

This architectural leverage means Weave can cover a comparable application surface at **roughly 5–10% of Wine's code volume**:

| Phase | Cumulative Rust LoC | What's working | Analogous state |
|---|---|---|---|
| **Current** (HEAD) | **~105K** (154K with docs/tooling) | ~21 milestones closed; 7-Zip supported on real desktop; Notepad++, IrfanView, Q-Dir passing CI gates | Ship-of-Theseus phase: filling stubs with real implementations |
| **v1 ship** (10 Tier-1 apps, real-desktop-validated) | **~200–250K** (~300K total) | All listed apps do their core task; D3D9 via DXVK proven; SSH and plain HTTP networking; audio scaffolded | Comparable to a large standalone application |
| **Stable asymptote** (mature stubs, high-value app corpus) | **~350–450K** (~500K total) | Sandboxed by default; broad Win32 surface; self-hosting for the supported app list | Comparable to the Linux kernel's DRM subsystem or a modern browser engine's GPU layer |
| **Completionist asymptote** (obscure one-off APIs) | **~500K** (~700K total) | Long tail of rarely-called APIs — written when a target app needs them, not speculatively | Still <11% of Wine's 6.5M lines |

The curve is logistic: rapid linear growth now as stub→impl conversion fills out the critical path, then deceleration as each new target app requires fewer new APIs, and finally a long tail of obscure one-off exports that never get written because no target app calls them.

```
 LoC
500K │                                    ── completionist asymptote
     │                                 ╱
400K │                              ╱   ── stable asymptote
     │                           ╱
300K │                        ╱   ── v1 ship
     │                     ╱
200K │                  ╱
     │               ╱
100K │ ─────────────   ── current
     │
     └────────────────────────────────────────────►  Time
         Era 2    v1       mature        long tail
```

This is not a claim that Weave will ever support everything Wine supports. It will not. The wedge is narrow by design: **the apps that matter for a specific audience, implemented well, sandboxed by default, in a fraction of the code.** Expanding the wedge is a conscious decision per target app, not a background promise.

---

## What Weave is today

Weave is an experimental Rust reimplementation of the Win32 API. It is early-stage. The wedge is narrow on purpose: **single-binary native Win32 desktop apps and SDL-era games that Wine handles poorly or insecurely, with sandboxing as the differentiator.**

Concretely, today:

- A Rust PE loader and ntdll syscall gateway exist and work end-to-end on the supported corpus.
- The Win32 surface is split across more than two dozen DLL crates (kernel32, user32, gdi32, ntdll, ws2_32, comctl32, oleaut32, shlwapi, gdiplus, ucrt, …) inside a ~38-crate Cargo workspace that also holds the loader, sandbox, and tooling. **1,661 Win32 exports are registered across 26 DLL emulation crates; 75 of those are fully implemented per the [SHIM-CONTRACT](docs/SHIM-CONTRACT.md) definition** (Wine-referenced behavior, non-panic body, exercised by a milestone gate). The rest are Phase A stubs — present in the resolver, returning sentinels, awaiting implementation.
- Every app runs inside a Landlock filesystem sandbox by default. Bubblewrap process containment, seccomp syscall filtering, and per-app network isolation are roadmap, not shipped. Relaxing the Landlock allowlist is opt-in.
- The supported-app list is short and per-release-tier. The current end-to-end gates that are green in CI (not `#[ignore]`'d) are: **NXEngine-evo** (SDL2 game, software renderer), **SDL2 testsprite2** (rendering smoke), **Notepad++** (resource walk, editor roundtrip), **7-Zip** (extraction, GUI browse-for-folder), **IrfanView** (BMP/JPEG/PNG/GIF open, PNG save, folder navigation), and **Q-Dir** (launch, file-pane population). Apps not on the list are not supported. See [`PROJECT-TRUTH.md`](PROJECT-TRUTH.md) for the live list and known gaps.
- DXVK / VKD3D, ARM64, GUI manager, plugin system, compat DB, hardware-accelerated games, real network clients, and the install flow are scaffolded or in progress — not shipped. See [`ROADMAP.md`](ROADMAP.md) for honest per-phase status.

This is not "a Wine alternative." It is a small, narrow, experimental project doing real work on a specific corpus.

### Real-desktop validation

Three Tier-1 target apps have been validated on real hardware (Fedora 41, GNOME Wayland, AMD RX 6700 XT, 2026-06-13):

- **7-Zip** — ✅ Supported. Full file extraction, archive browsing, and GUI browse-for-folder workflow.
- **Notepad++** — 🔶 CI gates green; editor save-roundtrip proven.
- **IrfanView** — 🔶 BMP/JPEG/PNG/GIF open and PNG save proven; folder navigation proven.

### Security framing — what Rust does and doesn't buy you

Rust eliminates entire categories of memory-safety bugs that have lived in Wine's C codebase for decades. But Rust alone does not make Win32 compatibility safe. A Win32 host necessarily handles guest-controlled pointers, ABI shims, and FFI across a trust boundary — the unsafe surface is structural, not incidental. The real safety story is **Rust + strict pointer validation + sandboxing reduces the blast radius of an exploited bug**: even when something goes wrong in the host, the guest can't reach your home directory, your network, or your system without explicit permission. Sandboxing is the load-bearing piece. Rust is the multiplier. Neither alone is the claim.

---

## Architecture

Weave's runtime is structured in two layers, both always active:

### Weave Native — API translation

Rust-based API translation maps Windows system calls to Linux equivalents. Graphics target Vulkan (via DXVK / VKD3D when those paths are wired up). Audio targets PipeWire. Filesystem calls route through a virtual prefix.

### Weave Sandbox — isolation

| Layer | Status today |
|-------|-------------|
| Filesystem | **Implemented.** Landlock restrictions — guest sees only its prefix + bridged user-data dirs. Requires Linux 5.13+; silently skipped (with diagnostic) on older kernels. |
| Process isolation | **Roadmap.** Bubblewrap + user namespaces — out-of-process model (Phase 4+). |
| Syscalls | **Roadmap.** seccomp filtering — blocked by the current in-process model (see below). |
| Network | **Roadmap.** Per-app network isolation — not implemented; guest uses the host network stack. |
| No root required | **Implemented.** Weave never needs elevated privileges. |

Seccomp footnote: the PE binary today shares Weave's address space, so a seccomp filter would have to allowlist every syscall Weave itself needs (mmap, write, exit, …) — which gives the guest the same syscall surface anyway. Meaningful syscall isolation requires moving the guest into a separate process; that's Phase 4+. See [`weave-sandbox/src/lib.rs`](weave-sandbox/src/lib.rs) lines 7–12.

The Landlock layer is not optional and is on by default. Users can adjust the path allowlist, but the safe default requires no configuration.

If an app on the supported list doesn't work, the right answer is to fix the underlying gap — not to hide it behind a fallback runtime.

### Modular DLL system

The Windows API surface is vast — thousands of functions across hundreds of DLLs. Weave handles this with a modular crate system — **every Windows DLL is a separate Rust crate**, independently versioned and testable. Adding a function to `kernel32` does not require understanding `user32`:

```
weave-core/          # PE loader, syscall dispatcher, process management
weave-kernel32/      # File I/O, process/thread management, memory (~19K LoC, 450 exports)
weave-user32/        # Window management, input, messaging (~17K LoC, 329 exports)
weave-ntdll/         # NT layer primitives (~2.5K LoC)
weave-gdi32/         # 2D graphics via Cairo/Skia (~6K LoC, 128 exports)
weave-gdiplus/       # GDI+ API surface (~2.9K LoC, 181 exports)
weave-advapi32/      # Registry, security, crypto (~4K LoC)
weave-ws2_32/        # Winsock networking (~2.4K LoC, 48 exports)
weave-shell32/       # Shell integration, file dialogs (~3.5K LoC, 36 exports)
weave-comctl32/      # Common controls (~650 LoC, 36 exports)
weave-ole32/         # COM/OLE automation (~930 LoC)
weave-oleaut32/      # OLE automation extensions (~640 LoC)
weave-ucrt/          # Universal C runtime (~5.4K LoC, 139 exports)
weave-d3d12/         # DirectX 12 → Vulkan translation (~940 LoC)
weave-ddraw/         # DirectDraw (~2.1K LoC)
weave-mmdevapi/      # Audio → PipeWire (~1.2K LoC)
weave-shlwapi/       # Shell light-weight utilities (~820 LoC)
weave-vulkan/        # Vulkan passthrough (~3.3K LoC, 291 exports)
weave-winmm/         # Windows multimedia (~1K LoC)
weave-xinput/        # Game controller input (~560 LoC)
```

Eighteen additional smaller crates cover bcrypt, crypt32, imm32, secur32, setupapi, wldap32, normaliz, msvcp140, and others. Full crate list at [`weave-cli/src/lib.rs`](weave-cli/src/lib.rs).

### Graphics pipeline (target)

- **DirectX 9/10/11** — translate to Vulkan via DXVK
- **DirectX 12** — translate to Vulkan via VKD3D-Proton
- **OpenGL** — host OpenGL or Zink
- **Vulkan** — passthrough
- **GDI/GDI+** — Cairo/Skia for 2D rendering

All graphics paths target Vulkan as the common backend. Today, the only validated graphics path is the SDL software renderer for NXEngine-evo and SDL2 testsprite2; D3D9 via DXVK is proven in CI but not real-desktop-validated. Hardware-accelerated games are not yet validated.

### Plugin system (disabled)

Third-party `.so` plugins were intended to register custom API implementations at runtime. The loader is **currently disabled**: prefix-local `.so` loading from a user-writable directory was unsafe by design (it ran before the Landlock sandbox and would dlopen arbitrary native code without signature verification), and no plugins are shipped. The loader crate is preserved for a future signed-plugin model and is not wired up to any binary.

### Compatibility approach

Weave does **not** maintain a crowd-sourced "anything might work" compatibility database in the Wine AppDB sense. The model is the opposite: a small, hard, **named** supported-app list per release tier, with end-to-end CI gates that have to be green and not `#[ignore]`'d for an app to be on the list. The list grows as gates close.

---

## What Weave is not

- **Not a Windows VM.** The path is API translation, not virtualization. There is no VM fallback.
- **Not a Wine fork.** Weave is an independent implementation. No Wine code is used. Wine's reverse engineering informs *what* needs to be implemented; the implementation is new.
- **Not a drop-in Wine replacement.** Weave's wedge is small native Win32 apps that matter for a specific audience. Anything outside the supported-app list is not supported.
- **Not a general-purpose Windows emulator.** Weave does not run every Windows binary. It runs the binaries on its list, and anything else is out of scope until it's on the list.
- **Not cloud-dependent.** Everything runs locally. No internet required. No telemetry without explicit opt-in.

## Releases

Tagged releases (`v*`) publish a Linux x86-64 binary as `weave-x86_64` plus `weave-x86_64.sha256` on GitHub Releases. Weave runs x86-64 Windows PE code natively and does not ship an aarch64 Linux build. To cut a release: tag `vX.Y.Z` on `main` after CI is green; the release workflow builds with `--release` and attaches both files. Dry-run without creating a release: `gh workflow run release.yml`.

## Roadmap

For honest per-phase status (what's complete vs. code-exists vs. scaffolded vs. not started), see [`ROADMAP.md`](ROADMAP.md). The summary is: PE loader and minimal kernel32 / user32 / gdi32 plus sandboxing work end-to-end on a small corpus; DXVK/VKD3D, ARM64, GUI manager, install flow, real network clients, and hardware-accelerated games are open work.

---

## Development infrastructure — Wine symbolic compression

Weave is an independent reimplementation, but Wine's 30 years of reverse engineering is an invaluable reference for *what* the Windows API actually does — especially undocumented behaviors that real applications depend on. The challenge is that Wine's codebase is roughly 10 million lines of C across thousands of files. Reading it traditionally burns context windows and tokens at an unsustainable rate.

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

## Tech stack

- **Language:** Rust (core), with C FFI where needed for existing libraries (DXVK, VKD3D, Cairo)
- **Build:** Cargo workspace, 35 crates
- **Graphics:** Vulkan (via ash), DXVK (D3D9/10/11), VKD3D-Proton (D3D12)
- **Audio:** PipeWire (via pipewire-rs)
- **Windowing:** xcb (X11), Wayland
- **Sandbox:** Landlock (bubblewrap and seccomp are roadmap)
- **Cross-arch (planned):** FEX-Emu / Box64 for ARM64 → x86_64 translation
- **GUI (planned):** Tauri 2 (Rust + Svelte)
- **License:** MIT

---

## Related projects

- **[Warden](https://github.com/eldo9000/Warden)** — Open-source, cross-platform anti-cheat for game developers. Native Linux + Windows support. Designed to work with Weave for gaming use cases.
- **[LibreWin OS](https://github.com/eldo9000/LibreWin-OS)** — A polished Linux desktop aimed at Windows/macOS switchers. Weave is designed to be the Windows compatibility layer for LibreWin.

---

*Weave is free, open-source software under the MIT license.*
