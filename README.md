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
- The supported-app list is short and per-release-tier. The current end-to-end gates that are green in CI (not `#[ignore]`'d) are: **NXEngine-evo** (SDL2 game, software renderer), **SDL2 testsprite2** (rendering smoke), **Notepad++** (resource walk, editor roundtrip), **7-Zip** (extraction, GUI browse-for-folder), **IrfanView** (BMP/JPEG/PNG/GIF open, PNG save, folder navigation), and **Q-Dir** (launch, file-pane population). Apps not on the list are not supported. See the [E3-M1 release gate matrix](docs/milestones/E3-M1-release-gate-matrix.md) for the live list and known gaps.
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

### Symbolic indexing

MCP-based symbolic indexing parses Wine's source tree using AST analysis, indexes every function, struct, and symbol, and stores them locally. Instead of reading entire files, agents query by symbol name and retrieve just that function's source code.

**Impact:**

| Operation | Without indexing | With symbolic indexing |
|-----------|-----------------|----------------------|
| "Show me Wine's `CreateFileW`" | Read entire `kernel32/file.c` (~2000 lines, ~8000 tokens) | Return just the function (~80 lines, ~400 tokens) |
| Token reduction | — | ~95% per lookup |
| Full API surface scan | Read hundreds of files | Query the index |

Over the lifetime of Weave development — tens of thousands of Wine reference lookups — this turns Wine from "a codebase you have to read" into "a database you can query."

### The reference-based reimplementation loop

This is the core development cycle for every DLL function in Weave:

1. **Reference** — Query the symbolic index: "Show me Wine's `NtCreateFile`" → get the C implementation in ~400 tokens
2. **Understand** — Read the C implementation, identify the behavioral contract including undocumented side effects
3. **Rewrite** — Generate a Rust reimplementation using Weave's architecture, sandbox constraints, and modern Linux primitives
4. **Test** — Run against real Windows behavior (captured in test suites) to verify correctness
5. **Iterate** — If behavior diverges, query Wine's implementation for edge cases, adjust, retest

Steps 1–3 are heavily tool-assisted. Step 4 requires real Windows reference output (automated CI against a Windows VM). Step 5 is where human contributors add the most value — understanding *why* an edge case exists.

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

The symbolic index also provides initial function signatures derived from Microsoft's public documentation. Contributors review, extend, and validate these stubs with real-world testing.

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

## White paper — deep technical addendum

*The sections below expand on topics introduced above. They assume familiarity with the Win32 API surface and Linux systems programming. They are here for the reader who wants to understand not just what Weave does, but how and why.*

---

### Stability and debuggability — the short debug chain

A core claim of the architectural comparison above is that Weave's translation-shim model produces a fundamentally shorter debug chain than a boundary-OS model like Wine's. This section makes that concrete.

Consider a bug: a file-open call fails when it should succeed. In each system, the path from bug to root cause has a different length:

**Wine's debug chain** (illustrative):

```
Guest EXE → kernel32.CreateFileW → ntdll.NtCreateFile → wineserver RPC →
    wineserver fd management → Unix VFS path translation → 
    security descriptor evaluation → actual openat(2) syscall
```

The bug could live in any of six layers: the wineserver protocol, the file descriptor caching logic, the path translation, the security descriptor mapping, the Unix file permission handling, or the syscall itself. The developer must understand the full stack to rule each one out.

**Weave's debug chain**:

```
Guest EXE → kernel32.CreateFileW → openat(2) syscall
```

The function lives in a single file (`weave-kernel32/src/api.rs`), is typically 30–60 lines, and does exactly one thing: translate Win32 semantics to a Linux syscall. If it fails, either:

- The translation is subtly wrong (Win32 error code mapping, flag conversion, edge case in path handling), or
- The Linux call genuinely failed, in which case the OS error message is directly interpretable

This has practical consequences for the project:

- **Bisection is trivial.** A regression means one function changed its behavior, not an RPC handshake or a shared-memory protocol version mismatch.
- **No cascading state corruption.** Because every DLL runs in the same Rust process with Rust's ownership model, a bug in gdi32 cannot corrupt kernel32's handle table — they share no mutable state without explicit, typed interfaces.
- **No silent failures.** A Wine bugsquash often finds that a function "mostly works" but silently drops an error code or uses a wrong default, accumulating bad state over hours of runtime. Weave's functions are so narrow that a wrong parameter shows up immediately: the wrong `flags` argument to `openat` either works or doesn't, with no intermediate degraded state.

**The simpler surface is structural, not aspirational.** It falls out of the architecture: narrow functions calling stable host infrastructure through typed Rust interfaces, with no intermediate daemon, no shared-memory protocol, and no reimplemented subsystem to have bugs in.

---

### Shim lifecycle — how a function graduates from stub to implementation

Every Win32 export in Weave begins as a **Phase A stub** and progresses through defined stages. The [SHIM-CONTRACT](docs/SHIM-CONTRACT.md) codifies this. The lifecycle is worth understanding because it governs what "coverage" actually means.

**Phase A — stub (present in the resolver):**

The function is registered in the crate's `resolve()` match block and returns a sentinel value (typically 0, `FALSE`, `ERROR_CALL_NOT_IMPLEMENTED`, or a zero-initialized struct). It exists so the PE loader can resolve the IAT entry and the process can continue past calls to unimplemented APIs. If a target app never calls it, it stays here forever.

**Phase B — implemented (Wine-referenced, non-panic, milestone-gated):**

The function has:

1. A `// Wine ref:` comment citing a real jcodemunch lookup of Wine's implementation
2. A real function body — no `panic!()`, `unimplemented!()`, or `todo!()` as the sole logic
3. A named assertion in a milestone doc that exercises this function through a real application

At this point it counts as "implemented" in the coverage gauge. But it may still be incomplete in edge cases not triggered by the current milestone corpus.

**Phase C — hardened (multi-app, multi-platform):**

The function has been exercised by multiple target applications, across at least two Tier 1 milestone gates, and on real hardware (not just CI under Docker). Edge cases discovered in one app's use are fixed before the next app is added.

**Why the staging matters:**

The 1,661 registered exports with 75 fully implemented is not a sign of incompleteness — it is a deliberate strategy. Writing a correct Win32 implementation requires knowing what real apps actually do. Phase A stubs exist to unblock the PE loader and let the rest of the system work. They get promoted to Phase B only when a target app needs them, and to Phase C only when multiple apps have stressed the edges.

This is the opposite of "implement everything speculatively." The wedge model means: implement only what the target list needs, implement it well, and let the long tail stay stubbed until it matters.

---

### Sandbox threat model — what is and isn't contained

The sandbox section above summarizes the status table. This section explains the reasoning behind each layer and what the gaps mean in practice.

**Landlock filesystem isolation (shipped):**

Landlock is a Linux security module (LSM) that allows a process to restrict its own filesystem access after initialization, without elevated privileges. Weave applies a Landlock ruleset after the PE is loaded and the IAT is patched but before guest code executes. The ruleset allows access only to:

- The Weave prefix directory (where the app and its dependencies live)
- Explicitly bridged user-data directories (`~/Documents`, `~/Desktop`, etc.)
- System libraries and devices needed for runtime operation

Everything else — `.ssh`, `.config`, `.gnupg`, browser profiles, the entire home directory outside the bridged paths — is blocked at the kernel level. The guest process simply cannot open those paths. This is not advisory; it is enforced by the kernel on every `openat()`, `stat()`, and `execve()` syscall.

**Why Landlock and not something more expressive:**

Landlock is intentionally simple. It supports path-based allowlisting, not deny-listing, not network rules, not syscall filtering. This simplicity is a feature for Weave's use case: the ruleset is small enough to audit by hand (roughly 15–20 rules), and the kernel guarantees cannot be bypassed by guest code because they are applied before guest execution and cannot be dropped without privilege escalation.

**The seccomp gap (roadmap):**

Seccomp-BPF filters can restrict which syscalls a process may use and with what arguments. This would be valuable for containing the guest — for example, blocking `reboot()`, `kexec_load()`, or `bpf()` itself. But seccomp interacts poorly with Weave's current in-process model.

The problem: because the guest PE shares Weave's address space, any seccomp filter must allowlist every syscall that Weave's own runtime uses — `mmap()`, `write()`, `openat()`, `read()`, `close()`, `exit_group()`, `futex()`, `clock_gettime()`, and dozens more. The guest gets the same allowlist, which means the filter is effectively useless: every syscall the guest might abuse is also a syscall the host needs.

Real seccomp isolation requires an out-of-process model where the guest lives in a separate process with its own filter, and Weave communicates with it through a controlled RPC interface. That architecture is Phase 4+ on the roadmap. Until then, the trade-off is explicit: Landlock covers filesystem containment (the highest-value isolation), and everything else runs at Weave's privilege level.

**The network gap (roadmap):**

Per-app network isolation — binding the guest to a specific network namespace or restricting it to specific ports/protocols — is not implemented. Today, the guest has the same network access as the host process. This is acceptable for the current target apps (file managers, text editors, image viewers, archive tools) which do not make arbitrary network connections. It will need to be addressed before networked apps like PuTTY, Signal, or Obsidian are marked supported.

**Where the sandbox stands relative to Wine:**

Wine has no sandbox. A Windows application running under Wine has full access to the user's home directory, all open network sockets, and every syscall the Linux kernel allows the user's process to make. Any exploit in the Windows app is an exploit at the user's privilege level. Weave's Landlock layer eliminates the highest-value attack surface (filesystem access to user data) today, before any of the roadmap isolation layers are built. The sandbox is not complete, but it is already strictly stronger than Wine's default posture.

---

### Line-count projection methodology

The asymptotic projection (105K current → ~500K completionist) merits explanation. The numbers are not guesses — they come from a bottom-up model with explicit assumptions.

**Current state (measured):** 105,244 lines of Rust across 35 workspace crates. Measured by `find . -path ./target -prune -o -name '*.rs' -print | xargs wc -l`. No auto-generated code is present. The 105K number is raw implementation.

**Stub→impl conversion (45K–80K):** 1,661 registered exports across 26 DLL crates. Of those, 75 are fully implemented (Phase B+). The remaining ~1,500 stubs each need an average of 30–50 lines of real implementation (function body, error handling, Wine-referenced behavior). Some will be shorter (simple flag translations), some longer (complex window creation paths). At 30 lines average: 45K. At 50 lines: 75K.

**New DLL coverage (10K–20K):** The current 26 DLL crates cover the Tier-1 target apps. Adding D2D1, DWrite, DXGI beyond current scaffolding, deeper OLE32 paths, and audio infrastructure might require 5–10 new crates at roughly 2K lines each. Zero if the current crate set proves sufficient for the full Tier-1 list.

**Application depth (20K–40K):** Real desktop use exposes edge cases that CI gates don't. File dialogs need correct filter patterns. Print dialogs need CUPS integration. Drag-and-drop needs XDnD protocol handling. Clipboard needs the X11/Wayland selection protocol. These are not speculative features — they are required for real desktop use of the existing target apps. Each adds complexity to existing functions rather than new functions.

**Infrastructure (10K–15K):** Bubblewrap integration, seccomp profiles, the `weave` CLI, `.desktop` file generation, installer tooling. These support the application compatibility layer but are not themselves API shims.

**Summing the midpoints:**

| Component | Low | Mid | High |
|---|---|---|---|
| Current | 105K | 105K | 105K |
| Stub→impl | 45K | 60K | 80K |
| New DLLs | 0K | 10K | 20K |
| App depth | 20K | 30K | 40K |
| Infrastructure | 10K | 12K | 15K |
| **Total Rust** | **180K** | **~220K** | **260K** |
| With docs/tooling | ~280K | ~330K | ~380K |

The v1 ship estimate of 200–250K Rust (300K total) is the midpoint of stub→impl conversion plus app depth, with new DLLs and infrastructure partially realized. The stable asymptote of 350–450K assumes the full conversion plus all new DLLs and infrastructure. The completionist asymptote of ~500K assumes a long tail of rarely-called APIs that get written only because a target app somewhere needs them.

The projection holds as long as the wedge model holds — that is, as long as Weave does not attempt to become a general-purpose Windows compatibility layer. If the ambition widens to "run anything Wine runs," the curve changes entirely and the asymptote approaches Wine's magnitude. That is not the current design.

---

### Open problems

Honest engineering requires acknowledging what doesn't work yet. These are the known gaps that will require architectural work, not just additional stub implementations.

**The in-process model limits isolation.** As discussed in the sandbox section, seccomp is structurally incompatible with shared-address-space execution. The out-of-process redesign (Phase 4+) is the single largest open architectural problem. It affects not just seccomp but also crash isolation: today, a guest crash takes down the Weave process. An out-of-process model would let the host survive guest failures.

**Audio is scaffolded but untested against real output.** PipeWire bindings exist in `weave-mmdevapi` (~1.2K LoC). No target app has been validated producing audio output on real hardware. The decode pipeline (codec → PCM → PipeWire stream) may have buffer-latency or format-conversion issues that only real audio output will reveal.

**D3D10/11/12 are unevaluated.** D3D9 via DXVK is proven in CI. The same DXVK codebase supports D3D10 and D3D11, but no test or target app has exercised those paths in Weave. D3D12 via VKD3D-Proton is scaffolded but completely untested. The gap between "compiles and loads" and "renders a frame correctly" could be substantial.

**TLS and certificate validation are unproven.** Plain HTTP and SSH work. HTTPS connects at the TLS layer but certificate validation (chain building, revocation checking, root store mapping from Windows to Linux) has not been exercised end-to-end. This blocks Let's Encrypt–signed sites and any service that validates client certificates.

**The ARM64 story is deferred.** Weave targets x86-64 today. ARM64 support requires integrating FEX-Emu or Box64 for CPU translation, which is an integration project of its own. The architecture would support it — the translation-shim model is ISA-agnostic above the CPU boundary — but no work has been done.

---

*Weave is free, open-source software under the MIT license.*
