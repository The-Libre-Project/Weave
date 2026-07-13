# Weave: Architecture and Methodology

Canonical technical reference for the Weave project. The architectural thesis, the cost model, the runtime structure, the safety model, and the development methodology: the reasoning that does not change commit to commit.

---

## 1. The thesis: boundary OS versus translation shim

Weave and Wine solve the same problem (run Windows software on Linux) with opposite architectures. Understanding the difference is the whole point of the project.

Wine does not translate Windows calls into Linux calls. It reimplements the entire Windows subsystem stack in userspace on Linux: its own window manager, its own compositor, its own software blitter, its own audio mixer, its own shell, its own registry hive parser, its own OLE infrastructure, its own NT kernel object manager. Each of these is a full operating-system subsystem re-expressed in C. That is why Wine is roughly 12 million lines of code and carries the complexity surface of a 30-year-old OS kernel.

This was the correct design in 1993. Linux at the time had no Vulkan, no PipeWire, no Wayland compositor, no namespaces, no Landlock, and no container ecosystem. Wine had to build every Windows subsystem from scratch because there was nothing on the host side to delegate to. The host could not draw a hardware-accelerated triangle, mix audio streams, or sandbox a process, so Wine grew its own implementations of all three.

Those subsystems exist now. Weave delegates to them.

| Subsystem | Wine approach | Weave approach | Consequence |
|---|---|---|---|
| Graphics | Own `winex11` window manager, software blitter, OpenGL wrappers | Delegate to DXVK/VKD3D, which speak Vulkan directly on the host | No reimplemented compositor; Vulkan drivers already exist on Linux |
| Windowing | `winex11` owns `CreateWindow`, `DispatchMessage`, Z-order, focus, clipping, regions, every pixel of the non-client area | Map `CreateWindowEx` to xcb; let the host compositor own the window tree | ~1.5M lines of Wine window management replaced by ~17K lines of xcb bridge |
| Audio | Own ALSA/OSS/PulseAudio driver stack with per-app mixer, position APIs, format conversion, resampling | Map `PlaySound`, `waveOut*` to PipeWire streams | ~400K lines of audio drivers replaced by ~1.2K lines of PipeWire bridge |
| Shell | Full `explorer.exe` reimplementation: taskbar, tray, desktop icons, start menu, file manager | None; the app runs in the host desktop, and the host shell is the shell | ~800K lines of shell code that do not exist in Weave |
| NT kernel | Own `ntoskrnl`: memory manager, object manager, I/O manager, process manager, configuration manager, security reference monitor, LPC | ntdll shim for the handful of NT syscalls real apps reach through the DLL boundary | ~600K lines trimmed to ~2.5K |

Wine is a **boundary OS**: it inserts a complete Windows operating-system boundary between the guest binary and the host kernel. Weave is a **translation shim**: it converts Windows calling conventions and data structures into native Linux syscalls and host libraries, and lets the host do the heavy lifting. Weave is the adapter, not the operating system.

This is not a value judgment about Wine. Wine's approach was right for its era and remains the most complete compatibility layer in existence. Weave is a bet that the era changed.

## 2. The cost model

The architectural leverage of delegation has a direct, measurable consequence: Weave can cover a comparable application surface at roughly 2 to 4 percent of Wine's code volume. This section explains the projection so it can be checked rather than trusted.

### 2.1 The shape of the curve

Growth is logistic, not linear. There are three regimes:

1. **Linear fill (now).** The PE loader and resolver already exist, with most Win32 exports present as stubs. Growth right now is the conversion of stubs into real implementations along the critical path of the supported apps. This is the steep part of the curve.
2. **Deceleration.** Each new target application requires fewer genuinely new APIs, because the high-frequency core (file I/O, memory, window creation, messaging, GDI) is shared across nearly all apps. The second image viewer needs far less new code than the first.
3. **Long tail.** A large set of rarely-called exports never get implemented at all, because no target app calls them. They stay as stubs forever. This is the asymptote.

<svg viewBox="0 0 640 400" style="width:100%;max-width:640px;height:auto;display:block;margin:24px auto;font-family:'Geist',monospace;font-size:11px;" xmlns="http://www.w3.org/2000/svg">
  <style>
    .chart-line { stroke: var(--ca-accent); stroke-width: 2.5; fill: none; stroke-linecap: round; }
    .chart-grid { stroke: var(--ca-border); stroke-width: 1; }
    .chart-label { fill: var(--ca-text-muted); }
    .chart-milestone { fill: var(--ca-text-heading); font-weight: 600; }
    .chart-asymptote { stroke: var(--ca-text-faint); stroke-width: 1; stroke-dasharray: 4 4; }
    .chart-asymptote-label { fill: var(--ca-text-faint); }
    .chart-axis { stroke: var(--ca-text-faint); stroke-width: 1.5; }
    .chart-tick { fill: var(--ca-text-faint); }
  </style>
  <line x1="60" y1="30" x2="60" y2="350" class="chart-axis" />
  <text x="55" y="35" text-anchor="end" class="chart-tick">LoC</text>
  <text x="55" y="55" text-anchor="end" class="chart-label">500K</text>
  <line x1="62" y1="62" x2="630" y2="62" class="chart-asymptote" />
  <text x="635" y="65" class="chart-asymptote-label">completionist asymptote</text>
  <text x="55" y="115" text-anchor="end" class="chart-label">400K</text>
  <text x="55" y="195" text-anchor="end" class="chart-label">300K</text>
  <text x="55" y="275" text-anchor="end" class="chart-label">200K</text>
  <text x="55" y="340" text-anchor="end" class="chart-label">100K</text>
  <line x1="62" y1="110" x2="630" y2="110" class="chart-grid" />
  <line x1="62" y1="190" x2="630" y2="190" class="chart-grid" />
  <line x1="62" y1="270" x2="630" y2="270" class="chart-grid" />
  <line x1="62" y1="335" x2="630" y2="335" class="chart-grid" />
  <line x1="60" y1="350" x2="630" y2="350" class="chart-axis" />
  <text x="630" y="370" text-anchor="end" class="chart-tick">Time</text>
  <text x="100" y="370" text-anchor="middle" class="chart-label">Era 2</text>
  <text x="255" y="370" text-anchor="middle" class="chart-label">v1 ship</text>
  <text x="430" y="370" text-anchor="middle" class="chart-label">mature</text>
  <text x="570" y="370" text-anchor="middle" class="chart-label">long tail</text>
  <line x1="62" y1="62" x2="630" y2="62" class="chart-asymptote" />
  <path d="M 60,338 C 100,338 140,338 170,335 C 200,330 230,318 260,290 C 290,260 320,225 360,200 C 400,178 450,165 510,158 C 560,153 600,150 630,148" class="chart-line" />
  <circle cx="170" cy="335" r="4" fill="var(--ca-accent)" />
  <text x="170" y="325" text-anchor="middle" class="chart-milestone" style="font-size:10px;">current</text>
  <circle cx="260" cy="290" r="4" fill="var(--ca-accent)" />
  <text x="260" y="280" text-anchor="middle" class="chart-milestone" style="font-size:10px;">v1 ship</text>
  <circle cx="430" cy="170" r="4" fill="var(--ca-accent)" />
  <text x="430" y="162" text-anchor="middle" class="chart-milestone" style="font-size:10px;">stable asymptote</text>
</svg>

### 2.2 Bottom-up projection

The numbers come from a component model, not a guess. The current measured figure is the anchor; see the README for the live count.

| Component | Basis | Low | Mid | High |
|---|---|---|---|---|
| Current | Measured Rust LoC across the workspace | 105K | 105K | 105K |
| Stub to implementation | ~1,500 remaining stubs at 30 to 50 lines of real body each | 45K | 60K | 80K |
| New DLL coverage | 5 to 10 new crates (D2D1, DWrite, deeper OLE32, audio) at ~2K each, or zero if the current set suffices | 0K | 10K | 20K |
| Application depth | Real-desktop edge cases (file dialog filters, print/CUPS, drag-and-drop, clipboard) added to existing functions | 20K | 30K | 40K |
| Infrastructure | IPC system, seccomp profiles, CLI, `.desktop` generation, installer | 12K | 15K | 18K |
| **Total Rust** | | **182K** | **~222K** | **263K** |
| With docs and tooling | | ~282K | ~332K | ~383K |

The three reference points on the curve:

- **v1 ship** (10 Tier-1 apps, real-desktop-validated): ~200 to 250K Rust, the midpoint of stub conversion plus application depth.
- **Stable asymptote** (mature stubs, high-value corpus): ~350 to 450K Rust, full conversion plus all new DLLs and infrastructure.
- **Completionist asymptote** (obscure one-off APIs): ~500K Rust, still under 5 percent of Wine's 12M lines.

### 2.3 The load-bearing assumption

The projection holds only as long as the wedge model holds: Weave does not attempt to become a general-purpose Windows compatibility layer. The wedge is narrow by design, which is **the apps that matter for a specific audience, implemented well, sandboxed by default, in a fraction of the code.** Expanding the wedge is a conscious decision per target app, not a background promise.

If the ambition widens to "run anything Wine runs," the curve changes entirely and the asymptote approaches Wine's magnitude. Weave will never support everything Wine supports, and that limitation is what keeps the code small.

## 3. Runtime architecture

Weave's runtime has two layers, both always active.

### 3.1 Weave Native: API translation

Rust code maps Windows system calls to Linux equivalents. File operations route through a virtual prefix. Graphics target Vulkan (via DXVK and VKD3D where those paths are wired up). Audio targets PipeWire. Windowing maps to xcb on X11 and to Wayland. The translation is direct: a Win32 function does its small amount of semantic adaptation and then calls stable host infrastructure.

### 3.2 Weave Sandbox: isolation

| Layer | Status |
|---|---|
| Filesystem | Implemented. Landlock restricts the guest to its prefix plus bridged user-data directories. Requires Linux 5.13+; skipped with a diagnostic on older kernels. |
| Process isolation | Implemented. Out-of-process fork model (E4 arc, shipped 2026-06-30). The guest runs in a forked child process; Win32 API calls are proxied to the host via IPC over Unix domain sockets. |
| Syscalls | Implemented. seccomp-BPF filter with an 18-syscall allowlist applied in the child process before guest code executes. Per-app syscall additions registered in a manifest. |
| Network | Roadmap. Per-app network isolation; the guest currently uses the host network stack. |
| No root required | Implemented. Weave never needs elevated privileges. |

The Landlock layer is on by default and is not optional. Users may adjust the path allowlist, but the safe default requires no configuration. If an app on the supported list does not work, the correct response is to fix the underlying gap, not to hide it behind a fallback runtime. There is no VM fallback.

### 3.3 The modular DLL system

The Windows API surface is thousands of functions across hundreds of DLLs. Weave handles this with one principle: **every Windows DLL is a separate Rust crate**, independently versioned and testable. Adding a function to `kernel32` does not require understanding `user32`. The crates share no mutable state except through explicit, typed interfaces, which is what makes the next two properties (Section 4) possible.

### 3.4 The graphics pipeline (target)

All graphics paths target Vulkan as the common backend:

- DirectX 9/10/11 translate to Vulkan via DXVK.
- DirectX 12 translates to Vulkan via VKD3D-Proton.
- OpenGL uses host OpenGL or Zink.
- Vulkan is passthrough.
- GDI and GDI+ render through Cairo/Skia for 2D.

GDI rendering (2D graphics, image display, text rendering) is validated on real desktop hardware (GNOME Wayland, AMD RX 6700 XT). D3D9 via DXVK is proven in CI but not yet validated on real hardware; hardware-accelerated games remain unvalidated on bare metal. See the ROADMAP for live status.

## 4. Debuggability: the short debug chain

A central claim of the translation-shim model is that it produces a fundamentally shorter path from bug to root cause than a boundary-OS model. This is concrete, not aspirational.

Consider a file-open call that fails when it should succeed.

**Wine's debug chain** (illustrative):

```
Guest EXE → kernel32.CreateFileW → ntdll.NtCreateFile → wineserver RPC →
    wineserver fd management → Unix VFS path translation →
    security descriptor evaluation → openat(2)
```

The bug could live in any of six layers: the wineserver protocol, the fd caching logic, path translation, security descriptor mapping, Unix permission handling, or the syscall. Ruling each one out requires understanding the full stack.

**Weave's debug chain**:

```
Guest EXE → kernel32.CreateFileW → openat(2)
```

The function lives in a single file, is typically 30 to 60 lines, and does one thing: translate Win32 semantics to a Linux syscall. If it fails, either the translation is subtly wrong (error-code mapping, flag conversion, a path edge case) or the Linux call genuinely failed and the OS error is directly interpretable.

The practical consequences:

- **Bisection is trivial.** A regression means one function changed behavior, not an RPC handshake or a shared-memory protocol version mismatch.
- **No cascading state corruption.** Every DLL crate is an independent module under Rust's ownership model. A bug in `gdi32` cannot corrupt `kernel32`'s handle table. They share no mutable state without an explicit typed interface. Under the out-of-process model (Section 3.2), the guest process boundary adds a further guarantee: guest memory corruption cannot reach host state at all.
- **No silent degradation.** A narrow function with a wrong flag either works or fails immediately. There is no intermediate degraded state accumulating over hours of runtime.

This simpler surface is structural. It falls out of the architecture: narrow functions calling stable host infrastructure through typed interfaces, with no intermediate daemon, no shared-memory protocol, and no reimplemented subsystem to have bugs in.

## 5. The shim lifecycle: what "coverage" means

Every Win32 export in Weave begins as a stub and graduates through defined stages. The [SHIM-CONTRACT.md](../SHIM-CONTRACT.md) codifies this. The staging is the reason a count like "1,661 registered exports, a fraction fully implemented" is a strategy rather than a measure of incompleteness.

**Phase A, stub (present in the resolver).** The function is registered in its crate's `resolve()` match block and returns a sentinel (0, `FALSE`, `ERROR_CALL_NOT_IMPLEMENTED`, or a zero-initialized struct). It exists so the PE loader can resolve the IAT entry and the process can continue past calls to unimplemented APIs. If no target app ever calls it, it stays here forever, costing almost nothing.

**Phase B, implemented (Wine-referenced, non-panic, milestone-gated).** The function has a `// Wine ref:` comment citing a real lookup of Wine's behavior, a real body with no `panic!`/`unimplemented!`/`todo!` as its sole logic, and a named assertion in a milestone doc that exercises it through a real application. At this point it counts as implemented, though edge cases outside the current corpus may remain.

**Phase C, hardened (multi-app, multi-platform).** The function has been exercised by multiple target apps, across at least two Tier-1 milestone gates, and on real hardware rather than only CI under Docker. Edge cases found in one app are fixed before the next app is added.

The discipline this encodes is the inverse of speculative implementation. Writing a correct Win32 function requires knowing what real apps actually do with it. Stubs unblock the loader; they get promoted only when a target app needs them, and hardened only when several apps have stressed the edges. Implement what the target list needs, implement it well, and leave the long tail stubbed until it matters.

## 6. The sandbox threat model

Section 3.2 gives the status table. This section explains the reasoning and the gaps.

### 6.1 Landlock filesystem isolation (shipped)

Landlock is a Linux security module that lets a process restrict its own filesystem access after initialization, without privileges. Weave applies a ruleset after the PE is loaded and the IAT is patched, but before guest code executes. The ruleset allows access only to the Weave prefix, explicitly bridged user-data directories (`~/Documents`, `~/Desktop`, and similar), and the system libraries and devices needed at runtime.

Everything else (`.ssh`, `.config`, `.gnupg`, browser profiles, the rest of the home directory) is blocked at the kernel level. The guest cannot open those paths. This is enforced on every `openat`, `stat`, and `execve`, not advised.

Landlock is intentionally simple: path-based allowlisting, no deny rules, no network rules, no syscall filtering. That simplicity is a feature here. The ruleset is small enough to audit by hand (roughly 15 to 20 rules), and the guarantee cannot be dropped by guest code because it is applied before guest execution and cannot be relaxed without privilege escalation.

### 6.2 Out-of-process sandbox (shipped)

The E4 arc (shipped 2026-06-30) replaces the original in-process execution model with a fork-based architecture. After the PE is loaded and the IAT is patched, Weave forks. The child process applies a seccomp-BPF filter with an 18-syscall allowlist, receives a DRM render-node file descriptor from the host via SCM_RIGHTS, and jumps to the PE entry point. The parent runs the host loop: it reads IPC call messages from the child over a Unix domain socket, dispatches them to the real Win32 API implementations, and sends the result back. The child never calls a real Win32 function directly — every IAT entry points to an IPC stub that serialises the call into a length-prefixed JSON message.

This is the **default execution path**. `--no-sandbox` exists for debugging and profiling but is not for production use.

The seccomp allowlist permits only the syscalls the guest needs to run: read, write, close, mmap, mprotect, munmap, brk, rt_sigaction, rt_sigprocmask, sigreturn, getpid, exit, gettid, futex, restart_syscall, clock_gettime, exit_group, and openat. Every other syscall — `reboot`, `kexec_load`, `bpf`, `ptrace`, `mount` — kills the child with SIGSYS. Per-app additions to the allowlist are registered in a manifest; new target apps are audited before additions are made.

Landlock filesystem isolation is applied in both processes after the fork (the host already had it). The combined isolation model is: Landlock restricts filesystem access by path, seccomp restricts the syscall surface by number, and the process boundary prevents guest memory corruption from reaching host state.

### 6.3 The network gap (roadmap)

Per-app network isolation is not implemented. The guest currently has the same network access as the host process. This is acceptable for the current target apps (file managers, text editors, image viewers, archive tools), which do not make arbitrary network connections. It must be addressed before networked apps such as PuTTY, Signal, or Obsidian are marked supported.

### 6.4 Position relative to Wine

Wine has no sandbox. A Windows app under Wine has full access to the user's home directory, all open sockets, and every syscall the kernel allows the user. Any exploit in the Windows app is an exploit at the user's privilege level. Weave's default execution path applies Landlock filesystem isolation, seccomp-BPF syscall filtering, and process-boundary isolation on every guest process. The sandbox is not complete (Section 6.3), but it is already structurally stronger than Wine's default posture by three independent mechanisms.

### 6.5 What Rust buys and what it does not

Rust eliminates whole categories of memory-safety bugs that have lived in Wine's C codebase for decades. But Rust alone does not make Win32 compatibility safe. A Win32 host necessarily handles guest-controlled pointers and FFI across a trust boundary; the unsafe surface is structural, not incidental. The real safety claim is composite: **Rust plus strict pointer validation plus sandboxing reduces the blast radius of an exploited bug.** Even when something goes wrong in the host, the guest cannot reach user data, the network, or the system without explicit permission. Sandboxing is the load-bearing piece. Rust is the multiplier. Neither alone is the claim.

## 7. Development methodology

### 7.1 Reference-first methodology

APIs are not copyrightable (*Oracle v. Google*, 2021). Reimplementing Win32 function signatures, parameters, return values, and error codes is legal regardless of how they were learned. Weave is GPL-3.0; Wine is LGPL; the licenses are compatible. Reading Wine and ReactOS as behavioral references is allowed. Copying their code is not, and is unnecessary, since the references are C and Weave is Rust.

The one hard rule: **never access proprietary Windows source**, meaning leaked source, decompiled binaries, or disassembled binaries. The reference hierarchy is MSDN first, then Wine and ReactOS for behavior (especially undocumented edges), then black-box observation on a licensed Windows VM when both are ambiguous. The full policy is in [REFERENCE-FIRST.md](REFERENCE-FIRST.md).

### 7.2 Symbolic compression of the reference corpus

Wine's value to Weave is its 30 years of reverse engineering: it documents what every Win32 function actually does, including the undocumented behaviors real apps depend on. The obstacle is volume. Wine is roughly 12 million lines of C across thousands of files. Reading it conventionally burns context and tokens at an unsustainable rate.

Weave uses MCP-based symbolic indexing that parses the reference trees with AST analysis and indexes every function, struct, and symbol into a queryable local database. Instead of reading a whole file, a developer or agent queries by symbol name and retrieves just that function.

| Operation | Without indexing | With symbolic indexing |
|---|---|---|
| Look up Wine's `CreateFileW` | Read `kernel32/file.c` (~2000 lines, ~8000 tokens) | Return the function (~80 lines, ~400 tokens) |
| Reduction per lookup | n/a | ~95% |
| Full API-surface scan | Read hundreds of files | Query the index |

Across the lifetime of the project (tens of thousands of reference lookups), this turns Wine from a codebase you read into a database you query. Six reference trees are indexed: Wine (Win32 behavior), ReactOS (NT internals), DXVK and VKD3D-Proton (DirectX translation), and Samba (Windows networking protocols).

### 7.3 The reference-based reimplementation loop

The core development cycle for every DLL function:

1. **Reference.** Query the index for the reference implementation (~400 tokens), and read MSDN for the official spec.
2. **Understand.** Identify the behavioral contract, including undocumented side effects.
3. **Rewrite.** Write original Rust using Weave's architecture, sandbox constraints, and Linux primitives.
4. **Test.** Run against real Windows behavior captured in test suites.
5. **Iterate.** Where behavior diverges, query the reference for edge cases, adjust, retest.

Steps 1 through 3 are heavily tool-assisted. Step 4 requires real Windows reference output (automated CI against a Windows VM). Step 5 is where human judgment adds the most value: understanding *why* an edge case exists.

### 7.4 The compatibility model

Weave does not maintain a crowd-sourced "anything might work" database in the Wine AppDB sense. The model is the opposite: a small, hard, **named** supported-app list per release tier, with end-to-end CI gates that must be green and not `#[ignore]`'d for an app to be on the list. The list grows only as gates close. An app is supported or it is not; there is no probabilistic middle.

## 8. Open problems

Honest engineering names what does not work yet. These require architectural work, not just more stubs.

**The in-process model (resolved).** The out-of-process redesign (E4 arc, shipped 2026-06-30) closed this. Guest isolation is now delivered through fork + seccomp-BPF + IPC proxy (Section 6.2). A guest crash kills the child process; the host survives. The remaining work in this area is per-app syscall audit (expanding the allowlist for new target apps) and per-app network isolation (Section 6.3).

**Audio is scaffolded but unproven.** PipeWire bindings exist, but no target app has been validated producing audio on real hardware. The decode pipeline (codec to PCM to PipeWire stream) may have latency or format-conversion issues that only real output will reveal.

**D3D10/11/12 are unevaluated.** D3D9 via DXVK is proven in CI. The same DXVK codebase supports D3D10 and D3D11, but no test or target app has exercised those paths in Weave. D3D12 via VKD3D-Proton is scaffolded and untested. The gap between "compiles and loads" and "renders a frame correctly" may be substantial.

**TLS and certificate validation are unproven.** Plain HTTP and SSH work. HTTPS connects at the TLS layer, but certificate validation (chain building, revocation, mapping the Windows root store to Linux) has not been exercised end to end.

**The ARM64 story is deferred.** Weave targets x86-64 today. ARM64 requires integrating FEX-Emu or Box64 for CPU translation, an integration project of its own. The architecture supports it (the translation-shim model is ISA-agnostic above the CPU boundary), but no work has been done.

## 9. Summary

Weave is a bet that the right way to run Windows software on Linux in this decade is to translate, not to reimplement. The host now provides the subsystems Wine once had to build, so Weave delegates to them and stays small: a translation shim instead of a boundary OS, narrow functions over stable infrastructure, sandboxed by default, in a fraction of the code. The cost of that smallness is a deliberately narrow wedge. The benefit is a codebase that is memory-safe, auditable, debuggable through a one-hop call chain, and maintainable by a small team. That trade is the entire design.

*Weave is free software licensed under the GNU General Public License v3 (GPL-3.0). Built by IronTree Software as the founding asset of the Libre Commons.*
