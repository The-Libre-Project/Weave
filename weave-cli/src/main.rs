use clap::Parser;
use std::path::PathBuf;
use weave_core::{cfg, cmdline, dll_registry, exec, iat, loader, prefix, registry, seh, teb};

mod arch;

/// Weave — run Windows executables on Linux.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the Windows .exe file to run
    exe: PathBuf,

    /// Weave prefix directory (virtual Windows root). Defaults to ~/.weave/default
    #[arg(long)]
    prefix: Option<PathBuf>,

    /// Disable the filesystem sandbox (for debugging only)
    #[arg(long)]
    no_sandbox: bool,

    /// Force ReactOS VM fallback mode, bypassing native API translation
    #[arg(long)]
    force_vm: bool,

    /// Arguments to pass to the Windows executable (e.g. `weave app.exe arg1 arg2`)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    exe_args: Vec<String>,
}

/// Resolve a Windows import to a function address.
///
/// Checks Weave's built-in stub crates first, then falls back to any
/// PE DLLs pre-loaded from the prefix (e.g. DXVK).
fn resolve(dll: &str, func: &str) -> Option<usize> {
    weave_plugin_system::lookup(dll, func)
        .or_else(|| weave_ntdll::resolve(dll, func))
        .or_else(|| weave_kernel32::resolve(dll, func))
        .or_else(|| weave_advapi32::resolve(dll, func))
        .or_else(|| weave_user32::resolve(dll, func))
        .or_else(|| weave_gdi32::resolve(dll, func))
        // msimg32.dll — alpha-blending, transparent blit (Sprint 5 IrfanView)
        .or_else(|| weave_gdi32::resolve_msimg32(dll, func))
        .or_else(|| weave_shell32::resolve(dll, func))
        .or_else(|| weave_ole32::resolve(dll, func))
        .or_else(|| weave_mmdevapi::resolve(dll, func))
        .or_else(|| weave_xinput::resolve(dll, func))
        .or_else(|| weave_winmm::resolve(dll, func))
        .or_else(|| weave_ucrt::resolve(dll, func))
        .or_else(|| weave_vulkan::resolve(dll, func))
        .or_else(|| weave_ws2::resolve(dll, func))
        .or_else(|| weave_comctl32::resolve(dll, func))
        .or_else(|| weave_oleaut32::resolve(dll, func))
        .or_else(|| weave_imm32::resolve(dll, func))
        .or_else(|| weave_shlwapi::resolve(dll, func))
        // gdiplus.dll — GDI+ 2D graphics / image codecs (Sprint 5 IrfanView)
        .or_else(|| weave_gdiplus::resolve(dll, func))
        // version.dll — file version info (Sprint 5 IrfanView)
        .or_else(|| weave_kernel32::resolve_version(dll, func))
        .or_else(|| dll_registry::lookup(dll, func))
}

fn main() {
    let args = Args::parse();

    // ── −1. Architecture compatibility ────────────────────────────────────
    if let Err(code) = arch::check_arch_compatibility(&args.exe) {
        std::process::exit(code);
    }

    // ── 0. Initialise the prefix ──────────────────────────────────────────
    // Set the Windows command line before IAT patching so that
    // GetCommandLineA/W and _acmdln/_wcmdln return the real argv.
    {
        let exe_name = args
            .exe
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("app.exe");
        // Convert absolute Linux paths in exe_args to Windows Z:\ paths so
        // that Windows apps receive paths they can round-trip through
        // GetFullPathNameW / CreateFileW.  Without this, a Linux path like
        // /weave/foo/bar.txt is treated as relative by GetFullPathNameW (it
        // doesn't start with a drive letter or backslash) and gets the CWD
        // prepended, doubling the path prefix.
        let windows_args: Vec<String> = args
            .exe_args
            .iter()
            .map(|arg| {
                if arg.starts_with('/') {
                    // Canonicalize to resolve any .. components, then map to Z:\
                    let canonical = std::path::Path::new(arg)
                        .canonicalize()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| arg.clone());
                    format!("Z:{}", canonical.replace('/', "\\"))
                } else {
                    arg.clone()
                }
            })
            .collect();
        cmdline::set(exe_name, &windows_args);
    }

    // Store the exe path as a Windows path (Z:\...) so GetModuleFileNameW(NULL)
    // can return the real location, letting apps like Notepad++ find their
    // plugins folder relative to the executable.
    {
        let abs = args.exe.canonicalize().unwrap_or_else(|_| args.exe.clone());
        let win_path = format!("Z:{}", abs.to_string_lossy().replace('/', "\\"));
        weave_core::exe_path::set(&win_path);
    }

    if let Some(p) = args.prefix {
        prefix::set(p);
    }
    prefix::ensure_dirs();
    weave_plugin_system::load_plugins(&weave_core::prefix::plugins_dir());
    registry::populate();

    // ── 1. Pre-load DLLs from the prefix ──────────────────────────────────
    // DLLs are loaded in dependency order so that each DLL's IAT can be
    // patched using exports from DLLs already registered.
    //
    // DXVK layout (user installs from a DXVK release into the prefix):
    //   {prefix}/drive_c/Windows/System32/{d3d9,d3d10core,d3d11,dxgi}.dll
    //
    // Any DLL not present is silently skipped — apps that don't use DirectX
    // continue to work unchanged.
    let system32 = prefix::system32();
    // dxgi must load before d3d10core / d3d11 (they import from it).
    let preload_dlls = ["dxgi.dll", "d3d9.dll", "d3d10core.dll", "d3d11.dll"];
    for dll_name in &preload_dlls {
        let path = system32.join(dll_name);
        let dll_bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue, // not installed — skip silently
        };
        match loader::load_dll(&dll_bytes) {
            Ok((image, exports)) => {
                // Patch the DLL's own IAT using our resolver (which by now
                // includes any DLLs registered in earlier iterations).
                unsafe {
                    iat::patch_best_effort(&dll_bytes, image.base, resolve, |d, f, va| {
                        eprintln!(
                            "weave: {dll_name}: unresolved import {d}!{f} at iat={va:#x} (skipped)"
                        );
                    });
                }
                dll_registry::register(dll_name.to_lowercase(), image, exports);
                eprintln!("weave: pre-loaded {dll_name}");
            }
            Err(e) => eprintln!("weave: warning: could not load {dll_name}: {e}"),
        }
    }

    // ── 1.5. VM fallback dispatch ─────────────────────────────────────────
    // Check before loading the PE — if we're going into the VM, we don't
    // need to map the binary into this process at all.
    if weave_vm_fallback::should_use_vm_fallback(&args.exe, args.force_vm) {
        let exit_code = weave_vm_fallback::execute_in_vm(&args.exe, &[]).unwrap_or_else(|e| {
            eprintln!("weave: VM fallback failed: {e}");
            std::process::exit(1);
        });
        std::process::exit(exit_code);
    }

    let bytes = std::fs::read(&args.exe).unwrap_or_else(|e| {
        eprintln!("weave: error reading {}: {e}", args.exe.display());
        std::process::exit(1);
    });

    // ── 2. Load sections into memory ──────────────────────────────────────
    let image = loader::load(&bytes).unwrap_or_else(|e| {
        eprintln!("weave: load failed: {e}");
        std::process::exit(1);
    });

    eprintln!(
        "weave: loaded {} at {:#x} (entry {:#x})",
        args.exe.display(),
        image.base as usize,
        image.entry_point as usize,
    );

    // ── 3. Patch the Import Address Table ────────────────────────────────
    // Use best-effort patching: unresolved imports are filled with a stub
    // that returns 0 and logs the miss.  This lets the binary start even when
    // some stub crates are incomplete, and surfaces all missing imports at
    // once rather than one per run.
    //
    // Safety: image.base points to a fully mapped PE loaded by loader::load().
    let mut missing: Vec<String> = Vec::new();
    unsafe {
        iat::patch_best_effort(&bytes, image.base, resolve, |dll, func, iat_va| {
            let sym = format!("{dll}!{func}");
            eprintln!("weave: unresolved import: {sym} at iat={iat_va:#x} (stubbed to null)");
            missing.push(sym);
        });
    }
    if !missing.is_empty() {
        eprintln!(
            "weave: warning: {} import(s) unresolved — binary may crash if they are called",
            missing.len()
        );
    }

    eprintln!("weave: imports resolved");

    // ── 4. Apply filesystem sandbox ───────────────────────────────────────
    // Allowlist the exe's own directory for read-only access so apps can open
    // config files, data files, and DLLs that live beside the executable.
    // All other filesystem paths remain denied by default.
    let exe_abs = args.exe.canonicalize().unwrap_or_else(|_| args.exe.clone());
    let exe_dir = exe_abs
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    weave_sandbox::apply(!args.no_sandbox, &[exe_dir]);

    // ── 5. Initialise TEB / PEB / TLS ────────────────────────────────────
    let _teb = teb::setup(&image).unwrap_or_else(|e| {
        eprintln!("weave: TEB setup failed: {e}");
        std::process::exit(1);
    });

    // ── 6. Install exception handlers ─────────────────────────────────────
    seh::install(&image);

    // ── 6.5. Patch CFG dispatch stubs ─────────────────────────────────────
    // Windows PEs compiled with CFG encode indirect call targets using the
    // security cookie. Weave provides a decode-and-call stub so the encoded
    // pointer in RAX is decoded before jumping, instead of crashing on a
    // non-canonical garbage address.
    cfg::setup(&bytes, image.base);

    // ── 6.6. Register runtime resolver ─────────────────────────────────
    // LoadLibraryExW / GetProcAddress stubs call back into this resolver
    // at runtime. Must be set before the PE entry point runs.
    weave_core::resolve::set(resolve);

    eprintln!("weave: TEB ready — jumping in");

    // ── DEBUG: print first 16 bytes at entry point and GS base ───────────
    #[cfg(target_os = "linux")]
    {
        let ep = image.entry_point;
        let bytes_at_ep: Vec<u8> = (0..16).map(|i| unsafe { *ep.add(i) }).collect();
        eprintln!("weave: entry bytes: {:02x?}", bytes_at_ep);
        let mut gs_base: u64 = 0;
        unsafe {
            libc::syscall(libc::SYS_arch_prctl, 0x1004i64, &mut gs_base as *mut u64);
        }
        eprintln!("weave: GS base = {gs_base:#x}");
    }

    // ── 7. Jump to the entry point ────────────────────────────────────────
    // Safety: image.entry_point is a valid executable address set up by loader::load().
    unsafe { exec::run(image.entry_point) }
}
