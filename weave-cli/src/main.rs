use clap::Parser;
use std::path::PathBuf;
use weave_core::{dll_registry, exec, iat, loader, prefix, registry, seh, teb};

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
}

/// Resolve a Windows import to a function address.
///
/// Checks Weave's built-in stub crates first, then falls back to any
/// PE DLLs pre-loaded from the prefix (e.g. DXVK).
fn resolve(dll: &str, func: &str) -> Option<usize> {
    weave_ntdll::resolve(dll, func)
        .or_else(|| weave_kernel32::resolve(dll, func))
        .or_else(|| weave_advapi32::resolve(dll, func))
        .or_else(|| weave_user32::resolve(dll, func))
        .or_else(|| weave_gdi32::resolve(dll, func))
        .or_else(|| weave_shell32::resolve(dll, func))
        .or_else(|| weave_ole32::resolve(dll, func))
        .or_else(|| weave_vulkan::resolve(dll, func))
        .or_else(|| dll_registry::lookup(dll, func))
}

fn main() {
    let args = Args::parse();

    // ── 0. Initialise the prefix ──────────────────────────────────────────
    if let Some(p) = args.prefix {
        prefix::set(p);
    }
    prefix::ensure_dirs();
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
                    iat::patch_best_effort(&dll_bytes, image.base, resolve, |d, f| {
                        eprintln!("weave: {dll_name}: unresolved import {d}!{f} (skipped)");
                    });
                }
                dll_registry::register(dll_name.to_lowercase(), image, exports);
                eprintln!("weave: pre-loaded {dll_name}");
            }
            Err(e) => eprintln!("weave: warning: could not load {dll_name}: {e}"),
        }
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
    // Safety: image.base points to a fully mapped PE loaded by loader::load().
    unsafe { iat::patch(&bytes, image.base, resolve) }.unwrap_or_else(|e| {
        eprintln!("weave: import error: {e}");
        std::process::exit(1);
    });

    eprintln!("weave: imports resolved");

    // ── 4. Apply filesystem sandbox ───────────────────────────────────────
    weave_sandbox::apply(!args.no_sandbox);

    // ── 5. Initialise TEB / PEB / TLS ────────────────────────────────────
    let _teb = teb::setup(&image).unwrap_or_else(|e| {
        eprintln!("weave: TEB setup failed: {e}");
        std::process::exit(1);
    });

    // ── 6. Install exception handlers ─────────────────────────────────────
    seh::install(&image);

    eprintln!("weave: TEB ready — jumping in");

    // ── 7. Jump to the entry point ────────────────────────────────────────
    // Safety: image.entry_point is a valid executable address set up by loader::load().
    unsafe { exec::run(image.entry_point) }
}
