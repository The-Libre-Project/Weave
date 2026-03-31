use clap::Parser;
use std::path::PathBuf;
use weave_core::{exec, iat, loader, seh, teb};

/// Weave — run Windows executables on Linux.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the Windows .exe file to run
    exe: PathBuf,

    /// Disable the filesystem sandbox (for debugging only)
    #[arg(long)]
    no_sandbox: bool,
}

/// Resolve a Windows import to a Weave stub address.
///
/// Tries each stub crate in turn; returns `None` for unknown imports so the
/// IAT patcher can abort with a clear "unresolved import" message.
fn resolve(dll: &str, func: &str) -> Option<usize> {
    weave_ntdll::resolve(dll, func).or_else(|| weave_kernel32::resolve(dll, func))
}

fn main() {
    let args = Args::parse();

    let bytes = std::fs::read(&args.exe).unwrap_or_else(|e| {
        eprintln!("weave: error reading {}: {e}", args.exe.display());
        std::process::exit(1);
    });

    // ── 1. Load sections into memory ─────────────────────────────────────
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

    // ── 2. Patch the Import Address Table ────────────────────────────────
    // Safety: image.base points to a fully mapped PE loaded by loader::load().
    unsafe { iat::patch(&bytes, image.base, resolve) }.unwrap_or_else(|e| {
        eprintln!("weave: import error: {e}");
        std::process::exit(1);
    });

    eprintln!("weave: imports resolved");

    // ── 3. Apply filesystem sandbox ───────────────────────────────────────
    weave_sandbox::apply(!args.no_sandbox);

    // ── 4. Initialise TEB / PEB / TLS ────────────────────────────────────
    // Keep _teb alive — it holds the TEB, PEB, ProcessParameters, and TLS
    // memory that the PE code will read via GS throughout its execution.
    let _teb = teb::setup(&image).unwrap_or_else(|e| {
        eprintln!("weave: TEB setup failed: {e}");
        std::process::exit(1);
    });

    // ── 5. Install exception handlers ─────────────────────────────────────
    seh::install(&image);

    eprintln!("weave: TEB ready — jumping in");

    // ── 6. Jump to the entry point ────────────────────────────────────────
    // Safety: image.entry_point is a valid executable address set up by loader::load().
    unsafe { exec::run(image.entry_point) }
}
