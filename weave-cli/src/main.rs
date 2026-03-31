use clap::Parser;
use std::path::PathBuf;
use weave_core::{exec, iat, loader, stubs, teb};

/// Weave — run Windows executables on Linux.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the Windows .exe file to run
    exe: PathBuf,
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
    iat::patch(&bytes, image.base, stubs::resolve).unwrap_or_else(|e| {
        eprintln!("weave: import error: {e}");
        std::process::exit(1);
    });

    eprintln!("weave: imports resolved");

    // ── 3. Initialise TEB / PEB ───────────────────────────────────────────
    // Keep _teb alive — it holds the TEB, PEB, and ProcessParameters memory
    // that the PE code will read via GS throughout its execution.
    let _teb = teb::setup().unwrap_or_else(|e| {
        eprintln!("weave: TEB setup failed: {e}");
        std::process::exit(1);
    });

    eprintln!("weave: TEB ready — jumping in");

    // ── 4. Jump to the entry point ────────────────────────────────────────
    exec::run(image.entry_point)
}
