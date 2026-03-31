use clap::Parser;
use std::path::PathBuf;
use weave_core::{exec, iat, loader, sandbox, stubs, teb};

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

fn main() {
    // Install a SIGSEGV handler that prints the faulting address before dying.
    // This helps diagnose crashes in PE code during development.
    #[cfg(target_os = "linux")]
    unsafe {
        extern "C" fn on_sigsegv(
            _sig: libc::c_int,
            info: *mut libc::siginfo_t,
            _ctx: *mut libc::c_void,
        ) {
            let addr = unsafe { (*info).si_addr() };
            // Use write(2) directly — malloc/eprintln may be broken at this point.
            let msg = format!("weave: SIGSEGV at {addr:p}\n");
            unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len()) };
            unsafe { libc::exit(139) };
        }
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_flags = libc::SA_SIGINFO;
        sa.sa_sigaction = on_sigsegv as extern "C" fn(_, _, _) as usize;
        libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut());
    }

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
    unsafe { iat::patch(&bytes, image.base, stubs::resolve) }.unwrap_or_else(|e| {
        eprintln!("weave: import error: {e}");
        std::process::exit(1);
    });

    eprintln!("weave: imports resolved");

    // ── 3. Apply filesystem sandbox ───────────────────────────────────────
    sandbox::apply(!args.no_sandbox);

    // ── 4. Initialise TEB / PEB / TLS ────────────────────────────────────
    // Keep _teb alive — it holds the TEB, PEB, ProcessParameters, and TLS
    // memory that the PE code will read via GS throughout its execution.
    let _teb = teb::setup(&image).unwrap_or_else(|e| {
        eprintln!("weave: TEB setup failed: {e}");
        std::process::exit(1);
    });

    eprintln!("weave: TEB ready — jumping in");

    // ── 5. Jump to the entry point ────────────────────────────────────────
    // Safety: image.entry_point is a valid executable address set up by loader::load().
    unsafe { exec::run(image.entry_point) }
}
