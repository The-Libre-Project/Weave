//! CI gate for the sandbox runtime invariant.
//!
//! Verifies that `weave-cli` refuses to launch guest Win32 code when the
//! sandbox is not active. Without this gate, "sandbox active" is only a
//! design claim — a refactor or new entry point can silently bypass it.
//!
//! What this protects against:
//!   - Someone passing `--no-sandbox` in production.
//!   - The env-var kill switch `WEAVE_DISABLE_SANDBOX=1` being honored
//!     without producing a panic.
//!   - A future entry point that forgets to call
//!     `weave_sandbox::assert_sandboxed!()` before transferring control.
//!
//! The test launches the real `weave` binary against a real fixture .exe,
//! with `WEAVE_DISABLE_SANDBOX=1` set. It asserts:
//!   1. The process exits non-zero (panic = abnormal exit).
//!   2. Stderr contains the stable invariant marker
//!      `weave: SANDBOX INVARIANT VIOLATION`.
//!
//! See `docs/SECURITY_AUDIT.md` § "Sandbox runtime invariant".

use std::path::PathBuf;
use std::process::Command;

/// Find a Win32 fixture .exe to drive the sandbox-disabled launch.
///
/// The test does not need the binary to actually run — the assert fires
/// before any guest code executes, so any well-formed .exe works. We pick
/// the smallest available fixture.
fn pick_fixture() -> Option<PathBuf> {
    // Walk up from CARGO_MANIFEST_DIR to find the workspace root.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest.parent().unwrap_or(&manifest);
    let candidates = [
        "tests/fixtures/bin/hello_minimal.exe",
        "tests/fixtures/bin/hello.exe",
        "tests/fixtures/bin/fileio.exe",
    ];
    for c in &candidates {
        let p = workspace_root.join(c);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

#[test]
fn sandbox_invariant_blocks_unsandboxed_launch() {
    let fixture = match pick_fixture() {
        Some(p) => p,
        None => {
            // CI compiles the fixtures before running tests; absence on a
            // local dev machine without mingw is acceptable. Print and skip.
            eprintln!(
                "sandbox_invariant_blocks_unsandboxed_launch: no fixture .exe \
                 found under tests/fixtures/bin — skipping. CI must build \
                 fixtures before tests."
            );
            return;
        }
    };

    let weave_bin = env!("CARGO_BIN_EXE_weave");
    let output = Command::new(weave_bin)
        .arg(&fixture)
        .env("WEAVE_DISABLE_SANDBOX", "1")
        // Keep the panic visible in stderr regardless of the runner config.
        .env("RUST_BACKTRACE", "0")
        .output()
        .expect("failed to spawn weave binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        !output.status.success(),
        "weave must NOT succeed when WEAVE_DISABLE_SANDBOX=1 is set. \
         status={:?} stdout={stdout} stderr={stderr}",
        output.status,
    );

    assert!(
        stderr.contains("SANDBOX INVARIANT VIOLATION"),
        "stderr must contain the sandbox-invariant marker. \
         status={:?} stderr={stderr}",
        output.status,
    );

    assert!(
        stderr.contains("weave-cli"),
        "panic message must name the entry point (`weave-cli`). \
         stderr={stderr}",
    );
}
