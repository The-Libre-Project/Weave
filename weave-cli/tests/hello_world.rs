//! Integration tests — run Windows .exe files under Weave and check output.
//!
//! Tests are skipped on non-Linux platforms (the dev machine is macOS ARM64).

fn run_weave(fixture_name: &str) -> std::process::Output {
    let weave_bin = env!("CARGO_BIN_EXE_weave");
    let fixture = format!(
        "{}/../tests/fixtures/bin/{fixture_name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::process::Command::new(weave_bin)
        .arg(&fixture)
        .output()
        .unwrap_or_else(|e| panic!("failed to run weave on {fixture_name}: {e}"))
}

/// `weave hello_minimal.exe` — nostdlib binary, exactly 3 NT imports.
#[test]
fn hello_minimal_prints_hello_world() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping execution test — requires Linux");
        return;
    }

    let output = run_weave("hello_minimal.exe");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "weave exited with non-zero status: {}\nstderr: {stderr}",
        output.status
    );
    assert_eq!(
        stdout, "Hello, World!\n",
        "unexpected stdout.\nstderr: {stderr}"
    );
}

/// `weave putty.exe` — PuTTY GUI; we check that HeapAlloc is called during CRT init.
/// This is a diagnostic test — PuTTY will crash later without a display, but we
/// want stderr to show HeapAlloc was reached before any crash.
#[test]
fn putty_heapalloc_is_reached() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping execution test — requires Linux");
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");
    let fixture = format!(
        "{}/../tests/fixtures/bin/putty.exe",
        env!("CARGO_MANIFEST_DIR")
    );
    // Run with a short timeout — PuTTY will likely crash or hang without a display.
    // We just care about stderr output from our stubs.
    let output = std::process::Command::new(weave_bin)
        .arg(&fixture)
        .output()
        .unwrap_or_else(|e| panic!("failed to run weave on putty.exe: {e}"));

    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("putty stderr:\n{stderr}");

    // Must have called HeapAlloc at least once (CRT init allocates memory).
    assert!(
        stderr.contains("weave: HeapAlloc"),
        "HeapAlloc was never called — CRT init may have crashed before reaching it.\nstderr: {stderr}"
    );
}

/// `weave hello.exe` — CRT-linked MinGW binary, 41 imports across 8 DLLs.
#[test]
fn hello_crt_prints_hello_world() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping execution test — requires Linux");
        return;
    }

    let output = run_weave("hello.exe");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "weave exited with non-zero status: {}\nstderr: {stderr}",
        output.status
    );
    assert_eq!(
        stdout, "Hello, World!\n",
        "unexpected stdout.\nstderr: {stderr}"
    );
}
