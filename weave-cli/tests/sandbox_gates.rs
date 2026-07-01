//! CI gates for SB1 — out-of-process guest execution.
//!
//! Gate 1 (sandbox_child_spawn_gate): verifies that after fork+exec, the child
//! prints the three phase markers: `child_spawned`, `seccomp_applied`, `ipc_alive`.
//!
//! Gate 2 (sandbox_hello_gate): verifies that hello.exe's stdout is "Hello, World!\n"
//! and matches a known SHA-256 hash, proving end-to-end IPC + host output works.

mod common;

use std::io::{Read, Write};
use std::process::Command;

fn find_fixture(name: &str) -> Option<std::path::PathBuf> {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture = manifest
        .parent()
        .unwrap()
        .join("tests/fixtures/bin")
        .join(name);
    if fixture.exists() { Some(fixture) } else { None }
}

fn sha256_of_bytes(data: &[u8]) -> String {
    let mut child = Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("sha256sum not found — needed for sandbox gate");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(data)
        .expect("write to sha256sum stdin");
    let out = child.wait_with_output().expect("sha256sum wait");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string()
}

/// Known-good SHA-256 of `b"Hello, World!\n"` (hello.exe's expected stdout).
const HELLO_EXPECTED_SHA256: &str = "c98c24b677eff44860afea6f493bbaec5bb1c4cbb209c6fc2bbb47f66ff2ad31";

/// Gate 1 — Verify child process spawns seccomp and IPC markers.
#[test]
fn sandbox_child_spawn_gate() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping sandbox_child_spawn_gate — requires Linux");
        return;
    }

    let fixture = match find_fixture("hello.exe") {
        Some(p) => p,
        None => {
            eprintln!("skipping: hello.exe not found in fixtures");
            return;
        }
    };

    let weave_bin = env!("CARGO_BIN_EXE_weave");
    let mut child = Command::new(weave_bin)
        .arg(&fixture)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn weave");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => panic!("wait failed: {e}"),
        }
    }

    let mut stderr_buf = Vec::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_end(&mut stderr_buf);
    }
    let stderr = String::from_utf8_lossy(&stderr_buf);

    eprintln!("sandbox_child_spawn_gate stderr:\n{stderr}");

    assert!(
        stderr.contains("PHASE: child_spawned"),
        "sandbox_child_spawn_gate FAIL: PHASE: child_spawned not found in stderr.\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("PHASE: seccomp_applied"),
        "sandbox_child_spawn_gate FAIL: PHASE: seccomp_applied not found in stderr.\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("PHASE: ipc_alive"),
        "sandbox_child_spawn_gate FAIL: PHASE: ipc_alive not found in stderr.\nstderr:\n{stderr}"
    );
}

/// Gate 2 — Verify hello.exe produces correct stdout under the sandbox.
#[test]
fn sandbox_hello_gate() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping sandbox_hello_gate — requires Linux");
        return;
    }

    let fixture = match find_fixture("hello.exe") {
        Some(p) => p,
        None => {
            eprintln!("skipping: hello.exe not found in fixtures");
            return;
        }
    };

    let weave_bin = env!("CARGO_BIN_EXE_weave");
    let output = Command::new(weave_bin)
        .arg(&fixture)
        .output()
        .expect("failed to run weave on hello.exe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("sandbox_hello_gate stdout:\n{stdout}");
    eprintln!("sandbox_hello_gate stderr:\n{stderr}");

    assert!(
        stdout.contains("Hello, World!"),
        "sandbox_hello_gate FAIL: stdout does not contain 'Hello, World!'.\nstdout: {stdout}\nstderr: {stderr}"
    );

    let actual_hash = sha256_of_bytes(&output.stdout);
    assert_eq!(
        actual_hash,
        HELLO_EXPECTED_SHA256,
        "sandbox_hello_gate FAIL: stdout SHA-256 mismatch.\n\
         expected: {HELLO_EXPECTED_SHA256}\n\
         actual:   {actual_hash}\n\
         stdout bytes (first 256): {:?}\n\
         stderr:\n{stderr}",
        &output.stdout[..output.stdout.len().min(256)],
    );
}
