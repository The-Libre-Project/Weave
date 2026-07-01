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

/// Gate 3 — Verify testsprite2 creates a window and dispatches WM_PAINT under sandbox,
/// then cleanly exits on Alt+F4.
#[test]
fn sandbox_testsprite_gate() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping sandbox_testsprite_gate — requires Linux");
        return;
    }

    let fixture = match find_fixture("testsprite2.exe") {
        Some(p) => p,
        None => {
            eprintln!("skipping: testsprite2.exe not found in fixtures");
            return;
        }
    };

    let bin_dir = fixture.parent().unwrap().to_path_buf();
    let weave_bin = env!("CARGO_BIN_EXE_weave");

    let mut child = Command::new(weave_bin)
        .current_dir(&bin_dir)
        .arg(&fixture)
        .env("DISPLAY", ":99")
        .env("SDL_VIDEODRIVER", "x11")
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn weave on testsprite2.exe");

    let stderr_pipe = child.stderr.take().expect("stderr was piped");
    let stderr_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let stderr_writer = std::sync::Arc::clone(&stderr_shared);
    let drain_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut pipe = stderr_pipe;
        let mut chunk = [0u8; 4096];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => stderr_writer.lock().unwrap().extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
    });

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut saw_create_window = false;
    let mut saw_wm_paint = false;
    let mut sent_alt_f4 = false;
    let mut exit_status: Option<std::process::ExitStatus> = None;

    loop {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            break;
        }

        {
            let stderr_bytes = stderr_shared.lock().unwrap().clone();
            let stderr = String::from_utf8_lossy(&stderr_bytes);
            if !saw_create_window && stderr.contains("PHASE: create_window_first") {
                saw_create_window = true;
                eprintln!("observed PHASE: create_window_first");
            }
            if !saw_wm_paint && stderr.contains("PHASE: wm_paint_dispatched_first") {
                saw_wm_paint = true;
                eprintln!("observed PHASE: wm_paint_dispatched_first");
            }
        }

        if saw_create_window && saw_wm_paint && !sent_alt_f4 {
            sent_alt_f4 = true;
            eprintln!("both phases observed — sending Alt+F4 via xdotool");
            let search = Command::new("xdotool")
                .args(["search", "--name", "testsprite"])
                .output();
            match search {
                Ok(out) if out.status.success() => {
                    let wid = String::from_utf8_lossy(&out.stdout)
                        .lines()
                        .next()
                        .map(|s| s.trim().to_string())
                        .unwrap_or_default();
                    if !wid.is_empty() {
                        let _ = Command::new("xdotool")
                            .args(["windowactivate", &wid])
                            .output();
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        let _ = Command::new("xdotool")
                            .args(["key", "--window", &wid, "Alt+F4"])
                            .output();
                    } else {
                        eprintln!("xdotool search found no window matching 'testsprite'");
                    }
                }
                _ => {
                    eprintln!("xdotool search failed or not found");
                }
            }
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => panic!("wait failed: {e}"),
        }
    }

    drain_thread.join().expect("stderr drain thread panicked");
    let stderr_bytes = stderr_shared.lock().unwrap().clone();
    let stderr = String::from_utf8_lossy(&stderr_bytes);

    eprintln!("sandbox_testsprite_gate stderr:\n{stderr}");
    eprintln!("sandbox_testsprite_gate exit: {:?}", exit_status);

    assert!(
        saw_create_window,
        "FAIL: PHASE: create_window_first not observed within 30s.\nstderr:\n{stderr}"
    );
    assert!(
        saw_wm_paint,
        "FAIL: PHASE: wm_paint_dispatched_first not observed within 30s.\nstderr:\n{stderr}"
    );
    assert_eq!(
        exit_status.map(|s| s.code().unwrap_or(-1)),
        Some(0),
        "FAIL: testsprite2 did not exit 0.\nexit_status: {:?}\nstderr:\n{stderr}",
        exit_status
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
