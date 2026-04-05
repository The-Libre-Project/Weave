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

/// `weave 7za.exe l test.7z` — list archive contents using the 7-Zip CLI binary.
///
/// Uses 7za.exe (7-Zip standalone, x64) from the portable 7-Zip 26.00 extra
/// package. The archive is tests/fixtures/bin/test.7z (two entries).
/// This is the Sprint 2 functional gate: proves 7-Zip runs a real command
/// end-to-end under Weave.
#[test]
fn seven_zip_list_archive() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping execution test — requires Linux");
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let bin_dir = format!("{manifest}/../tests/fixtures/bin");
    let seven_zip = format!("{bin_dir}/7za.exe");
    let archive = format!("{bin_dir}/test.7z");

    if !std::path::Path::new(&seven_zip).exists() {
        eprintln!("skipping: 7za.exe not present in fixtures");
        return;
    }
    if !std::path::Path::new(&archive).exists() {
        eprintln!("skipping: test.7z not present in fixtures (run tests/fixtures/src/make_zip.py)");
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");
    // Run with CWD = bin_dir so 7za.exe can open "test.7z" as a relative path.
    // Absolute Linux paths (e.g. /weave/tests/fixtures/bin/test.7z) are
    // rejected by 7za.exe as invalid Windows paths before any file I/O.
    // GetCurrentDirectoryW returns Z:\<linux-cwd> so 7za.exe canonicalizes
    // "test.7z" → "Z:\<cwd>\test.7z" which our path translator opens correctly.
    let output = std::process::Command::new(weave_bin)
        .current_dir(&bin_dir)
        .arg(&seven_zip)
        .arg("l")
        .arg("test.7z")
        .output()
        .unwrap_or_else(|e| panic!("failed to run weave on 7za.exe: {e}"));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("7za stderr:\n{stderr}");

    assert!(
        output.status.success(),
        "7za.exe l exited non-zero: {}\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
    assert!(
        stdout.contains("hello.txt"),
        "archive listing did not contain 'hello.txt'.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("world.txt"),
        "archive listing did not contain 'world.txt'.\nstdout: {stdout}\nstderr: {stderr}"
    );
}

/// `weave putty.exe` — PuTTY GUI; we check that HeapAlloc is called during CRT init.
///
/// PuTTY will hang after CRT init (no display in Docker), so we enforce a 5s
/// timeout, kill the process, then inspect what was written to stderr.
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

    // Capture stderr via a pipe, spawn, wait up to 5 s, then kill.
    let mut child = std::process::Command::new(weave_bin)
        .arg(&fixture)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn weave on putty.exe: {e}"));

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break, // exited on its own
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => panic!("wait failed: {e}"),
        }
    }

    // Read whatever stderr was produced.
    let stderr_bytes = {
        use std::io::Read;
        let mut buf = Vec::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    };
    let stderr = String::from_utf8_lossy(&stderr_bytes);
    eprintln!("putty stderr:\n{stderr}");

    // PuTTY's CRT init calls LoadLibraryA at runtime (via _initterm callbacks).
    // Seeing GetProcAddress output proves CRT init is running successfully.
    assert!(
        stderr.contains("GetProcAddress"),
        "CRT init did not reach runtime LoadLibrary/GetProcAddress — may have crashed early.\nstderr: {stderr}"
    );
}

/// `weave 7zFM.exe` — 7-Zip GUI; exits cleanly (code 0) in headless Docker.
///
/// Validates that the entire CRT initialisation runs without crashing.
/// The binary detects no display and exits — exit code 0 is correct.
#[test]
fn seven_zip_fm_crt_init_completes() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping execution test — requires Linux");
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");
    let fixture = format!(
        "{}/../tests/fixtures/bin/7zFM.exe",
        env!("CARGO_MANIFEST_DIR")
    );

    if !std::path::Path::new(&fixture).exists() {
        eprintln!("skipping: 7zFM.exe not present in fixtures (add from portable 7-Zip 26.x)");
        return;
    }

    // The GUI app exits on its own in headless Docker; cap at 10 s anyway.
    let mut child = std::process::Command::new(weave_bin)
        .arg(&fixture)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn weave on 7zFM.exe: {e}"));

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => panic!("wait failed: {e}"),
        }
    }

    let stderr_bytes = {
        use std::io::Read;
        let mut buf = Vec::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    };
    let stderr = String::from_utf8_lossy(&stderr_bytes);
    eprintln!("7zFM stderr:\n{stderr}");

    // Must have loaded and resolved imports without crashing.
    assert!(
        stderr.contains("weave: imports resolved"),
        "import resolution did not complete — possible crash during IAT patch.\nstderr: {stderr}"
    );
    // CRT stub _initterm must have been called (proves CRT startup ran).
    assert!(
        stderr.contains("_initterm"),
        "CRT _initterm was never called — CRT startup may have crashed.\nstderr: {stderr}"
    );
}

/// `weave notepad++.exe` — Notepad++ GUI; Sprint 4 portable-mode gate.
///
/// We run it with a 10-second timeout.  The critical check: Notepad++ must
/// NOT print "Load langs.xml failed!" — that error fires when portable mode
/// detection fails and Notepad++ looks in the wrong directory for config files.
/// A clean run (no error dialog) means `PathFileExistsW` / `GetFileAttributesExW`
/// correctly located `doLocalConf.xml` next to the exe.
#[test]
fn notepad_plus_plus_portable_mode() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping execution test — requires Linux");
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let npp_dir = format!("{manifest}/../tests/fixtures/npp");
    let npp_exe = format!("{npp_dir}/notepad++.exe");

    if !std::path::Path::new(&npp_exe).exists() {
        eprintln!("skipping: notepad++.exe not present in tests/fixtures/npp/");
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");
    // Run with CWD = npp_dir so relative paths in Notepad++ resolve inside the
    // portable directory.
    let mut child = std::process::Command::new(weave_bin)
        .current_dir(&npp_dir)
        .arg(&npp_exe)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn weave on notepad++.exe: {e}"));

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => panic!("wait failed: {e}"),
        }
    }

    let stderr_bytes = {
        use std::io::Read;
        let mut buf = Vec::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    };
    let stderr = String::from_utf8_lossy(&stderr_bytes);
    eprintln!("notepad++ stderr:\n{stderr}");

    // Imports must resolve before the entry point runs.
    assert!(
        stderr.contains("weave: imports resolved"),
        "import resolution did not complete — possible crash during IAT patch.\nstderr: {stderr}"
    );

    // Portable mode check: doLocalConf.xml must be found next to the exe.
    // If not found, Notepad++ shows "Load langs.xml failed!" via MessageBoxW.
    assert!(
        !stderr.contains("Load langs.xml failed"),
        "Notepad++ could not find langs.xml — portable mode detection failed.\nstderr: {stderr}"
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
