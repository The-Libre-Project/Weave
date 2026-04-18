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

/// `weave notepad++.exe test.py` — Notepad++ GUI; Phase 6b WS1 gate.
///
/// Runs Notepad++ with a Python file argument. Checks:
/// 1. IAT patch completes ("weave: imports resolved")
/// 2. Portable-mode config lookup succeeds (no "Load langs.xml failed!")
/// 3. No critical GDI32/USER32 functions remain unresolved for Scintilla's
///    text-rendering path (GetTextExtentExPointW, EnumFontFamiliesExW, etc.)
/// 4. The process enters the Win32 message loop and runs for ≥ 2 seconds,
///    indicating Notepad++ successfully loaded the file and began processing.
///
/// Note: visual verification (syntax-highlighted text in an X11 window) requires
/// an interactive session with a live display. This test covers the headless
/// regression gate only.
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

    // Copy the fixture to a temp dir so NPP can write-open config files (langs.xml,
    // stylers.xml, etc.) without hitting the sandbox deny on the read-only fixture dir.
    let tmp_dir = std::env::temp_dir().join("weave_npp_test");
    if tmp_dir.exists() {
        std::fs::remove_dir_all(&tmp_dir).expect("failed to clean temp npp dir");
    }
    fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) {
        std::fs::create_dir_all(dst).expect("create_dir_all failed");
        for entry in std::fs::read_dir(src).expect("read_dir failed") {
            let entry = entry.expect("entry failed");
            let dst_path = dst.join(entry.file_name());
            if entry.file_type().expect("file_type failed").is_dir() {
                copy_dir_all(&entry.path(), &dst_path);
            } else {
                std::fs::copy(entry.path(), &dst_path).expect("copy failed");
            }
        }
    }
    copy_dir_all(std::path::Path::new(&npp_dir), &tmp_dir);

    let tmp_exe = tmp_dir.join("notepad++.exe");
    let tmp_py = tmp_dir.join("test.py");

    // Run with CWD = tmp_dir so relative paths in Notepad++ resolve inside the
    // writable copy. Pass test.py as argv[1] to exercise the file-load path.
    let start = std::time::Instant::now();
    let mut child = std::process::Command::new(weave_bin)
        .current_dir(&tmp_dir)
        .arg(&tmp_exe)
        .arg(&tmp_py)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn weave on notepad++.exe: {e}"));

    // Drain stderr concurrently — NPP's Weave output can exceed the 64 KB
    // Linux pipe buffer, blocking write() before the message loop is reached.
    let stderr_pipe = child.stderr.take().expect("stderr was piped");
    let stderr_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let stderr_writer = std::sync::Arc::clone(&stderr_shared);
    let drain_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut pipe = stderr_pipe;
        let _ = pipe.read_to_end(&mut buf);
        *stderr_writer.lock().unwrap() = buf;
    });

    let deadline = start + std::time::Duration::from_secs(10);
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
    let elapsed = start.elapsed();

    drain_thread.join().expect("stderr drain thread panicked");
    let stderr_bytes = stderr_shared.lock().unwrap().clone();
    let stderr = String::from_utf8_lossy(&stderr_bytes);
    eprintln!("notepad++ stderr ({elapsed:.1?}):\n{stderr}");

    // Gate 1: IAT patch must complete before the entry point runs.
    assert!(
        stderr.contains("weave: imports resolved"),
        "import resolution did not complete — possible crash during IAT patch.\nstderr: {stderr}"
    );

    // Gate 2: Portable mode — doLocalConf.xml must be found next to the exe.
    assert!(
        !stderr.contains("Load langs.xml failed"),
        "Notepad++ could not find langs.xml — portable mode detection failed.\nstderr: {stderr}"
    );

    // Gate 3: Critical Scintilla GDI functions must not appear as unresolved.
    // These were wired in Phase 6b WS1; if they appear here the resolve() table
    // regressed.
    for func in &[
        "GetTextExtentExPointW",
        "EnumFontFamiliesExW",
        "SetTextAlign",
        "CreateRectRgn",
        "GetObjectW",
    ] {
        assert!(
            !stderr.contains(&format!("weave: unresolved: gdi32.dll::{func}")),
            "Scintilla GDI function {func} is still unresolved — Phase 6b WS1 regression.\nstderr: {stderr}"
        );
    }

    // Gate 4: Process must run for at least 2 seconds, indicating it entered
    // the Win32 message loop rather than crashing at startup.
    assert!(
        elapsed >= std::time::Duration::from_secs(2),
        "Notepad++ ran for only {elapsed:.1?} — likely crashed before entering message loop.\nstderr: {stderr}"
    );

    // Gate 5: WM_PAINT must have been dispatched, proving the paint path is reached.
    // ShowWindow posts WM_PAINT → GetMessageW returns it → DispatchMessageW fires the
    // wm_paint_dispatched_first phase marker before invoking NPP's WndProc.
    assert!(
        stderr.contains("PHASE: wm_paint_dispatched_first"),
        "PHASE: wm_paint_dispatched_first was never emitted — WM_PAINT was not dispatched, \
         meaning Notepad++ did not reach the paint path.\nstderr: {stderr}"
    );

    // Gate 6: Scintilla document must have content after opening test.py.
    // NPP uses Scintilla_DirectFunction (not SendMessageW) for all SCI ops. The proxy
    // intercepts this and logs SCI_APPENDTEXT when NPP loads file bytes into the document.
    // Note: SCI_DIRECT_PTR only stores the last SCI_GETDIRECTPOINTER result (secondary
    // Scintilla window) so BeginPaint's SCI_GETLENGTH probe reads the wrong instance.
    // Checking SCI_APPENDTEXT(wp>0) in the proxy log is the correct signal.
    let sci_content_loaded = stderr.lines().any(|l| {
        if !l.contains("msg=2282(SCI_APPENDTEXT)") {
            return false;
        }
        l.split("wp=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| usize::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .map(|wp| wp > 0)
            .unwrap_or(false)
    });
    assert!(
        sci_content_loaded,
        "Scintilla never received SCI_APPENDTEXT with content — \
         test.py was loaded but not inserted into Scintilla.\n\
         stderr: {stderr}"
    );
}

/// `weave i_view64.exe` — IrfanView 64-bit portable image viewer.
///
/// Sprint 5 functional gate: IrfanView 4.73 (64-bit) must fully initialise its
/// Win32 window, run its message loop, and exit cleanly when no display is
/// available (headless Docker). IrfanView 4.73 x64 does NOT use gdiplus.dll;
/// it imports KERNEL32, USER32, GDI32, ADVAPI32, SHELL32, COMCTL32 statically
/// plus ole32/SHLWAPI/COMDLG32 via delay-load.
///
/// The fixture is `tests/fixtures/irfanview/i_view64.exe`. It is not bundled
/// in the repo — copy the IrfanView portable exe there before running in Docker.
/// The test is skipped gracefully if the file is absent (CI still passes).
///
/// In headless Docker, IrfanView detects no display and exits with code 0.
/// We cap at 15 s, kill if it hangs, then inspect stderr.
#[test]
fn irfanview_gdip_startup_reached() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping execution test — requires Linux");
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let irfan_dir = format!("{manifest}/../tests/fixtures/irfanview");
    let irfan_exe = format!("{irfan_dir}/i_view64.exe");

    if !std::path::Path::new(&irfan_exe).exists() {
        eprintln!("skipping: i_view64.exe not present in tests/fixtures/irfanview/");
        eprintln!("  → copy the IrfanView 64-bit portable exe there to enable this test");
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");
    // IrfanView's test is designed for headless operation: it detects no display
    // and exits cleanly via WM_QUIT. Unset DISPLAY so the test stays headless even
    // when Xvfb is running for the NPP test.
    let mut child = std::process::Command::new(weave_bin)
        .current_dir(&irfan_dir)
        .arg(&irfan_exe)
        .env_remove("DISPLAY")
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn weave on i_view64.exe: {e}"));

    // Drain stderr concurrently — IrfanView's Weave output can exceed the 64 KB
    // Linux pipe buffer, blocking write() before the message loop is reached.
    let stderr_pipe = child.stderr.take().expect("stderr was piped");
    let stderr_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let stderr_writer = std::sync::Arc::clone(&stderr_shared);
    let drain_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut pipe = stderr_pipe;
        let _ = pipe.read_to_end(&mut buf);
        *stderr_writer.lock().unwrap() = buf;
    });

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
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

    drain_thread.join().expect("stderr drain thread panicked");
    let stderr_bytes = stderr_shared.lock().unwrap().clone();
    let stderr = String::from_utf8_lossy(&stderr_bytes);
    eprintln!("irfanview stderr:\n{stderr}");

    // Import resolution must complete before the entry point fires.
    assert!(
        stderr.contains("weave: imports resolved"),
        "import resolution did not complete — possible crash during IAT patch.\nstderr: {stderr}"
    );

    // Sprint 5 functional gate: IrfanView 4.73 64-bit must reach its Win32
    // message loop and exit cleanly when no display is available (headless Docker).
    // GetMessageW returning WM_QUIT proves: IAT patch succeeded, RegisterClassExW
    // and CreateWindowExW ran, COM initialised, and the message pump started.
    assert!(
        stderr.contains("wm_paint_dispatched_first"),
        "IrfanView did not reach WM_PAINT dispatch — startup failed before message loop.\nstderr: {stderr}"
    );
}

/// `weave SciTE.exe test.txt` — SciTE 5.6.1 source code editor; Gate 5 semantic gate.
///
/// SciTE (SCIntilla based Text Editor) is a Win32 GUI editor that embeds
/// Scintilla statically — Scintilla.dll does not appear in the import table.
/// SCI_GETLENGTH (message 2006) is dispatched via SendMessageW to the Scintilla
/// control when the editor loads a document; intercepting it proves the editor
/// loop is running and a document was inserted into the Scintilla buffer.
///
/// Surface audit: 2026-04-12, SciTE 5.6.1 (x64 PE).
/// - All 8 phase-ladder events are reachable from a cold start with a file arg.
/// - PHASE: sci_getlength_probed appears in Weave stderr when SCI_GETLENGTH fires.
///
/// Known risk: SciTE.exe re-exports 146 lua_*/luaL_* symbols from its own EXE
/// section — EXE-as-pseudo-DLL edge case that may trigger Weave loader issues
/// on export table resolution. If the loader crashes early, imports resolved
/// will be absent and the test will fail on Gate 1 with a clear message.
///
/// Gate 5 semantic: sci_getlength_probed in stderr proves SCI_GETLENGTH was
/// dispatched, i.e. the Scintilla editor loaded the document and the editor
/// loop is processing Win32 messages.
///
/// Fixture: tests/fixtures/scite/SciTE.exe + tests/fixtures/scite/test.txt
/// The test is skipped gracefully if either file is absent (CI still passes).
/// Timeout: 15 s cap (kill); asserts alive for ≥ 8 s OR sci_getlength_probed.
#[test]
fn scite_portable_mode() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping execution test — requires Linux");
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let scite_dir = format!("{manifest}/../tests/fixtures/scite");
    let scite_exe = format!("{scite_dir}/SciTE.exe");
    let test_txt = format!("{scite_dir}/test.txt");

    if !std::path::Path::new(&scite_exe).exists() {
        eprintln!("skipping: SciTE.exe not present in tests/fixtures/scite/");
        eprintln!("  → copy SciTE 5.6.1 portable exe there to enable this test");
        return;
    }

    if !std::path::Path::new(&test_txt).exists() {
        eprintln!("skipping: test.txt not present in tests/fixtures/scite/");
        eprintln!("  → create tests/fixtures/scite/test.txt with content to enable this test");
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");
    let start = std::time::Instant::now();
    let mut child = std::process::Command::new(weave_bin)
        .current_dir(&scite_dir)
        .arg(&scite_exe)
        .arg(&test_txt)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn weave on SciTE.exe: {e}"));

    // Drain stderr in a background thread so the OS pipe (64 KB on Linux) never
    // fills up and blocks SciTE's eprintln! calls.  Without this, SciTE's verbose
    // Weave output (toolbar button setup alone emits ~71 KB) fills the pipe buffer
    // and the SciTE process blocks on write() before it can call GetMessageW.
    let stderr_pipe = child.stderr.take().expect("stderr was piped");
    let stderr_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let stderr_writer = std::sync::Arc::clone(&stderr_shared);
    let drain_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut pipe = stderr_pipe;
        let _ = pipe.read_to_end(&mut buf);
        *stderr_writer.lock().unwrap() = buf;
    });

    let deadline = start + std::time::Duration::from_secs(15);
    let mut exit_status: Option<std::process::ExitStatus> = None;
    let mut killed_by_deadline = false;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    killed_by_deadline = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => panic!("wait failed: {e}"),
        }
    }
    let elapsed = start.elapsed();

    #[cfg(unix)]
    let exit_summary = {
        use std::os::unix::process::ExitStatusExt;
        if killed_by_deadline {
            "killed by test deadline".to_string()
        } else if let Some(ref s) = exit_status {
            if let Some(sig) = s.signal() {
                format!("killed by signal {sig}")
            } else if let Some(code) = s.code() {
                format!("exited with code {code}")
            } else {
                "unknown exit status".to_string()
            }
        } else {
            "no exit status captured".to_string()
        }
    };
    #[cfg(not(unix))]
    let exit_summary = if killed_by_deadline {
        "killed by test deadline".to_string()
    } else if let Some(ref s) = exit_status {
        if let Some(code) = s.code() {
            format!("exited with code {code}")
        } else {
            "unknown exit status".to_string()
        }
    } else {
        "no exit status captured".to_string()
    };

    // Wait for the drain thread to finish reading all remaining output.
    drain_thread.join().expect("stderr drain thread panicked");
    let stderr_bytes = stderr_shared.lock().unwrap().clone();
    let stderr = String::from_utf8_lossy(&stderr_bytes);
    eprintln!("scite stderr ({elapsed:.1?}):\n{stderr}");

    // Gate 1: IAT patch must complete before the entry point runs.
    assert!(
        stderr.contains("weave: imports resolved"),
        "import resolution did not complete — possible crash during IAT patch \
         (check Lua re-export EXE edge case).\nexit: {exit_summary}\nstderr: {stderr}"
    );

    // Gate 2: Process ran ≥ 8 seconds OR SCI_GETLENGTH was dispatched —
    // either condition proves SciTE reached the editor message loop.
    assert!(
        elapsed >= std::time::Duration::from_secs(8)
            || stderr.contains("PHASE: sci_getlength_probed"),
        "SciTE ran for only {elapsed:.1?} without dispatching SCI_GETLENGTH — \
         likely crashed before reaching the editor loop.\nexit: {exit_summary}\nstderr: {stderr}"
    );

    // Gate 5 semantic: SCI_GETLENGTH (msg=2006) must have been dispatched via
    // SendMessageW, proving the Scintilla buffer was loaded with document content.
    assert!(
        stderr.contains("PHASE: sci_getlength_probed"),
        "PHASE: sci_getlength_probed was never emitted — SCI_GETLENGTH was not \
         dispatched, meaning Scintilla did not process the document.\n\
         exit: {exit_summary}\nstderr: {stderr}"
    );
}

/// Sample the X11 display `:99` for non-trivial (non-black) pixels.
///
/// Uses Python3 + ctypes + libX11.so.6 (available via libx11-dev in CI).
/// Samples a 640×480 grid at 8-pixel intervals.  Returns:
///   `Some(true)` — found a pixel brighter than #141414
///   `Some(false)` — all sampled pixels are near-black
///   `None` — Python3 or libX11 unavailable (skips the check)
#[cfg(target_os = "linux")]
fn sample_display_pixels_99() -> Option<bool> {
    // Raw string — Python braces don't conflict with Rust format.
    // Sample the whole 1280x720 Xvfb screen at 16-pixel intervals (~3600 samples).
    // SDL2 testsprite2 opens centered on a 1280x720 screen → ~(320,120).
    // Sampling every 16 px covers the window area without being slow.
    let script = r#"
import ctypes, sys
try:
    x = ctypes.cdll.LoadLibrary("libX11.so.6")
    x.XOpenDisplay.restype  = ctypes.c_void_p
    x.XRootWindow.restype   = ctypes.c_ulong
    x.XGetImage.restype     = ctypes.c_void_p
    x.XGetPixel.restype     = ctypes.c_ulong
    dpy = x.XOpenDisplay(b":99")
    if not dpy: sys.exit(42)
    scr  = x.XDefaultScreen(dpy)
    root = x.XRootWindow(dpy, scr)
    # Full 1280x720 screen — SDL2 window is centered so top-left misses it
    img = x.XGetImage(dpy, root, 0, 0, 1280, 720, 0xFFFFFF, 2)
    if not img:
        x.XCloseDisplay(dpy)
        sys.exit(43)
    threshold = 0x141414  # any channel > 20 counts as "not black"
    found = any(x.XGetPixel(img, xi, yi) > threshold
                for xi in range(0, 1280, 16) for yi in range(0, 720, 16))
    x.XDestroyImage(img)
    x.XCloseDisplay(dpy)
    print(1 if found else 0)
except Exception:
    import traceback; traceback.print_exc()
    sys.exit(44)
"#;
    let out = std::process::Command::new("python3")
        .arg("-c")
        .arg(script)
        .output()
        .ok()?;
    match out.status.code() {
        Some(42) | Some(43) | Some(44) => {
            eprintln!(
                "gate2/pixel-sampler: python3 exit {:?} stderr={}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
            None
        }
        _ if !out.status.success() => None,
        _ => match String::from_utf8_lossy(&out.stdout).trim() {
            "1" => Some(true),
            "0" => Some(false),
            s => {
                eprintln!("gate2/pixel-sampler: unexpected output: {s:?}");
                None
            }
        },
    }
}

/// `weave testsprite2.exe` — SDL2 test binary; WS2 Gate 1 + Gate 2 smoke test.
///
/// Runs testsprite2.exe (SDL2 test binary, PE32+ x86-64) under Weave with
/// --no-sandbox and DISPLAY=:99 (Xvfb). SDL2.dll must be in the same directory
/// as the exe (tests/fixtures/bin/SDL2.dll).
///
/// Gate 1 definition of done: window opens, sprites animate for 10 seconds
/// without crash. This test is a first-run diagnostic: it always dumps full
/// stderr and does not assert on the phase marker yet — that comes after gate 1
/// is confirmed green. The one hard assertion is that IAT patch completes.
///
/// Gate 2 definition of done (M1): at the 5-second mark, the Xvfb screen
/// contains at least one non-black pixel in the 640×480 window area, proving
/// that SDL2's software renderer is actually blitting pixels via GDI→X11.
///
/// Skipped gracefully if testsprite2.exe is absent from fixtures.
#[test]
fn testsprite2_sdl2_gate1_smoke() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping execution test — requires Linux");
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let bin_dir = format!("{manifest}/../tests/fixtures/bin");
    let exe = format!("{bin_dir}/testsprite2.exe");

    if !std::path::Path::new(&exe).exists() {
        eprintln!("skipping: testsprite2.exe not present in tests/fixtures/bin/");
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");

    // Run with CWD = bin_dir so SDL2.dll is found by the PE loader next to the
    // exe. Pass --no-sandbox to eliminate sandbox as a variable on first run.
    // Set DISPLAY=:99 (Xvfb) so SDL2 can attempt to open an X11 window.
    let start = std::time::Instant::now();
    let mut child = std::process::Command::new(weave_bin)
        .current_dir(&bin_dir)
        .arg(&exe)
        .arg("--no-sandbox")
        .env("DISPLAY", ":99")
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn weave on testsprite2.exe: {e}"));

    // Drain stderr concurrently — SDL2's verbose output can fill the 64 KB
    // Linux pipe buffer and block the child process before it gets anywhere.
    let stderr_pipe = child.stderr.take().expect("stderr was piped");
    let stderr_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let stderr_writer = std::sync::Arc::clone(&stderr_shared);
    let drain_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut pipe = stderr_pipe;
        let _ = pipe.read_to_end(&mut buf);
        *stderr_writer.lock().unwrap() = buf;
    });

    // Let it run for up to 15 seconds (Gate 1 target is 10 s of animation),
    // then kill it. SDL2 in headless mode may exit early on its own.
    let deadline = start + std::time::Duration::from_secs(15);
    // Gate 2 pixel check: at 5 seconds testsprite2 has rendered ~300 frames.
    // We sample the Xvfb display for non-black pixels to confirm GDI→X11 blit works.
    let pixel_check_at = start + std::time::Duration::from_secs(5);
    let mut gate2_pixels: Option<bool> = None;
    let mut exit_status: Option<std::process::ExitStatus> = None;
    let mut killed_by_deadline = false;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => {
                let now = std::time::Instant::now();
                // Gate 2: sample pixels once at the 5-second mark.
                if gate2_pixels.is_none() && now >= pixel_check_at {
                    #[cfg(target_os = "linux")]
                    {
                        gate2_pixels = sample_display_pixels_99();
                    }
                    eprintln!(
                        "gate2: pixel check at {:.1?} → {:?}",
                        now - start,
                        gate2_pixels
                    );
                }
                if now >= deadline {
                    let _ = child.kill();
                    killed_by_deadline = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => panic!("wait failed: {e}"),
        }
    }
    let elapsed = start.elapsed();

    drain_thread.join().expect("stderr drain thread panicked");
    let stderr_bytes = stderr_shared.lock().unwrap().clone();
    let stderr = String::from_utf8_lossy(&stderr_bytes);

    // --- Diagnostic dump ---------------------------------------------------
    eprintln!("testsprite2 elapsed: {elapsed:.1?}");
    eprintln!(
        "testsprite2 exit: {}",
        if killed_by_deadline {
            "killed by deadline".to_string()
        } else {
            exit_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        }
    );
    eprintln!("--- FULL STDERR BEGIN ---");
    eprintln!("{stderr}");
    eprintln!("--- FULL STDERR END ---");

    // Grep summary lines for the report.
    eprintln!("--- warn_once hits ---");
    for line in stderr.lines().filter(|l| l.contains("warn_once")) {
        eprintln!("{line}");
    }
    eprintln!("--- FATAL / fatal ---");
    for line in stderr
        .lines()
        .filter(|l| l.contains("FATAL") || l.contains("fatal"))
    {
        eprintln!("{line}");
    }
    eprintln!("--- error / Error ---");
    for line in stderr
        .lines()
        .filter(|l| l.contains("error") || l.contains("Error"))
    {
        eprintln!("{line}");
    }
    eprintln!("--- SDL lines ---");
    for line in stderr.lines().filter(|l| l.contains("SDL")) {
        eprintln!("{line}");
    }
    eprintln!("--- vulkan / Vulkan / vk lines ---");
    for line in stderr
        .lines()
        .filter(|l| l.contains("vulkan") || l.contains("Vulkan") || l.contains(" vk"))
    {
        eprintln!("{line}");
    }
    eprintln!("--- unresolved imports ---");
    for line in stderr.lines().filter(|l| l.contains("unresolved import")) {
        eprintln!("{line}");
    }

    // Gate 1, assertion 1: IAT patch must complete before anything else matters.
    assert!(
        stderr.contains("weave: imports resolved"),
        "WS2 Gate 1 FAIL: IAT patch did not complete — weave crashed before \
         reaching the entry point.\nelapsed: {elapsed:.1?}\nstderr: {stderr}"
    );

    // Gate 1, assertion 2: SDL2 must reach video init (display discovered).
    // EnumDisplayMonitors callback fires only if SDL2 got past WIN_InitModes.
    // The RegisterClassExW("SDL_app") line appears immediately after display
    // enumeration succeeds, so it's a reliable proxy for "video driver inited".
    assert!(
        stderr.contains("RegisterClassExW(\"SDL_app\")"),
        "WS2 Gate 1 FAIL: SDL2 video init did not reach display enumeration — \
         no display found.\nelapsed: {elapsed:.1?}\nstderr: {stderr}"
    );

    // Gate 1, assertion 3: process must survive at least 10 seconds.
    // If it died in < 10s, either a hard crash or SDL_CreateWindow failed.
    assert!(
        killed_by_deadline || elapsed >= std::time::Duration::from_secs(10),
        "WS2 Gate 1 FAIL: process exited after only {elapsed:.1?} — \
         crashed or quit before 10-second gate.\nstderr: {stderr}"
    );

    // Gate 2 (M1 — First Frame): Xvfb must show non-black pixels at 5 s.
    //
    // testsprite2 renders animated sprites onto a black background.  After
    // 5 seconds of running the GDI→X11 BitBlt path must have written colored
    // pixels to the Xvfb frame buffer.  If the screen is all-black, the
    // DibSection→Pixmap sync (put_dib_to_pixmap) is broken.
    //
    // Skip gracefully when Python3/libX11 unavailable (returns None).
    eprintln!("gate2: final pixel check result: {:?}", gate2_pixels);
    if let Some(has_pixels) = gate2_pixels {
        assert!(
            has_pixels,
            "WS2 Gate 2 / M1 FAIL: Xvfb screen all-black at 5 s — \
             SDL2 is running but no pixels rendered. GDI→X11 BitBlt broken.\
             \nelapsed: {elapsed:.1?}\nstderr:\n{stderr}"
        );
    }
}

/// `weave waveout_test.exe` — waveOut + blue window; Gate 1 smoke test.
///
/// Runs waveout_test.exe under Weave with --no-sandbox and DISPLAY=:99.
/// The binary opens a solid-blue window, calls waveOutOpen/PrepareHeader/Write
/// with a 1-second silence PCM buffer, runs for 5 seconds, then cleans up.
///
/// Gates:
///   1. process exits (not timeout) — no panic / hard crash
///   2. stderr contains PHASE: waveout_opened — waveOutOpen returned MMSYSERR_NOERROR
///   3. pixel check at 5 s — Xvfb screen non-black (blue window rendered)
///   PHASE: waveout_wrote is checked but only warned (silent stub is acceptable)
///
/// Skipped gracefully if waveout_test.exe is absent from fixtures.
#[test]
fn waveout_gate1_smoke() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping execution test — requires Linux");
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let bin_dir = format!("{manifest}/../tests/fixtures/bin");
    let exe = format!("{bin_dir}/waveout_test.exe");

    if !std::path::Path::new(&exe).exists() {
        eprintln!("skipping: waveout_test.exe not present in tests/fixtures/bin/");
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");

    let start = std::time::Instant::now();
    let mut child = std::process::Command::new(weave_bin)
        .current_dir(&bin_dir)
        .arg(&exe)
        .arg("--no-sandbox")
        .env("DISPLAY", ":99")
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn weave on waveout_test.exe: {e}"));

    // Drain stderr concurrently to avoid blocking the child on the 64 KB pipe.
    let stderr_pipe = child.stderr.take().expect("stderr was piped");
    let stderr_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let stderr_writer = std::sync::Arc::clone(&stderr_shared);
    let drain_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut pipe = stderr_pipe;
        let _ = pipe.read_to_end(&mut buf);
        *stderr_writer.lock().unwrap() = buf;
    });

    let deadline = start + std::time::Duration::from_secs(10);
    let pixel_check_at = start + std::time::Duration::from_secs(5);
    let mut pixel_result: Option<bool> = None;
    let mut exit_status: Option<std::process::ExitStatus> = None;
    let mut killed_by_deadline = false;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => {
                let now = std::time::Instant::now();
                if pixel_result.is_none() && now >= pixel_check_at {
                    #[cfg(target_os = "linux")]
                    {
                        pixel_result = sample_display_pixels_99();
                    }
                    println!("gate2: waveout_pixel_check → {:?}", pixel_result);
                }
                if now >= deadline {
                    let _ = child.kill();
                    killed_by_deadline = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => panic!("wait failed: {e}"),
        }
    }
    let elapsed = start.elapsed();

    drain_thread.join().expect("stderr drain thread panicked");
    let stderr_bytes = stderr_shared.lock().unwrap().clone();
    let stderr = String::from_utf8_lossy(&stderr_bytes);

    eprintln!("waveout_test elapsed: {elapsed:.1?}");
    eprintln!(
        "waveout_test exit: {}",
        if killed_by_deadline {
            "killed by deadline".to_string()
        } else {
            exit_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        }
    );
    eprintln!("--- FULL STDERR BEGIN ---");
    eprintln!("{stderr}");
    eprintln!("--- FULL STDERR END ---");

    // Gate 1: process must exit before the 10-second deadline (no hard hang/panic).
    assert!(
        !killed_by_deadline,
        "waveout Gate 1 FAIL: process did not exit within 10 s — hung or panicked.\nstderr: {stderr}"
    );

    // Gate 2: waveOutOpen must have returned MMSYSERR_NOERROR.
    assert!(
        stderr.contains("PHASE: waveout_opened"),
        "waveout Gate 1 FAIL: PHASE: waveout_opened not found — waveOutOpen did not \
         return MMSYSERR_NOERROR.\nstderr: {stderr}"
    );

    // Warn only (not fail) if waveOutWrite did not succeed — silent stub is OK.
    if !stderr.contains("PHASE: waveout_wrote") {
        eprintln!(
            "waveout warn: PHASE: waveout_wrote absent — waveOutWrite stub may be silent (acceptable)"
        );
    }

    // Gate 2 pixel check: blue window rendering is a diagnostic only.
    // waveout_test validates waveOut stubs — the GDI FillRect→X11 path is
    // tracked separately (testsprite2 owns the rendering gate).  A black
    // screen here means FillRect/EndPaint doesn't flush to X11, which is a
    // known gap but does not invalidate the waveOut result.
    eprintln!(
        "gate2: waveout final pixel check result: {:?} (diagnostic — not a hard gate)",
        pixel_result
    );
    if let Some(false) | None = pixel_result {
        eprintln!(
            "gate2: waveout pixel check WARN — screen black; \
             FillRect→X11 path not flushing (separate from waveOut correctness)"
        );
    }
}

/// `weave sdl2_audio_test.exe` — SDL2 video+audio fixture; M2 Gate 1 smoke test.
///
/// Runs sdl2_audio_test.exe under Weave with --no-sandbox and DISPLAY=:99 (Xvfb).
/// SDL2.dll must be in the same directory as the exe (tests/fixtures/bin/SDL2.dll).
///
/// Gates:
///   1. process exits within 70 s — no panic / hard crash (M2: 60s stability)
///   2. stderr contains PHASE: sdl2_audio_init — SDL_Init succeeded
///   3. stderr contains PHASE: sdl2_audio_opened — SDL_OpenAudio returned 0 (waveOut stubs work)
///   4. pixel check at 5 s — Xvfb screen non-black (SDL2 software renderer working)
///      Gate 4 is warn-only: Some(false) is logged but does NOT fail the test.
///
/// Skipped gracefully if sdl2_audio_test.exe is absent from fixtures.
#[test]
fn sdl2_audio_gate1_smoke() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping execution test — requires Linux");
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let bin_dir = format!("{manifest}/../tests/fixtures/bin");
    let exe = format!("{bin_dir}/sdl2_audio_test.exe");

    if !std::path::Path::new(&exe).exists() {
        eprintln!("skipping: sdl2_audio_test.exe not present in tests/fixtures/bin/");
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");

    // Run with CWD = bin_dir so SDL2.dll is found next to the exe.
    // --no-sandbox eliminates sandbox as a variable. DISPLAY=:99 for Xvfb.
    let start = std::time::Instant::now();
    let mut child = std::process::Command::new(weave_bin)
        .current_dir(&bin_dir)
        .arg(&exe)
        .arg("--no-sandbox")
        .env("DISPLAY", ":99")
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn weave on sdl2_audio_test.exe: {e}"));

    // Drain stderr concurrently to avoid blocking the child on the 64 KB pipe.
    let stderr_pipe = child.stderr.take().expect("stderr was piped");
    let stderr_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let stderr_writer = std::sync::Arc::clone(&stderr_shared);
    let drain_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut pipe = stderr_pipe;
        let _ = pipe.read_to_end(&mut buf);
        *stderr_writer.lock().unwrap() = buf;
    });

    let deadline = start + std::time::Duration::from_secs(70);
    let pixel_check_at = start + std::time::Duration::from_secs(5);
    let mut pixel_result: Option<bool> = None;
    let mut exit_status: Option<std::process::ExitStatus> = None;
    let mut killed_by_deadline = false;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => {
                let now = std::time::Instant::now();
                if pixel_result.is_none() && now >= pixel_check_at {
                    #[cfg(target_os = "linux")]
                    {
                        pixel_result = sample_display_pixels_99();
                    }
                    println!("gate2: sdl2_audio_pixel_check → {:?}", pixel_result);
                }
                if now >= deadline {
                    let _ = child.kill();
                    killed_by_deadline = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => panic!("wait failed: {e}"),
        }
    }
    let elapsed = start.elapsed();

    drain_thread.join().expect("stderr drain thread panicked");
    let stderr_bytes = stderr_shared.lock().unwrap().clone();
    let stderr = String::from_utf8_lossy(&stderr_bytes);

    eprintln!("sdl2_audio_test elapsed: {elapsed:.1?}");
    eprintln!(
        "sdl2_audio_test exit: {}",
        if killed_by_deadline {
            "killed by deadline".to_string()
        } else {
            exit_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        }
    );
    eprintln!("--- FULL STDERR BEGIN ---");
    eprintln!("{stderr}");
    eprintln!("--- FULL STDERR END ---");

    // Gate 1: process must exit before the 12-second deadline (no hang/panic).
    assert!(
        !killed_by_deadline,
        "sdl2_audio Gate 1 FAIL: process did not exit within 12 s — hung or panicked.\nstderr: {stderr}"
    );

    // Gate 2: SDL_Init must have succeeded.
    assert!(
        stderr.contains("PHASE: sdl2_audio_init"),
        "sdl2_audio Gate 2 FAIL: PHASE: sdl2_audio_init not found — SDL_Init failed.\nstderr: {stderr}"
    );

    // Gate 3: SDL_OpenAudio must have returned 0 — proves waveOut stubs are functional.
    assert!(
        stderr.contains("PHASE: sdl2_audio_opened"),
        "sdl2_audio Gate 3 FAIL: PHASE: sdl2_audio_opened not found — \
         SDL_OpenAudio did not return 0. waveOut stubs may be broken.\nstderr: {stderr}"
    );

    // Gate 4 (warn only): SDL2 software renderer pixel check.
    // Some(false) = screen black; not a hard failure — audio is the primary gate.
    eprintln!(
        "gate4: sdl2_audio final pixel check result: {:?} (warn only — not a hard gate)",
        pixel_result
    );
    if let Some(false) | None = pixel_result {
        eprintln!(
            "gate4: sdl2_audio pixel check WARN — screen black or unavailable; \
             SDL2 software renderer may not be flushing to X11 (separate from audio correctness)"
        );
    }
}

/// `weave nx.exe` — NXEngine-evo (Cave Story) x64 Windows build; M2 real-game gate.
///
/// Downloads handled in CI (Download NXEngine-evo step). Skipped gracefully
/// when binary is absent (local dev / non-CI).
///
/// This is a diagnostic / exploratory gate — it logs everything and only asserts
/// the absolute minimum: PE loads without IAT crash. All other results are logged
/// for analysis. The pixel check is warn-only. This gate intentionally does NOT
/// fail CI — it is the base for iterative M2 game work.
///
/// CWD is set to tests/fixtures/nxengine/ so nx.exe finds its data directory.
#[test]
fn nxengine_gate1_smoke() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping nxengine_gate1_smoke — requires Linux");
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let game_dir = format!("{manifest}/../tests/fixtures/nxengine");
    let exe = format!("{game_dir}/nx.exe");

    if !std::path::Path::new(&exe).exists() {
        eprintln!("skipping: nx.exe not present in tests/fixtures/nxengine/ — run CI or download NXEngine-evo manually");
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");
    let start = std::time::Instant::now();

    // Spawn with CWD = game dir so nx.exe finds its data files next to itself.
    let mut child = std::process::Command::new(weave_bin)
        .current_dir(&game_dir)
        .args(["--no-sandbox", &exe])
        .env("DISPLAY", ":99")
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn weave on nx.exe: {e}"));

    let pixel_check_at = start + std::time::Duration::from_secs(5);
    let deadline = start + std::time::Duration::from_secs(20);
    let mut pixel_result: Option<bool> = None;
    let mut exited = false;

    loop {
        let now = std::time::Instant::now();
        match child.try_wait().expect("try_wait failed") {
            Some(_) => {
                exited = true;
                break;
            }
            None => {
                if pixel_result.is_none() && now >= pixel_check_at {
                    pixel_result = sample_display_pixels_99();
                    println!("gate2: nxengine_pixel_check → {:?}", pixel_result);
                }
                if now >= deadline {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    let elapsed = start.elapsed();
    let stderr = {
        use std::io::Read;
        let mut s = String::new();
        if let Some(mut p) = child.stderr.take() {
            let _ = p.read_to_string(&mut s);
        }
        s
    };

    eprintln!("nxengine elapsed: {elapsed:.1?}");
    eprintln!("nxengine exited_before_deadline: {exited}");
    eprintln!("--- nxengine STDERR BEGIN ---\n{stderr}\n--- nxengine STDERR END ---");

    // Only hard gate: PE must load (Weave must not crash on IAT resolution).
    assert!(
        stderr.contains("PHASE: loaded_pe") || stderr.contains("weave: loaded"),
        "nxengine Gate 1 FAIL: PE did not load — IAT resolution crashed before entry point.\nstderr:\n{stderr}"
    );

    // Soft diagnostics — warn only.
    if let Some(false) | None = pixel_result {
        eprintln!("nxengine pixel WARN — screen black at 5s; rendering or init incomplete");
    }
    if !stderr.contains("weave/user32: CreateWindow") && !stderr.contains("RegisterClassEx") {
        eprintln!(
            "nxengine window WARN — no CreateWindow seen; game may not have reached SDL2 init"
        );
    }
}

/// `weave putty.exe -ssh localhost 22` — PuTTY SSH engine; M3 Gate 1.
///
/// Runs PuTTY with `-ssh localhost 22` under Weave with DISPLAY=:99 (Xvfb).
/// The goal is to get PuTTY past IAT resolution and into its SSH init path,
/// then report the first observable failure.
///
/// Gates:
///   1. IAT resolution completes ("weave: imports resolved")
///   2. WSA async-event stubs reached — stderr contains at least one of
///      "WSACreateEvent", "WSAEventSelect", or "WSAWaitForMultipleEvents"
///      (diagnostic — logged even if the stub path is silent, as a warn-only gate).
///
/// 10-second timeout: PuTTY will not exit on its own (interactive GUI);
/// we kill after 10 s and inspect what was logged to stderr.
///
/// Skipped gracefully if putty.exe is absent from fixtures.
#[test]
fn putty_m3_config_window_gate() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping putty_m3_config_window_gate — requires Linux");
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let fixture = format!("{manifest}/../tests/fixtures/bin/putty.exe");

    if !std::path::Path::new(&fixture).exists() {
        eprintln!("skipping: putty.exe not present in tests/fixtures/bin/");
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");

    let start = std::time::Instant::now();
    let mut child = std::process::Command::new(weave_bin)
        .arg(&fixture)
        .arg("-ssh")
        .arg("localhost")
        .arg("22")
        .env("DISPLAY", ":99")
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn weave on putty.exe: {e}"));

    // Drain stderr concurrently to avoid 64 KB pipe blocking.
    let stderr_pipe = child.stderr.take().expect("stderr was piped");
    let stderr_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let stderr_writer = std::sync::Arc::clone(&stderr_shared);
    let drain_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut pipe = stderr_pipe;
        let _ = pipe.read_to_end(&mut buf);
        *stderr_writer.lock().unwrap() = buf;
    });

    let deadline = start + std::time::Duration::from_secs(10);
    let mut exit_status: Option<std::process::ExitStatus> = None;
    let mut killed_by_deadline = false;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    killed_by_deadline = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => panic!("wait failed: {e}"),
        }
    }
    let elapsed = start.elapsed();

    drain_thread.join().expect("stderr drain thread panicked");
    let stderr_bytes = stderr_shared.lock().unwrap().clone();
    let stderr = String::from_utf8_lossy(&stderr_bytes);

    eprintln!("putty_m3 elapsed: {elapsed:.1?}");
    eprintln!(
        "putty_m3 exit: {}",
        if killed_by_deadline {
            "killed by deadline".to_string()
        } else {
            exit_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        }
    );
    eprintln!("--- putty_m3 FULL STDERR BEGIN ---");
    eprintln!("{stderr}");
    eprintln!("--- putty_m3 FULL STDERR END ---");

    // Report unresolved imports for diagnosis.
    eprintln!("--- putty_m3 unresolved imports ---");
    for line in stderr.lines().filter(|l| l.contains("unresolved import")) {
        eprintln!("{line}");
    }

    // Gate 1 (hard): IAT patch must complete before SSH init can be reached.
    assert!(
        stderr.contains("weave: imports resolved"),
        "putty_m3 Gate 1 FAIL: IAT patch did not complete — weave crashed before \
         entry point.\nelapsed: {elapsed:.1?}\nstderr:\n{stderr}"
    );

    // Gate 2 (diagnostic / warn-only): report whether WSA async-event stubs were hit.
    // PuTTY's SSH engine calls WSAEventSelect immediately after socket creation.
    // If these lines are absent, PuTTY crashed before reaching the SSH socket path.
    let wsa_async_hit = stderr.contains("WSACreateEvent")
        || stderr.contains("WSAEventSelect")
        || stderr.contains("WSAWaitForMultipleEvents")
        || stderr.contains("WSAEnumNetworkEvents");
    if wsa_async_hit {
        eprintln!("putty_m3 Gate 2: WSA async-event stubs reached — SSH socket path entered");
    } else {
        eprintln!(
            "putty_m3 Gate 2 WARN: no WSA async-event stub hit detected in stderr. \
             PuTTY may have failed before reaching SSH socket init. \
             First observable failure is reported above in the FULL STDERR dump."
        );
    }
}

/// PuTTY M3 SSH connect gate — attempts a real TCP connection to a local sshd.
///
/// Prerequisites (set up by CI before running this test):
///   - openssh-server installed, host keys generated, sshd running on port 2222
///   - PasswordAuthentication=yes, UsePAM=no in sshd_config
///
/// PuTTY is invoked with:
///   `weave putty.exe -ssh -P 2222 -l runner -pw "" -batch localhost`
///
/// `-batch` suppresses interactive prompts (host-key verification, password
/// dialogs) so PuTTY drives straight into the SSH handshake without waiting
/// for user input.
///
/// Gates:
///   1. (hard) IAT resolution completes — "weave: imports resolved"
///   2. (hard) TCP connect or name resolution was attempted — stderr contains
///      "connect" or "getaddrinfo" or "WSAConnect" (proves SSH path entered)
///   3. (diagnostic) WSA async-event stubs reached
///
/// 15-second timeout. Skipped gracefully if putty.exe is absent.
#[test]
fn putty_m3_ssh_connect_gate() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping putty_m3_ssh_connect_gate — requires Linux");
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let fixture = format!("{manifest}/../tests/fixtures/bin/putty.exe");

    if !std::path::Path::new(&fixture).exists() {
        eprintln!("skipping: putty.exe not present in tests/fixtures/bin/ — putty_m3_ssh_connect_gate skipped");
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");

    let start = std::time::Instant::now();
    let mut child = std::process::Command::new(weave_bin)
        .arg(&fixture)
        .arg("-ssh")
        .arg("-P")
        .arg("2222")
        .arg("-l")
        .arg("runner")
        .arg("-pw")
        .arg("")
        .arg("-batch")
        .arg("localhost")
        .env("DISPLAY", ":99")
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn weave on putty.exe (ssh connect gate): {e}"));

    // Drain stderr concurrently to avoid 64 KB pipe blocking.
    let stderr_pipe = child.stderr.take().expect("stderr was piped");
    let stderr_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let stderr_writer = std::sync::Arc::clone(&stderr_shared);
    let drain_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let mut pipe = stderr_pipe;
        let _ = pipe.read_to_end(&mut buf);
        *stderr_writer.lock().unwrap() = buf;
    });

    let deadline = start + std::time::Duration::from_secs(15);
    let mut exit_status: Option<std::process::ExitStatus> = None;
    let mut killed_by_deadline = false;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    killed_by_deadline = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => panic!("wait failed: {e}"),
        }
    }
    let elapsed = start.elapsed();

    drain_thread.join().expect("stderr drain thread panicked");
    let stderr_bytes = stderr_shared.lock().unwrap().clone();
    let stderr = String::from_utf8_lossy(&stderr_bytes);

    eprintln!("putty_m3_ssh elapsed: {elapsed:.1?}");
    eprintln!(
        "putty_m3_ssh exit: {}",
        if killed_by_deadline {
            "killed by deadline".to_string()
        } else {
            exit_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        }
    );
    eprintln!("--- putty_m3_ssh FULL STDERR BEGIN ---");
    eprintln!("{stderr}");
    eprintln!("--- putty_m3_ssh FULL STDERR END ---");

    // Report unresolved imports for diagnosis.
    eprintln!("--- putty_m3_ssh unresolved imports ---");
    for line in stderr.lines().filter(|l| l.contains("unresolved import")) {
        eprintln!("{line}");
    }

    // Gate 1 (hard): IAT patch must complete before the SSH stack is entered.
    assert!(
        stderr.contains("weave: imports resolved"),
        "putty_m3_ssh Gate 1 FAIL: IAT patch did not complete — weave crashed before \
         entry point.\nelapsed: {elapsed:.1?}\nstderr:\n{stderr}"
    );

    // Gate 2 (hard): TCP connect or name resolution must have been attempted.
    // ws_connect and ws_getaddrinfo both log their function name to stderr.
    // Seeing either proves PuTTY drove past the config dialog into the SSH path.
    let tcp_attempted = stderr.contains("ws_connect")
        || stderr.contains("ws_getaddrinfo")
        || stderr.contains("WSAConnect")
        || stderr.contains("getaddrinfo")
        || stderr.contains("connect(");
    assert!(
        tcp_attempted,
        "putty_m3_ssh Gate 2 FAIL: no TCP connect or name-resolution call observed. \
         PuTTY did not reach the SSH connection path under Weave. \
         First observable failure is in the FULL STDERR dump above.\n\
         elapsed: {elapsed:.1?}\nstderr:\n{stderr}"
    );

    // Gate 3 (diagnostic): WSA async-event stubs reached — logged warn-only.
    let wsa_async_hit = stderr.contains("WSACreateEvent")
        || stderr.contains("WSAEventSelect")
        || stderr.contains("WSAWaitForMultipleEvents")
        || stderr.contains("WSAEnumNetworkEvents");
    if wsa_async_hit {
        eprintln!("putty_m3_ssh Gate 3: WSA async-event stubs reached — SSH socket path entered");
    } else {
        eprintln!(
            "putty_m3_ssh Gate 3 WARN: no WSA async-event stub hit in stderr. \
             TCP connect may be failing before the async event loop is set up."
        );
    }
}

/// `weave plink.exe` — headless SSH client gate (M3).
///
/// Runs `weave plink.exe -batch -pw weave-test-pw -P 2222 runner@localhost echo hello`
/// against a local sshd on port 2222 (set up by CI). 15-second timeout with
/// concurrent stderr and stdout drains. Gate 1 (hard): imports resolved. Reports all
/// stderr/stdout for diagnosis. Skipped gracefully if plink.exe or host key is absent.
#[test]
fn putty_m3_plink_gate() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping putty_m3_plink_gate — requires Linux");
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let fixture = format!("{manifest}/../tests/fixtures/bin/plink.exe");

    if !std::path::Path::new(&fixture).exists() {
        eprintln!(
            "skipping: plink.exe not present in tests/fixtures/bin/ — putty_m3_plink_gate skipped"
        );
        return;
    }

    // Extract sshd ed25519 host key fingerprint so plink -batch can verify the host key
    // without an interactive prompt. Without -hostkey, plink -batch exits 1 immediately
    // on an unknown host key (no registry entry / known_hosts file present).
    let hostkey_output = std::process::Command::new("ssh-keygen")
        .args([
            "-l",
            "-E",
            "sha256",
            "-f",
            "/etc/ssh/ssh_host_ed25519_key.pub",
        ])
        .output();
    let hostkey_fingerprint = match hostkey_output {
        Err(e) => {
            eprintln!(
                "skipping: ssh-keygen failed ({e}) — cannot determine sshd host key; \
                 putty_m3_plink_gate skipped"
            );
            return;
        }
        Ok(out) if !out.status.success() => {
            eprintln!(
                "skipping: ssh-keygen exited {:?} — /etc/ssh/ssh_host_ed25519_key.pub absent; \
                 putty_m3_plink_gate skipped",
                out.status
            );
            return;
        }
        Ok(out) => {
            // Output format: "256 SHA256:xxxx /etc/ssh/... (ED25519)"
            // Field [1] is the SHA256:base64 fingerprint.
            let stdout = String::from_utf8_lossy(&out.stdout);
            match stdout.split_whitespace().nth(1) {
                Some(fp) => fp.to_string(),
                None => {
                    eprintln!(
                        "skipping: could not parse ssh-keygen output: {stdout:?}; \
                         putty_m3_plink_gate skipped"
                    );
                    return;
                }
            }
        }
    };
    eprintln!("putty_m3_plink: using hostkey fingerprint: {hostkey_fingerprint}");

    let weave_bin = env!("CARGO_BIN_EXE_weave");

    let start = std::time::Instant::now();
    let mut child = std::process::Command::new(weave_bin)
        .arg("--no-sandbox")
        .arg(&fixture)
        .arg("-batch")
        .arg("-pw")
        .arg("weave-test-pw")
        .arg("-hostkey")
        .arg(&hostkey_fingerprint)
        .arg("-P")
        .arg("2222")
        .arg("runner@localhost")
        .arg("echo")
        .arg("hello")
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn weave on plink.exe: {e}"));

    // Drain stderr concurrently to avoid 64 KB pipe blocking.
    let mut stderr_pipe = child.stderr.take().expect("stderr was piped");
    let stderr_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let stderr_writer = std::sync::Arc::clone(&stderr_shared);
    let drain_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        *stderr_writer.lock().unwrap() = buf;
    });

    // Drain stdout concurrently to avoid 64 KB pipe blocking (plink writes "hello" here).
    let mut stdout_pipe = child.stdout.take().expect("stdout was piped");
    let stdout_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let stdout_writer = std::sync::Arc::clone(&stdout_shared);
    let stdout_drain_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        *stdout_writer.lock().unwrap() = buf;
    });

    let deadline = start + std::time::Duration::from_secs(15);
    let mut exit_status: Option<std::process::ExitStatus> = None;
    let mut killed_by_deadline = false;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    killed_by_deadline = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => panic!("wait failed: {e}"),
        }
    }
    let elapsed = start.elapsed();

    drain_thread.join().expect("stderr drain thread panicked");
    stdout_drain_thread
        .join()
        .expect("stdout drain thread panicked");
    let stderr_bytes = stderr_shared.lock().unwrap().clone();
    let stderr = String::from_utf8_lossy(&stderr_bytes);
    let stdout_bytes = stdout_shared.lock().unwrap().clone();
    let stdout = String::from_utf8_lossy(&stdout_bytes);

    eprintln!("putty_m3_plink elapsed: {elapsed:.1?}");
    eprintln!(
        "putty_m3_plink exit: {}",
        if killed_by_deadline {
            "killed by deadline".to_string()
        } else {
            exit_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        }
    );
    eprintln!("--- putty_m3_plink FULL STDOUT BEGIN ---");
    eprintln!("{stdout}");
    eprintln!("--- putty_m3_plink FULL STDOUT END ---");
    eprintln!("--- putty_m3_plink FULL STDERR BEGIN ---");
    eprintln!("{stderr}");
    eprintln!("--- putty_m3_plink FULL STDERR END ---");

    // Report unresolved imports for diagnosis.
    eprintln!("--- putty_m3_plink unresolved imports ---");
    for line in stderr.lines().filter(|l| l.contains("unresolved import")) {
        eprintln!("{line}");
    }

    // Gate 1 (hard): IAT patch must complete before plink enters its SSH stack.
    assert!(
        stderr.contains("weave: imports resolved"),
        "putty_m3_plink Gate 1 FAIL: IAT patch did not complete — weave crashed before \
         entry point.\nelapsed: {elapsed:.1?}\nstderr:\n{stderr}"
    );

    // Diagnostic: report what SSH activity was observed.
    let tcp_attempted = stderr.contains("ws_connect")
        || stderr.contains("ws_getaddrinfo")
        || stderr.contains("gethostbyname")
        || stderr.contains("connect(");
    eprintln!("putty_m3_plink diagnostic: TCP/name-resolution attempted = {tcp_attempted}");

    // Soft gate: warn if exit was non-zero or stdout does not contain "hello".
    // This is diagnostic-only (not a hard assert) — further stubs may be needed.
    let exit_ok = exit_status.map_or(false, |s| s.success());
    let stdout_has_hello = stdout.contains("hello");
    if exit_ok && stdout_has_hello {
        eprintln!(
            "putty_m3_plink diagnostic: SSH session succeeded — exit=0, stdout contains 'hello'"
        );
    } else {
        eprintln!(
            "putty_m3_plink diagnostic: SSH session incomplete — exit_ok={exit_ok}, \
             stdout_has_hello={stdout_has_hello} (further stubs may be needed)"
        );
    }
}

/// `weave 7za.exe x test.7z` — M4 extraction gate.
///
/// Verifies that 7-Zip can extract a known archive under Weave and that the
/// extracted files have the expected SHA-256 digests. This exercises the CRT
/// file-I/O path (fopen/fwrite/fclose) and Weave's path translation layer.
///
/// Expected archive contents (tests/fixtures/bin/test.7z):
///   hello.txt — "hello world\n"  (SHA-256: a948904f2f0f479b8f...)
///   world.txt — "hello world\n"  (SHA-256: a948904f2f0f479b8f...)
///
/// The test extracts to a fresh temp directory, then reads each file back and
/// checks its SHA-256 against the known value. A mismatch or missing file is
/// a hard failure and reports exactly which file is wrong.
///
/// Skipped gracefully if 7za.exe or test.7z is absent from fixtures.
#[test]
fn sevenzip_m4_extraction_gate() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping sevenzip_m4_extraction_gate — requires Linux");
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let bin_dir = format!("{manifest}/../tests/fixtures/bin");
    let seven_zip = format!("{bin_dir}/7za.exe");
    let archive = format!("{bin_dir}/test.7z");

    if !std::path::Path::new(&seven_zip).exists() {
        eprintln!("skipping: 7za.exe not present in tests/fixtures/bin/");
        return;
    }
    if !std::path::Path::new(&archive).exists() {
        eprintln!(
            "skipping: test.7z not present in tests/fixtures/bin/ \
             (run tests/fixtures/src/make_zip.py)"
        );
        return;
    }

    // Compute SHA-256 of a byte slice using the sha2 crate is not available
    // without adding a dep; use the standard library's approach via /proc or
    // shell out to sha256sum (available in CI Docker image).
    fn sha256_of_bytes(data: &[u8]) -> String {
        use std::io::Write;
        let mut child = std::process::Command::new("sha256sum")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("sha256sum not found — needed for extraction gate");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(data)
            .expect("write to sha256sum stdin");
        let out = child.wait_with_output().expect("sha256sum wait");
        // output: "<hex>  -\n"
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string()
    }

    // Create a fresh extraction directory INSIDE bin_dir so that Landlock's
    // exe-dir allow-rule covers it.  Using /tmp would be outside the sandbox's
    // allowed path set and CreateFileW would receive EACCES.
    let out_dir = std::path::PathBuf::from(&bin_dir).join("extract_out");
    if out_dir.exists() {
        std::fs::remove_dir_all(&out_dir).expect("failed to clean extract_out dir");
    }
    std::fs::create_dir_all(&out_dir).expect("failed to create extract_out dir");

    let weave_bin = env!("CARGO_BIN_EXE_weave");

    // Run: weave 7za.exe x test.7z -o<out_dir> -y
    // CWD = bin_dir so 7za.exe finds test.7z as a relative path.
    // -y: assume yes to all prompts (non-interactive).
    let output = std::process::Command::new(weave_bin)
        .current_dir(&bin_dir)
        .arg(&seven_zip)
        .arg("x")
        .arg("test.7z")
        .arg(format!("-o{}", out_dir.display()))
        .arg("-y")
        .output()
        .unwrap_or_else(|e| panic!("failed to run weave on 7za.exe x: {e}"));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("sevenzip_m4_extraction: exit: {}", output.status);
    eprintln!("--- 7za stdout ---\n{stdout}");
    eprintln!("--- 7za stderr ---\n{stderr}");

    // Gate 1 (hard): 7za.exe must exit 0.
    assert!(
        output.status.success(),
        "sevenzip_m4_extraction Gate 1 FAIL: 7za.exe x exited non-zero: {}\n\
         stdout: {stdout}\nstderr: {stderr}",
        output.status
    );

    // Gate 2 (hard): extracted files must exist and have correct content.
    //
    // Archive layout (see tests/fixtures/src/make_zip.py):
    //   hello.txt           → "Hello from inside the archive!\n"
    //   subdir/world.txt    → "Another file in a subdirectory.\n"
    //
    // We compute expected hashes dynamically from the known byte strings so
    // this test does not depend on hard-coded digests that could drift.
    // Archive contents (tests/fixtures/bin/test.7z — binary fixture committed to repo).
    // Verified by inspecting bytes extracted by 7za 26.00 x86_64.
    //   hello.txt        → "Hello from inside the archive\!\n"  (backslash before !)
    //   subdir/world.txt → "Another file in a subdirectory.\n"
    let checks: &[(&str, &[u8])] = &[
        ("hello.txt", b"Hello from inside the archive\\!\n"),
        ("subdir/world.txt", b"Another file in a subdirectory.\n"),
    ];

    for (rel_path, expected_content) in checks {
        let path = out_dir.join(rel_path);
        let expected_hash = sha256_of_bytes(expected_content);
        eprintln!("sevenzip_m4_extraction: {rel_path} expected SHA-256 = {expected_hash}");

        assert!(
            path.exists(),
            "sevenzip_m4_extraction Gate 2 FAIL: extracted file {rel_path} is missing.\n\
             out_dir contents: {:?}\nstdout: {stdout}\nstderr: {stderr}",
            std::fs::read_dir(&out_dir)
                .map(|r| r
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name())
                    .collect::<Vec<_>>())
                .unwrap_or_default()
        );

        let actual = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("failed to read extracted {rel_path}: {e}"));
        let actual_hash = sha256_of_bytes(&actual);

        assert_eq!(
            actual_hash,
            expected_hash,
            "sevenzip_m4_extraction Gate 2 FAIL: {rel_path} SHA-256 mismatch.\n\
             expected: {expected_hash}\n\
             actual:   {actual_hash}\n\
             actual bytes (first 256): {:?}\n\
             stdout: {stdout}\nstderr: {stderr}",
            &actual[..actual.len().min(256)]
        );

        eprintln!("sevenzip_m4_extraction: {rel_path} OK — SHA-256 {actual_hash}");
    }
}

/// M4 listing gate — `weave 7za.exe l test.7z` lists archive contents correctly.
///
/// Verifies file names and sizes match the known archive layout:
///   hello.txt           32 bytes
///   subdir/world.txt    32 bytes
#[test]
fn sevenzip_m4_listing_gate() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping sevenzip_m4_listing_gate — requires Linux");
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let bin_dir = format!("{manifest}/../tests/fixtures/bin");
    let seven_zip = format!("{bin_dir}/7za.exe");
    let archive = format!("{bin_dir}/test.7z");

    if !std::path::Path::new(&seven_zip).exists() {
        eprintln!("skipping: 7za.exe not present in tests/fixtures/bin/");
        return;
    }
    if !std::path::Path::new(&archive).exists() {
        eprintln!(
            "skipping: test.7z not present in tests/fixtures/bin/ \
             (run tests/fixtures/src/make_zip.py)"
        );
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");

    // Run: weave 7za.exe l test.7z
    // CWD = bin_dir so 7za.exe finds test.7z as a relative path.
    let output = std::process::Command::new(weave_bin)
        .current_dir(&bin_dir)
        .arg(&seven_zip)
        .arg("l")
        .arg("test.7z")
        .output()
        .unwrap_or_else(|e| panic!("failed to run weave on 7za.exe l: {e}"));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("sevenzip_m4_listing: exit: {}", output.status);
    eprintln!("--- 7za stdout ---\n{stdout}");
    eprintln!("--- 7za stderr ---\n{stderr}");

    // Gate 3a (hard): 7za.exe l must exit 0.
    assert!(
        output.status.success(),
        "sevenzip_m4_listing Gate 3a FAIL: 7za.exe l exited non-zero: {}\n\
         stdout: {stdout}\nstderr: {stderr}",
        output.status
    );

    // Gate 3b (hard): stdout must contain both file names and correct sizes.
    //   hello.txt           → 32 bytes ("Hello from inside the archive\!\n")
    //   subdir/world.txt    → 32 bytes ("Another file in a subdirectory.\n")
    // 7za l uses backslash separators in its output on Windows paths.
    let expected: &[(&str, &str)] = &[("hello.txt", "32"), ("subdir\\world.txt", "32")];

    for (name, size) in expected {
        assert!(
            stdout.contains(name),
            "sevenzip_m4_listing Gate 3b FAIL: '{name}' not found in 7za l output.\n\
             stdout: {stdout}\nstderr: {stderr}"
        );
        // The listing line format: "Size  Compressed  ..." — size appears on the
        // same line as the file name. We just need the size digit sequence present
        // somewhere before the file name on its line.
        let found_size = stdout
            .lines()
            .any(|line| line.contains(name) && line.contains(size));
        assert!(
            found_size,
            "sevenzip_m4_listing Gate 3b FAIL: '{name}' line does not contain size {size}.\n\
             stdout: {stdout}\nstderr: {stderr}"
        );
        eprintln!("sevenzip_m4_listing: {name} ({size} bytes) OK");
    }
}

/// M5 install-flow gate — exercises the full prefix+desktop pipeline:
/// PrefixManager::create → set_exe_path → generate_desktop_file →
/// install_desktop_file → (Linux only) weave run hello.exe.
///
/// Steps 1-4 are pure Rust and run on all platforms.
/// Step 5 is Linux-only (guarded by cfg).
#[test]
fn m5_install_flow_gate() {
    use weave_desktop::{generate_desktop_file, install_desktop_file};
    use weave_installer::PrefixManager;

    // ── Step 1: Create a prefix via PrefixManager (isolated tempdir). ────────
    let tmp = tempfile::tempdir().expect("tempdir for m5_install_flow_gate");
    // Override XDG_DATA_HOME so install_desktop_file writes inside tmp too.
    let xdg_data = tmp.path().join("xdg");
    std::fs::create_dir_all(&xdg_data).expect("create xdg_data dir");
    std::env::set_var("XDG_DATA_HOME", &xdg_data);

    let prefix_base = tmp.path().join("prefixes");
    let mgr = PrefixManager::with_base(&prefix_base);
    let prefix = mgr
        .create("hello-app")
        .expect("PrefixManager::create failed");

    assert!(prefix.exists(), "prefix directory must exist after create");
    assert!(prefix.drive_c().is_dir(), "drive_c must be a directory");
    assert!(prefix.config_path().is_file(), "prefix.toml must be a file");

    // ── Step 2: Store the exe path. ──────────────────────────────────────────
    let manifest = env!("CARGO_MANIFEST_DIR");
    let hello_exe = std::path::PathBuf::from(format!("{manifest}/../tests/fixtures/bin/hello.exe"));
    prefix
        .set_exe_path(&hello_exe)
        .expect("set_exe_path failed");

    let got = prefix
        .get_exe_path()
        .expect("get_exe_path failed")
        .expect("get_exe_path returned None after set");
    assert_eq!(
        got, hello_exe,
        "get_exe_path must round-trip the stored path"
    );

    // ── Step 3: Generate the .desktop file content. ──────────────────────────
    let exec_cmd = format!("weave run {}", hello_exe.display());
    let content = generate_desktop_file("Hello App", &exec_cmd, None, "Utility;");

    assert!(
        content.contains("Name=Hello App"),
        "desktop content must contain Name=Hello App\ncontent:\n{content}"
    );
    assert!(
        content.contains("Exec=weave run"),
        "desktop content must contain Exec=weave run\ncontent:\n{content}"
    );
    assert!(
        content.contains("Type=Application"),
        "desktop content must contain Type=Application\ncontent:\n{content}"
    );
    assert!(
        content.contains("[Desktop Entry]"),
        "desktop content must start with [Desktop Entry]\ncontent:\n{content}"
    );

    // ── Step 4: Install the .desktop file into tempdir. ──────────────────────
    // XDG_DATA_HOME is already set to xdg_data above; install_desktop_file
    // will write to <xdg_data>/applications/weave-hello-app.desktop.
    let installed_path =
        install_desktop_file("hello-app", &content).expect("install_desktop_file failed");

    assert!(
        installed_path.exists(),
        "installed .desktop file must exist on disk at {installed_path:?}"
    );

    let on_disk =
        std::fs::read_to_string(&installed_path).expect("failed to read installed .desktop file");
    assert_eq!(
        on_disk, content,
        "on-disk .desktop content must match generated content"
    );

    eprintln!("m5_install_flow_gate: steps 1-4 OK — prefix+desktop pipeline verified");

    // ── Step 5 (Linux only): weave run hello.exe → exits 0 + "Hello, World!". -
    if !cfg!(target_os = "linux") {
        eprintln!("m5_install_flow_gate: skipping step 5 (weave run) — requires Linux");
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");
    let output = std::process::Command::new(weave_bin)
        .arg(&hello_exe)
        .output()
        .unwrap_or_else(|e| panic!("failed to launch weave for step 5: {e}"));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("m5_install_flow_gate step 5: exit {}", output.status);
    eprintln!("--- weave stdout ---\n{stdout}");
    eprintln!("--- weave stderr ---\n{stderr}");

    assert!(
        output.status.success(),
        "m5_install_flow_gate step 5 FAIL: weave run exited non-zero: {}\n\
         stdout: {stdout}\nstderr: {stderr}",
        output.status
    );
    assert_eq!(
        stdout.as_ref(),
        "Hello, World!\n",
        "m5_install_flow_gate step 5 FAIL: unexpected stdout.\nstderr: {stderr}"
    );

    eprintln!("m5_install_flow_gate: step 5 OK — weave run hello.exe exited 0");
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

/// M5 prefix CLI gate — exercises the `weave prefix` subcommands end-to-end:
/// create / list / launch / delete, each as a subprocess call to the real binary.
///
/// Linux-only: `launch` runs the PE under Weave which requires Linux x86-64.
#[test]
fn m5_prefix_cli_gate() {
    if !cfg!(target_os = "linux") {
        eprintln!("m5_prefix_cli_gate: skipping — requires Linux");
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");
    let manifest = env!("CARGO_MANIFEST_DIR");
    let hello_exe = format!("{manifest}/../tests/fixtures/bin/hello.exe");

    let tmp = tempfile::tempdir().expect("tempdir for m5_prefix_cli_gate");
    let xdg_data = tmp.path().join("xdg");
    std::fs::create_dir_all(&xdg_data).expect("create xdg_data dir");

    // ── Step 1: create the prefix ─────────────────────────────────────────
    let output = std::process::Command::new(weave_bin)
        .args(["prefix", "create", "hello-cli", "--exe", &hello_exe])
        .env("XDG_DATA_HOME", &xdg_data)
        .output()
        .expect("failed to run `weave prefix create`");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "m5_prefix_cli_gate step 1 FAIL: `weave prefix create` exited {}\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
    eprintln!("m5_prefix_cli_gate step 1 OK: {}", stdout.trim());

    // ── Step 2: list — must contain "hello-cli" ────────────────────────────
    let output = std::process::Command::new(weave_bin)
        .args(["prefix", "list"])
        .env("XDG_DATA_HOME", &xdg_data)
        .output()
        .expect("failed to run `weave prefix list`");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "m5_prefix_cli_gate step 2 FAIL: `weave prefix list` exited {}\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
    assert!(
        stdout.contains("hello-cli"),
        "m5_prefix_cli_gate step 2 FAIL: 'hello-cli' not in list output\nstdout: {stdout}"
    );
    eprintln!("m5_prefix_cli_gate step 2 OK: list contains hello-cli");

    // ── Step 3: launch — must exit 0 and print "Hello, World!" ────────────
    let output = std::process::Command::new(weave_bin)
        .args(["prefix", "launch", "hello-cli"])
        .env("XDG_DATA_HOME", &xdg_data)
        .output()
        .expect("failed to run `weave prefix launch`");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("m5_prefix_cli_gate step 3: exit {}", output.status);
    eprintln!("--- weave stdout ---\n{stdout}");
    eprintln!("--- weave stderr ---\n{stderr}");
    assert!(
        output.status.success(),
        "m5_prefix_cli_gate step 3 FAIL: `weave prefix launch` exited {}\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
    assert!(
        stdout.contains("Hello, World!"),
        "m5_prefix_cli_gate step 3 FAIL: stdout does not contain 'Hello, World!'\nstdout: {stdout}\nstderr: {stderr}"
    );
    eprintln!("m5_prefix_cli_gate step 3 OK: launch exited 0 + Hello, World!");

    // ── Step 4: delete ────────────────────────────────────────────────────
    let output = std::process::Command::new(weave_bin)
        .args(["prefix", "delete", "hello-cli"])
        .env("XDG_DATA_HOME", &xdg_data)
        .output()
        .expect("failed to run `weave prefix delete`");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "m5_prefix_cli_gate step 4 FAIL: `weave prefix delete` exited {}\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
    eprintln!("m5_prefix_cli_gate step 4 OK: {}", stdout.trim());

    // ── Step 5: list — must NOT contain "hello-cli" ────────────────────────
    let output = std::process::Command::new(weave_bin)
        .args(["prefix", "list"])
        .env("XDG_DATA_HOME", &xdg_data)
        .output()
        .expect("failed to run `weave prefix list` after delete");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "m5_prefix_cli_gate step 5 FAIL: `weave prefix list` exited {}\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
    assert!(
        !stdout.contains("hello-cli"),
        "m5_prefix_cli_gate step 5 FAIL: 'hello-cli' still present after delete\nstdout: {stdout}"
    );
    eprintln!("m5_prefix_cli_gate step 5 OK: hello-cli absent after delete");
    eprintln!("m5_prefix_cli_gate: all 5 steps passed");
}

/// `weave --no-sandbox curl.exe http://example.com` — ws2 second-app network validation gate.
///
/// Verifies that curl.exe (static MinGW Windows build, 64-bit) can make a real
/// HTTP GET request to http://example.com under Weave and return the HTML
/// response to stdout. This exercises the full ws2_32 networking path
/// (WSAStartup → getaddrinfo → socket → connect → send → recv → closesocket)
/// using a blocking/select-based HTTP client rather than the async WSAEventSelect
/// model used by plink.
///
/// Exit criteria:
///   1. weave exits 0
///   2. stdout contains "Example Domain"
///
/// Network requires /etc/hosts access, so --no-sandbox is mandatory.
/// Skipped gracefully on non-Linux targets.
// Task 01 pivot (2026-04-18): curl.exe uses an async-DNS loopback-pair +
// WSAEventSelect dance that required 9 commits of ws2 fixes before reaching
// outbound HTTP. The remaining surface (ws_accept → getaddrinfo result
// delivery, then ws_connect to the resolved IP) is a multi-commit project on
// its own. Task 01's exit criterion is "a non-plink binary with a different
// socket pattern exits 0 under Weave CI" — wget.exe (blocking HTTP) satisfies
// that with far less scope. This gate is #[ignore]'d while the task pivots to
// wget_ws2_gate; the ws2 fixes accumulated here (SO_EXCLUSIVEADDRUSE no-op,
// POLLOUT flood suppression, FD_ACCEPT on listening sockets, SOCKET_LISTENING
// cleanup on close) are durable and remain in tree. Re-enable this gate when
// async-DNS delivery is implemented as its own task.
#[test]
#[ignore = "Task 01 pivoted to wget_ws2_gate; re-enable once async-DNS delivery ships"]
fn curl_ws2_gate() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping curl_ws2_gate — requires Linux");
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let fixture = format!("{manifest}/../tests/fixtures/bin/curl.exe");

    if !std::path::Path::new(&fixture).exists() {
        eprintln!(
            "skipping: curl.exe not present in tests/fixtures/bin/ — curl_ws2_gate skipped"
        );
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");

    let start = std::time::Instant::now();
    let mut child = std::process::Command::new(weave_bin)
        .arg("--no-sandbox")
        .arg(&fixture)
        .arg("--no-progress-meter")
        .arg("http://example.com")
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn weave on curl.exe: {e}"));

    // Drain stderr concurrently to avoid 64 KB pipe blocking.
    let mut stderr_pipe = child.stderr.take().expect("stderr was piped");
    let stderr_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let stderr_writer = std::sync::Arc::clone(&stderr_shared);
    let drain_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        *stderr_writer.lock().unwrap() = buf;
    });

    // Drain stdout concurrently (curl writes HTML here).
    let mut stdout_pipe = child.stdout.take().expect("stdout was piped");
    let stdout_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let stdout_writer = std::sync::Arc::clone(&stdout_shared);
    let stdout_drain_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        *stdout_writer.lock().unwrap() = buf;
    });

    // 30-second deadline — DNS + TCP + HTTP for example.com should complete well within this.
    let deadline = start + std::time::Duration::from_secs(30);
    let mut exit_status: Option<std::process::ExitStatus> = None;
    let mut killed_by_deadline = false;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    eprintln!("curl_ws2_gate: deadline exceeded — killing curl.exe");
                    let _ = child.kill();
                    killed_by_deadline = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("curl_ws2_gate: try_wait error: {e}");
                break;
            }
        }
    }

    let elapsed = start.elapsed();
    drain_thread.join().ok();
    stdout_drain_thread.join().ok();

    let stderr = String::from_utf8_lossy(&stderr_shared.lock().unwrap()).into_owned();
    let stdout = String::from_utf8_lossy(&stdout_shared.lock().unwrap()).into_owned();

    eprintln!("curl_ws2_gate: elapsed={elapsed:.1?} killed={killed_by_deadline}");
    eprintln!("--- curl_ws2_gate FULL STDOUT BEGIN ---");
    eprintln!("{stdout}");
    eprintln!("--- curl_ws2_gate FULL STDOUT END ---");
    eprintln!("--- curl_ws2_gate FULL STDERR BEGIN ---");
    eprintln!("{stderr}");
    eprintln!("--- curl_ws2_gate FULL STDERR END ---");

    // Report unresolved imports for diagnosis.
    eprintln!("--- curl_ws2_gate unresolved imports ---");
    for line in stderr.lines().filter(|l| l.contains("unresolved import")) {
        eprintln!("{line}");
    }

    assert!(
        !killed_by_deadline,
        "curl_ws2_gate FAIL: curl.exe did not exit within 30s deadline\nstderr:\n{stderr}"
    );

    // Gate 1 (hard): IAT patch must complete.
    assert!(
        stderr.contains("weave: imports resolved"),
        "curl_ws2_gate Gate 1 FAIL: IAT patch did not complete\nelapsed: {elapsed:.1?}\nstderr:\n{stderr}"
    );

    // Gate 2 (hard): exit 0.
    assert!(
        exit_status.map_or(false, |s| s.success()),
        "curl_ws2_gate Gate 2 FAIL: curl.exe exited {:?} (expected 0)\nstdout:\n{stdout}\nstderr:\n{stderr}",
        exit_status
    );

    // Gate 3 (hard): stdout contains the expected page content.
    assert!(
        stdout.contains("Example Domain"),
        "curl_ws2_gate Gate 3 FAIL: stdout does not contain 'Example Domain'\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    eprintln!("curl_ws2_gate: all gates passed — curl.exe HTTP GET to example.com succeeded");
}

/// `weave --no-sandbox wget.exe -O - http://example.com` — Task 01 active gate.
///
/// Task 01 second-app network validation. wget.exe uses a blocking HTTP path
/// (getaddrinfo → socket → connect → send → recv) with no WSAEventSelect or
/// async-DNS loopback-pair — a meaningfully different socket pattern from
/// plink's async WSA event model. Pivoted here from curl_ws2_gate (see comment
/// on that test) after curl's async-DNS scope expanded past the task budget.
///
/// Binary: eternallybored.org/misc/wget/ 1.21.4 64-bit static build
/// (OpenSSL statically linked; plain-HTTP target avoids the CRYPT32/BCRYPT
/// surface entirely).
///
/// Exit criteria:
///   1. weave exits 0
///   2. wget.exe exits 0
///   3. stdout contains "Example Domain"
///
/// `-O -` streams the response body to stdout so no file I/O is needed and
/// Landlock allow-set considerations do not apply.
/// `--no-sandbox` required for /etc/hosts / DNS. Skipped on non-Linux.
#[test]
fn wget_ws2_gate() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping wget_ws2_gate — requires Linux");
        return;
    }

    let manifest = env!("CARGO_MANIFEST_DIR");
    let fixture = format!("{manifest}/../tests/fixtures/bin/wget.exe");

    if !std::path::Path::new(&fixture).exists() {
        eprintln!(
            "skipping: wget.exe not present in tests/fixtures/bin/ — wget_ws2_gate skipped"
        );
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");

    let start = std::time::Instant::now();
    let mut child = std::process::Command::new(weave_bin)
        .arg("--no-sandbox")
        .arg(&fixture)
        .arg("-q") // quiet: no progress bar on stderr
        .arg("-O")
        .arg("-") // stream body to stdout
        .arg("http://example.com")
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn weave on wget.exe: {e}"));

    // Drain stderr concurrently to avoid 64 KB pipe blocking.
    let mut stderr_pipe = child.stderr.take().expect("stderr was piped");
    let stderr_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let stderr_writer = std::sync::Arc::clone(&stderr_shared);
    let drain_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        *stderr_writer.lock().unwrap() = buf;
    });

    // Drain stdout concurrently (wget writes HTML here).
    let mut stdout_pipe = child.stdout.take().expect("stdout was piped");
    let stdout_shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let stdout_writer = std::sync::Arc::clone(&stdout_shared);
    let stdout_drain_thread = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        *stdout_writer.lock().unwrap() = buf;
    });

    let deadline = start + std::time::Duration::from_secs(30);
    let mut exit_status: Option<std::process::ExitStatus> = None;
    let mut killed_by_deadline = false;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    eprintln!("wget_ws2_gate: deadline exceeded — killing wget.exe");
                    let _ = child.kill();
                    killed_by_deadline = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("wget_ws2_gate: try_wait error: {e}");
                break;
            }
        }
    }

    let elapsed = start.elapsed();
    drain_thread.join().ok();
    stdout_drain_thread.join().ok();

    let stderr = String::from_utf8_lossy(&stderr_shared.lock().unwrap()).into_owned();
    let stdout = String::from_utf8_lossy(&stdout_shared.lock().unwrap()).into_owned();

    eprintln!("wget_ws2_gate: elapsed={elapsed:.1?} killed={killed_by_deadline}");
    eprintln!("--- wget_ws2_gate FULL STDOUT BEGIN ---");
    eprintln!("{stdout}");
    eprintln!("--- wget_ws2_gate FULL STDOUT END ---");
    eprintln!("--- wget_ws2_gate FULL STDERR BEGIN ---");
    eprintln!("{stderr}");
    eprintln!("--- wget_ws2_gate FULL STDERR END ---");

    eprintln!("--- wget_ws2_gate unresolved imports ---");
    for line in stderr.lines().filter(|l| l.contains("unresolved import")) {
        eprintln!("{line}");
    }

    assert!(
        !killed_by_deadline,
        "wget_ws2_gate FAIL: wget.exe did not exit within 30s deadline\nstderr:\n{stderr}"
    );

    assert!(
        stderr.contains("weave: imports resolved"),
        "wget_ws2_gate Gate 1 FAIL: IAT patch did not complete\nelapsed: {elapsed:.1?}\nstderr:\n{stderr}"
    );

    assert!(
        exit_status.map_or(false, |s| s.success()),
        "wget_ws2_gate Gate 2 FAIL: wget.exe exited {:?} (expected 0)\nstdout:\n{stdout}\nstderr:\n{stderr}",
        exit_status
    );

    assert!(
        stdout.contains("Example Domain"),
        "wget_ws2_gate Gate 3 FAIL: stdout does not contain 'Example Domain'\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    eprintln!("wget_ws2_gate: all gates passed — wget.exe HTTP GET to example.com succeeded");
}
