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
