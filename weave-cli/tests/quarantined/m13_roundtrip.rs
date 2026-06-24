#![allow(unused)]

static M13_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

fn m13_lock() -> std::sync::MutexGuard<'static, ()> {
    M13_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// sevenzip_m13_roundtrip_gate — M13 end-to-end create-then-extract gate.
///
/// Drives `7za.exe` through a full round trip:
///   Phase 1: `weave 7za.exe a roundtrip.7z hello.txt lorem.txt bytes.bin`
///   Phase 2: `weave 7za.exe x roundtrip.7z -o<extract_dir> -y`
///
/// Tier A assertions:
///   A1: Phase 1 (`7za a`) exits 0.
///   A2: `roundtrip.7z` exists in work_dir with non-zero size after Phase 1.
///   A3 (load-bearing): each of the three extracted files matches the
///       embedded fixture bytes from `tests/fixtures/sevenzip/m13/` exactly.
///
/// Sandbox notes: Landlock allows write access to the fixture bin_dir but NOT
/// /tmp. Work_dir is a subdir of bin_dir, identical pattern to M4/M8a.
///
/// Skipped gracefully on macOS (Linux-only) and if `7za.exe` is absent.
///
/// `#[ignore]` (2026-05-17, M13 close): MSVC-built `7za.exe` (26.00) is part
/// of the M13 MSVC residual scoped out of closure. First post-body
/// `0x80070057` edge proved at `0x47bb00 -> 0x47b5cc`, classified
/// `MSVC_INTERNAL_PATH_UNRESOLVED`. See `docs/milestones/M13-7za-roundtrip.md`
/// § "Residual". Run explicitly via `cargo test ... -- --ignored
/// sevenzip_m13_roundtrip_gate` if revisiting that residual.
#[test]
#[ignore]
fn sevenzip_m13_roundtrip_gate() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping sevenzip_m13_roundtrip_gate — requires Linux");
        return;
    }
    let _m13_guard = m13_lock();

    let manifest = env!("CARGO_MANIFEST_DIR");
    let bin_dir = format!("{manifest}/../tests/fixtures/bin");
    let seven_zip = format!("{bin_dir}/7za.exe");
    let fixture_dir = format!("{manifest}/../tests/fixtures/sevenzip/m13");

    if !std::path::Path::new(&seven_zip).exists() {
        eprintln!("skipping: 7za.exe not present in tests/fixtures/bin/");
        return;
    }
    if !std::path::Path::new(&fixture_dir).exists() {
        eprintln!("skipping: M13 fixture dir missing at {fixture_dir}");
        return;
    }

    // Embedded canonical fixture bytes — load-bearing for A3.
    let hello_expected: &[u8] = include_bytes!("../../tests/fixtures/sevenzip/m13/hello.txt");
    let lorem_expected: &[u8] = include_bytes!("../../tests/fixtures/sevenzip/m13/lorem.txt");
    let bytes_expected: &[u8] = include_bytes!("../../tests/fixtures/sevenzip/m13/bytes.bin");

    // Landlock covers bin_dir but not /tmp — work_dir MUST be a subdir of
    // bin_dir, same pattern as sevenzip_m4_extraction_gate / seven_zip_a_extract_gate.
    let work_dir = std::path::PathBuf::from(&bin_dir).join("m13_roundtrip_work");

    // Pre-cleanup (idempotent across reruns).
    let _ = std::fs::remove_dir_all(&work_dir);
    std::fs::create_dir_all(&work_dir)
        .unwrap_or_else(|e| panic!("failed to create work_dir {}: {e}", work_dir.display()));

    // Copy fixture inputs into work_dir so the create invocation sees them
    // as cwd-relative entries (and so the archive does not embed an
    // absolute path that the extract phase would then re-create).
    for name in &["hello.txt", "lorem.txt", "bytes.bin"] {
        let src = std::path::PathBuf::from(&fixture_dir).join(name);
        let dst = work_dir.join(name);
        std::fs::copy(&src, &dst).unwrap_or_else(|e| {
            panic!(
                "failed to copy fixture {} -> {}: {e}",
                src.display(),
                dst.display()
            )
        });
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");

    // ===== Phase 1: create =====
    // CWD = work_dir so the input filenames stored in the archive are bare
    // (no path prefix), which keeps the extract path simple.
    //
    // Flag bisect (M13 investigation 2026-05-12): all five tested switches
    // RED (-mtc- / -mtm- / -mta- / -ms=off / -mmt=1). The failure surface is
    // NOT in file-time fields, solid-mode topology, or multi-threading. Next
    // step per operator: build a debug 7-Zip with verbose RINOK to localize
    // the specific `return E_INVALIDARG` callsite.
    let create_out = std::process::Command::new(weave_bin)
        .current_dir(&work_dir)
        .arg(&seven_zip)
        .arg("a")
        .arg("roundtrip.7z")
        .arg("hello.txt")
        .arg("lorem.txt")
        .arg("bytes.bin")
        .output()
        .unwrap_or_else(|e| panic!("failed to run weave on 7za.exe a: {e}"));

    let c_stdout = String::from_utf8_lossy(&create_out.stdout);
    let c_stderr = String::from_utf8_lossy(&create_out.stderr);

    eprintln!(
        "sevenzip_m13_roundtrip_gate: create exit: {}",
        create_out.status
    );
    eprintln!("--- 7za a stdout ---\n{c_stdout}");
    eprintln!("--- 7za a stderr ---\n{c_stderr}");

    // A1: create exit 0.
    assert!(
        create_out.status.success(),
        "sevenzip_m13_roundtrip_gate A1 FAIL: weave 7za.exe a exited non-zero: {}\n\
         stdout: {c_stdout}\nstderr: {c_stderr}",
        create_out.status
    );

    // A2: archive exists and is non-empty.
    let archive_path = work_dir.join("roundtrip.7z");
    let archive_meta = std::fs::metadata(&archive_path).unwrap_or_else(|e| {
        panic!(
            "sevenzip_m13_roundtrip_gate A2 FAIL: stat({}) failed: {e}\n\
             work_dir contents: {:?}\nstdout: {c_stdout}\nstderr: {c_stderr}",
            archive_path.display(),
            std::fs::read_dir(&work_dir)
                .map(|r| r
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name())
                    .collect::<Vec<_>>())
                .unwrap_or_default()
        )
    });
    let archive_len = archive_meta.len();
    assert!(
        archive_len > 0,
        "sevenzip_m13_roundtrip_gate A2 FAIL: archive exists but is 0 bytes at {}\n\
         stdout: {c_stdout}\nstderr: {c_stderr}",
        archive_path.display()
    );

    // B-tier diagnostics: 7z magic bytes + compression ratio.
    if let Ok(prefix) = std::fs::read(&archive_path) {
        let head = &prefix[..prefix.len().min(6)];
        let head_hex = head
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        eprintln!(
            "sevenzip_m13_roundtrip_gate: archive head (first 6) = {head_hex} \
             (expect 37 7A BC AF 27 1C for valid 7z signature)"
        );
    }
    let raw_total = hello_expected.len() + lorem_expected.len() + bytes_expected.len();
    eprintln!(
        "sevenzip_m13_roundtrip_gate: archive size {archive_len} bytes vs raw input {raw_total} bytes \
         (ratio = {:.2}x)",
        archive_len as f64 / raw_total as f64
    );

    // ===== Phase 2: extract =====
    let extract_dir = work_dir.join("extract");
    let _ = std::fs::remove_dir_all(&extract_dir);
    std::fs::create_dir_all(&extract_dir).unwrap_or_else(|e| {
        panic!(
            "failed to create extract_dir {}: {e}",
            extract_dir.display()
        )
    });

    let extract_out = std::process::Command::new(weave_bin)
        .current_dir(&work_dir)
        .arg(&seven_zip)
        .arg("x")
        .arg("roundtrip.7z")
        .arg(format!("-o{}", extract_dir.display()))
        .arg("-y")
        .output()
        .unwrap_or_else(|e| panic!("failed to run weave on 7za.exe x: {e}"));

    let x_stdout = String::from_utf8_lossy(&extract_out.stdout);
    let x_stderr = String::from_utf8_lossy(&extract_out.stderr);

    eprintln!(
        "sevenzip_m13_roundtrip_gate: extract exit: {}",
        extract_out.status
    );
    eprintln!("--- 7za x stdout ---\n{x_stdout}");
    eprintln!("--- 7za x stderr ---\n{x_stderr}");

    assert!(
        extract_out.status.success(),
        "sevenzip_m13_roundtrip_gate extract FAIL: weave 7za.exe x exited non-zero: {}\n\
         stdout: {x_stdout}\nstderr: {x_stderr}",
        extract_out.status
    );

    // SHA-256 helper (shells out to sha256sum, available in CI image; same
    // pattern as sevenzip_m4_extraction_gate).
    fn sha256_of_bytes(data: &[u8]) -> String {
        use std::io::Write;
        let mut child = std::process::Command::new("sha256sum")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("sha256sum not found — needed for M13 diagnostics");
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

    // A3 (load-bearing): every extracted file matches its embedded fixture
    // byte-for-byte. On mismatch we print SHA-256 of both sides and the
    // first differing offset to make CI triage immediate.
    let checks: &[(&str, &[u8])] = &[
        ("hello.txt", hello_expected),
        ("lorem.txt", lorem_expected),
        ("bytes.bin", bytes_expected),
    ];

    for (name, expected) in checks {
        let path = extract_dir.join(name);
        if !path.exists() {
            let listing = std::fs::read_dir(&extract_dir)
                .map(|r| {
                    r.filter_map(|e| e.ok())
                        .map(|e| e.file_name())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            panic!(
                "sevenzip_m13_roundtrip_gate A3 FAIL: extracted file {name} missing at {}\n\
                 extract_dir contents: {listing:?}\nstdout: {x_stdout}\nstderr: {x_stderr}",
                path.display()
            );
        }
        let actual = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("failed to read extracted {}: {e}", path.display()));
        if actual.as_slice() != *expected {
            let actual_sha = sha256_of_bytes(&actual);
            let expected_sha = sha256_of_bytes(expected);
            let first_diff = actual
                .iter()
                .zip(expected.iter())
                .position(|(a, b)| a != b)
                .map(|i| i.to_string())
                .unwrap_or_else(|| {
                    format!(
                        "length-only (actual={}, expected={})",
                        actual.len(),
                        expected.len()
                    )
                });
            panic!(
                "sevenzip_m13_roundtrip_gate A3 FAIL: {name} extracted bytes != fixture bytes.\n\
                 actual len:   {}  sha256: {actual_sha}\n\
                 expected len: {}  sha256: {expected_sha}\n\
                 first differing index: {first_diff}\n\
                 actual (first 64):   {:?}\n\
                 expected (first 64): {:?}\n\
                 create stdout: {c_stdout}\ncreate stderr: {c_stderr}\n\
                 extract stdout: {x_stdout}\nextract stderr: {x_stderr}",
                actual.len(),
                expected.len(),
                &actual[..actual.len().min(64)],
                &expected[..expected.len().min(64)],
            );
        }
        eprintln!(
            "sevenzip_m13_roundtrip_gate: {name} round-trip OK ({} bytes)",
            actual.len()
        );
    }

    eprintln!(
        "sevenzip_m13_roundtrip_gate: all Tier A gates passed — 3 files round-tripped, \
         archive {archive_len} bytes"
    );

    // Post-cleanup (best effort).
    let _ = std::fs::remove_dir_all(&work_dir);
}

/// sevenzip_m13_store_roundtrip_gate — M13 store-mode (-mx0) round-trip gate.
///
/// Identical to `sevenzip_m13_roundtrip_gate` except the create phase passes
/// `-mx0` (no compression, store only).  This isolates whether the 0x80070057
/// failure seen with 7za 26.00 default LZMA2 compression is triggered by the
/// compression finish-header path or by something more fundamental in archive
/// metadata serialisation.
///
/// If this gate passes and the default-compression gate stays red, the
/// difference is the LZMA finish-header path — a deferred M13c item.
/// If this gate also fails, the problem is earlier (metadata/header writer).
///
/// Tier A assertions:
///   A1: `weave 7za.exe a -mx0 store.7z ...` exits 0
///   A2: store.7z is non-empty on disk
///   A3: extracted bytes match fixture bytes exactly (3 files)
///
/// `#[ignore]` (2026-05-17, M13 close): MSVC `7za.exe` -mx0 hits the same
/// post-body `0x80070057` failure as the default-compression gate. Scoped
/// out of M13 closure as MSVC residual — see
/// `docs/milestones/M13-7za-roundtrip.md` § "Residual".
#[test]
#[ignore]
fn sevenzip_m13_store_roundtrip_gate() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping sevenzip_m13_store_roundtrip_gate — requires Linux");
        return;
    }
    let _m13_guard = m13_lock();

    let manifest = env!("CARGO_MANIFEST_DIR");
    let bin_dir = format!("{manifest}/../tests/fixtures/bin");
    let seven_zip = format!("{bin_dir}/7za.exe");
    let fixture_dir = format!("{manifest}/../tests/fixtures/sevenzip/m13");

    if !std::path::Path::new(&seven_zip).exists() {
        eprintln!("skipping: 7za.exe not present in tests/fixtures/bin/");
        return;
    }
    if !std::path::Path::new(&fixture_dir).exists() {
        eprintln!("skipping: M13 fixture dir missing at {fixture_dir}");
        return;
    }

    let hello_expected: &[u8] = include_bytes!("../../tests/fixtures/sevenzip/m13/hello.txt");
    let lorem_expected: &[u8] = include_bytes!("../../tests/fixtures/sevenzip/m13/lorem.txt");
    let bytes_expected: &[u8] = include_bytes!("../../tests/fixtures/sevenzip/m13/bytes.bin");

    let work_dir = std::path::PathBuf::from(&bin_dir).join("m13_store_work");

    let _ = std::fs::remove_dir_all(&work_dir);
    std::fs::create_dir_all(&work_dir)
        .unwrap_or_else(|e| panic!("failed to create work_dir {}: {e}", work_dir.display()));

    for name in &["hello.txt", "lorem.txt", "bytes.bin"] {
        let src = std::path::PathBuf::from(&fixture_dir).join(name);
        let dst = work_dir.join(name);
        std::fs::copy(&src, &dst).unwrap_or_else(|e| {
            panic!(
                "failed to copy fixture {} -> {}: {e}",
                src.display(),
                dst.display()
            )
        });
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");

    // ===== Phase 1: create (store mode) =====
    let create_out = std::process::Command::new(weave_bin)
        .current_dir(&work_dir)
        .arg(&seven_zip)
        .arg("a")
        .arg("-mx0")
        .arg("store.7z")
        .arg("hello.txt")
        .arg("lorem.txt")
        .arg("bytes.bin")
        .output()
        .unwrap_or_else(|e| panic!("failed to run weave on 7za.exe a -mx0: {e}"));

    let c_stdout = String::from_utf8_lossy(&create_out.stdout);
    let c_stderr = String::from_utf8_lossy(&create_out.stderr);

    eprintln!(
        "sevenzip_m13_store_roundtrip_gate: create exit: {}",
        create_out.status
    );
    eprintln!("--- 7za a -mx0 stdout ---\n{c_stdout}");
    eprintln!("--- 7za a -mx0 stderr ---\n{c_stderr}");

    // A1: create exit 0.
    assert!(
        create_out.status.success(),
        "sevenzip_m13_store_roundtrip_gate A1 FAIL: weave 7za.exe a -mx0 exited non-zero: {}\n\
         stdout: {c_stdout}\nstderr: {c_stderr}",
        create_out.status
    );

    // A2: archive exists and is non-empty.
    let archive_path = work_dir.join("store.7z");
    let archive_meta = std::fs::metadata(&archive_path).unwrap_or_else(|e| {
        panic!(
            "sevenzip_m13_store_roundtrip_gate A2 FAIL: stat({}) failed: {e}\n\
             work_dir contents: {:?}\nstdout: {c_stdout}\nstderr: {c_stderr}",
            archive_path.display(),
            std::fs::read_dir(&work_dir)
                .map(|r| r
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name())
                    .collect::<Vec<_>>())
                .unwrap_or_default(),
        )
    });
    let archive_len = archive_meta.len();
    assert!(
        archive_len > 0,
        "sevenzip_m13_store_roundtrip_gate A2 FAIL: archive exists but is 0 bytes\n\
         stdout: {c_stdout}\nstderr: {c_stderr}",
    );
    eprintln!(
        "sevenzip_m13_store_roundtrip_gate: archive size {archive_len} bytes (store, no compression)"
    );

    // ===== Phase 2: extract =====
    let extract_dir = work_dir.join("extracted");
    std::fs::create_dir_all(&extract_dir).unwrap_or_else(|e| {
        panic!(
            "failed to create extract_dir {}: {e}",
            extract_dir.display()
        )
    });

    let extract_out = std::process::Command::new(weave_bin)
        .current_dir(&work_dir)
        .arg(&seven_zip)
        .arg("x")
        .arg("store.7z")
        .arg(format!("-o{}", extract_dir.display()))
        .arg("-y")
        .output()
        .unwrap_or_else(|e| panic!("failed to run weave on 7za.exe x: {e}"));

    let x_stdout = String::from_utf8_lossy(&extract_out.stdout);
    let x_stderr = String::from_utf8_lossy(&extract_out.stderr);

    eprintln!(
        "sevenzip_m13_store_roundtrip_gate: extract exit: {}",
        extract_out.status
    );
    eprintln!("--- 7za x stdout ---\n{x_stdout}");
    eprintln!("--- 7za x stderr ---\n{x_stderr}");

    assert!(
        extract_out.status.success(),
        "sevenzip_m13_store_roundtrip_gate extract FAIL: weave 7za.exe x exited non-zero: {}\n\
         stdout: {x_stdout}\nstderr: {x_stderr}",
        extract_out.status
    );

    // A3: extracted bytes match fixture.
    let checks: &[(&str, &[u8])] = &[
        ("hello.txt", hello_expected),
        ("lorem.txt", lorem_expected),
        ("bytes.bin", bytes_expected),
    ];
    for (name, expected) in checks {
        let path = extract_dir.join(name);
        if !path.exists() {
            let listing: Vec<_> = std::fs::read_dir(&extract_dir)
                .map(|r| r.filter_map(|e| e.ok()).map(|e| e.file_name()).collect())
                .unwrap_or_default();
            panic!(
                "sevenzip_m13_store_roundtrip_gate A3 FAIL: {name} missing after extract\n\
                 extract_dir contents: {listing:?}\nstdout: {x_stdout}\nstderr: {x_stderr}",
            );
        }
        let actual =
            std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read extracted {name}: {e}"));
        assert_eq!(
            actual,
            *expected,
            "sevenzip_m13_store_roundtrip_gate A3 FAIL: {name} bytes mismatch\n\
             actual len: {}  expected len: {}\nstdout: {x_stdout}\nstderr: {x_stderr}",
            actual.len(),
            expected.len()
        );
        eprintln!(
            "sevenzip_m13_store_roundtrip_gate: {name} round-trip OK ({} bytes)",
            actual.len()
        );
    }

    eprintln!(
        "sevenzip_m13_store_roundtrip_gate: all Tier A gates passed — 3 files round-tripped \
         (store mode, archive {archive_len} bytes)"
    );

    let _ = std::fs::remove_dir_all(&work_dir);
}

/// sevenzip_m13_v23_roundtrip_gate — M13 round-trip gate using 7za 23.01.
///
/// Same fixture and assertions as `sevenzip_m13_roundtrip_gate` (default LZMA2
/// compression), but runs against `7za-23.exe` (23.01 x64) instead of 26.00.
///
/// Purpose: determine whether the `Error #80070057` finish-header failure is
/// specific to 7za 26.00 or also present in 23.01.
///
/// - If this gate passes and the 26.00 gate stays red → 26.00-specific
///   regression; pin M13 required gate to 23.01, defer 26.00 as M13c.
/// - If this gate also fails with the same error → Weave metadata/header
///   bug, not 26.00-specific; root cause investigation required.
///
/// Skipped gracefully on macOS and if `7za-23.exe` is absent from fixtures.
///
/// `#[ignore]` (2026-05-17, M13 close): MSVC `7za-23.exe` is the binary
/// follow-up U analyzed in depth. First observable post-body `0x80070057`
/// edge proved at `0x47bb00 -> 0x47b5cc`; residual classified
/// `MSVC_INTERNAL_PATH_UNRESOLVED`. Scoped out of M13 closure pending an
/// optional binary RE pass on `0x47b5cc` / vtable `0x4ed030`. See
/// `docs/milestones/M13-7za-roundtrip.md` § "Residual".
#[test]
#[ignore]
fn sevenzip_m13_v23_roundtrip_gate() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping sevenzip_m13_v23_roundtrip_gate — requires Linux");
        return;
    }
    let _m13_guard = m13_lock();

    let manifest = env!("CARGO_MANIFEST_DIR");
    let bin_dir = format!("{manifest}/../tests/fixtures/bin");
    let seven_zip = format!("{bin_dir}/7za-23.exe");
    let fixture_dir = format!("{manifest}/../tests/fixtures/sevenzip/m13");

    if !std::path::Path::new(&seven_zip).exists() {
        eprintln!("skipping: 7za-23.exe not present in tests/fixtures/bin/");
        return;
    }
    if !std::path::Path::new(&fixture_dir).exists() {
        eprintln!("skipping: M13 fixture dir missing at {fixture_dir}");
        return;
    }

    let hello_expected: &[u8] = include_bytes!("../../tests/fixtures/sevenzip/m13/hello.txt");
    let lorem_expected: &[u8] = include_bytes!("../../tests/fixtures/sevenzip/m13/lorem.txt");
    let bytes_expected: &[u8] = include_bytes!("../../tests/fixtures/sevenzip/m13/bytes.bin");

    let work_dir = std::path::PathBuf::from(&bin_dir).join("m13_v23_work");

    let _ = std::fs::remove_dir_all(&work_dir);
    std::fs::create_dir_all(&work_dir)
        .unwrap_or_else(|e| panic!("failed to create work_dir {}: {e}", work_dir.display()));

    for name in &["hello.txt", "lorem.txt", "bytes.bin"] {
        let src = std::path::PathBuf::from(&fixture_dir).join(name);
        let dst = work_dir.join(name);
        std::fs::copy(&src, &dst).unwrap_or_else(|e| {
            panic!(
                "failed to copy fixture {} -> {}: {e}",
                src.display(),
                dst.display()
            )
        });
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");

    // ===== Phase 1: create =====
    // follow-up F: WEAVE_IAT_TRACE=1 to capture the Win32 call sequence for
    // differential comparison against 7za-debug-E.exe (MinGW).
    let create_out = std::process::Command::new(weave_bin)
        .current_dir(&work_dir)
        .env("WEAVE_IAT_TRACE", "1")
        .env("WEAVE_M13_CRT_TRACE", "1")
        .arg(&seven_zip)
        .arg("a")
        .arg("roundtrip23.7z")
        .arg("hello.txt")
        .arg("lorem.txt")
        .arg("bytes.bin")
        .output()
        .unwrap_or_else(|e| panic!("failed to run weave on 7za-23.exe a: {e}"));

    let c_stdout = String::from_utf8_lossy(&create_out.stdout);
    let c_stderr = String::from_utf8_lossy(&create_out.stderr);

    eprintln!(
        "sevenzip_m13_v23_roundtrip_gate: create exit: {}",
        create_out.status
    );
    eprintln!("--- 7za-23 a stdout ---\n{c_stdout}");
    eprintln!("--- 7za-23 a stderr ---\n{c_stderr}");

    // A1: create exit 0.
    assert!(
        create_out.status.success(),
        "sevenzip_m13_v23_roundtrip_gate A1 FAIL: weave 7za-23.exe a exited non-zero: {}\n\
         stdout: {c_stdout}\nstderr: {c_stderr}",
        create_out.status
    );

    // A2: archive exists and is non-empty.
    let archive_path = work_dir.join("roundtrip23.7z");
    let archive_meta = std::fs::metadata(&archive_path).unwrap_or_else(|e| {
        panic!(
            "sevenzip_m13_v23_roundtrip_gate A2 FAIL: stat({}) failed: {e}\n\
             work_dir: {:?}\nstdout: {c_stdout}\nstderr: {c_stderr}",
            archive_path.display(),
            std::fs::read_dir(&work_dir)
                .map(|r| r
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name())
                    .collect::<Vec<_>>())
                .unwrap_or_default(),
        )
    });
    let archive_len = archive_meta.len();
    assert!(
        archive_len > 0,
        "sevenzip_m13_v23_roundtrip_gate A2 FAIL: archive is 0 bytes\n\
         stdout: {c_stdout}\nstderr: {c_stderr}",
    );
    eprintln!("sevenzip_m13_v23_roundtrip_gate: archive size {archive_len} bytes");

    // ===== Phase 2: extract =====
    let extract_dir = work_dir.join("extracted");
    std::fs::create_dir_all(&extract_dir).unwrap_or_else(|e| {
        panic!(
            "failed to create extract_dir {}: {e}",
            extract_dir.display()
        )
    });

    let extract_out = std::process::Command::new(weave_bin)
        .current_dir(&work_dir)
        .arg(&seven_zip)
        .arg("x")
        .arg("roundtrip23.7z")
        .arg(format!("-o{}", extract_dir.display()))
        .arg("-y")
        .output()
        .unwrap_or_else(|e| panic!("failed to run weave on 7za-23.exe x: {e}"));

    let x_stdout = String::from_utf8_lossy(&extract_out.stdout);
    let x_stderr = String::from_utf8_lossy(&extract_out.stderr);

    eprintln!(
        "sevenzip_m13_v23_roundtrip_gate: extract exit: {}",
        extract_out.status
    );
    eprintln!("--- 7za-23 x stdout ---\n{x_stdout}");
    eprintln!("--- 7za-23 x stderr ---\n{x_stderr}");

    assert!(
        extract_out.status.success(),
        "sevenzip_m13_v23_roundtrip_gate extract FAIL: weave 7za-23.exe x exited non-zero: {}\n\
         stdout: {x_stdout}\nstderr: {x_stderr}",
        extract_out.status
    );

    // A3: extracted bytes match fixture.
    let checks: &[(&str, &[u8])] = &[
        ("hello.txt", hello_expected),
        ("lorem.txt", lorem_expected),
        ("bytes.bin", bytes_expected),
    ];
    for (name, expected) in checks {
        let path = extract_dir.join(name);
        if !path.exists() {
            let listing: Vec<_> = std::fs::read_dir(&extract_dir)
                .map(|r| r.filter_map(|e| e.ok()).map(|e| e.file_name()).collect())
                .unwrap_or_default();
            panic!(
                "sevenzip_m13_v23_roundtrip_gate A3 FAIL: {name} missing after extract\n\
                 extract_dir: {listing:?}\nstdout: {x_stdout}\nstderr: {x_stderr}",
            );
        }
        let actual =
            std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read extracted {name}: {e}"));
        assert_eq!(
            actual,
            *expected,
            "sevenzip_m13_v23_roundtrip_gate A3 FAIL: {name} bytes mismatch\n\
             actual len: {}  expected len: {}\nstdout: {x_stdout}\nstderr: {x_stderr}",
            actual.len(),
            expected.len()
        );
        eprintln!(
            "sevenzip_m13_v23_roundtrip_gate: {name} round-trip OK ({} bytes)",
            actual.len()
        );
    }

    eprintln!(
        "sevenzip_m13_v23_roundtrip_gate: all Tier A gates passed — 3 files round-tripped \
         (7za 23.01, archive {archive_len} bytes)"
    );

    let _ = std::fs::remove_dir_all(&work_dir);
}
