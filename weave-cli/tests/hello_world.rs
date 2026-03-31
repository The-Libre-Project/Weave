/// Integration test: `weave hello_minimal.exe` must print "Hello, World!\n"
/// and exit with code 0.
///
/// This test only runs on Linux x86-64 (where execution is supported).
/// On macOS (dev machine) it is compiled but skipped at runtime.
#[test]
fn hello_minimal_prints_hello_world() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping execution test — requires Linux");
        return;
    }

    let weave_bin = env!("CARGO_BIN_EXE_weave");
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/fixtures/bin/hello_minimal.exe"
    );

    let output = std::process::Command::new(weave_bin)
        .arg(fixture)
        .output()
        .expect("failed to run weave binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "weave exited with non-zero status: {}\nstderr: {stderr}",
        output.status
    );

    assert_eq!(
        stdout,
        "Hello, World!\n",
        "unexpected stdout.\nstderr: {stderr}"
    );
}
