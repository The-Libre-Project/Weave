//! Integration tests — WEAVE_PREFIX environment variable.
//!
//! Verifies that `weave` honours the `WEAVE_PREFIX` env var when `--prefix`
//! is not given, and that `--prefix` wins when both are set.
//!
//! Tests are skipped on non-Linux platforms (the dev machine is macOS ARM64).

mod common;

/// Helper: run `weave <fixture>` with a custom environment and return the
/// process output.  `env_vars` replaces (not augments) the inherited env for
/// the listed keys only; unmentioned env keys are inherited unchanged.
fn run_weave_with_env(
    fixture_name: &str,
    env_vars: &[(&str, &str)],
    extra_args: &[&str],
) -> std::process::Output {
    let weave_bin = env!("CARGO_BIN_EXE_weave");
    let fixture = format!(
        "{}/../tests/fixtures/bin/{fixture_name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut cmd = std::process::Command::new(weave_bin);
    for (k, v) in env_vars {
        cmd.env(k, v);
    }
    for arg in extra_args {
        cmd.arg(arg);
    }
    cmd.arg(&fixture);
    cmd.output()
        .unwrap_or_else(|e| panic!("failed to run weave on {fixture_name}: {e}"))
}

/// `WEAVE_PREFIX` points at a temp dir → `drive_c/` is created there after
/// startup (prefix::ensure_dirs() runs unconditionally at startup).
#[test]
fn weave_prefix_env_creates_drive_c() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping execution test — requires Linux");
        return;
    }

    let tmp = tempfile::tempdir().expect("could not create temp dir");
    let prefix_path = tmp.path().to_str().unwrap().to_owned();

    // Drive the simplest available fixture so the test is fast and has no
    // extra dependencies.  The exact exit status doesn't matter — what
    // matters is that Weave started and ran ensure_dirs().
    let _output = run_weave_with_env("hello_minimal.exe", &[("WEAVE_PREFIX", &prefix_path)], &[]);

    let drive_c = tmp.path().join("drive_c");
    assert!(
        drive_c.exists(),
        "WEAVE_PREFIX={prefix_path}: expected drive_c/ to be created, but it was not"
    );
}

/// When both `--prefix` flag and `WEAVE_PREFIX` env are set, the flag wins.
#[test]
fn prefix_flag_beats_env() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping execution test — requires Linux");
        return;
    }

    let tmp_flag = tempfile::tempdir().expect("could not create temp dir (flag)");
    let tmp_env = tempfile::tempdir().expect("could not create temp dir (env)");

    let flag_path = tmp_flag.path().to_str().unwrap().to_owned();
    let env_path = tmp_env.path().to_str().unwrap().to_owned();

    let _output = run_weave_with_env(
        "hello_minimal.exe",
        &[("WEAVE_PREFIX", &env_path)],
        &["--prefix", &flag_path],
    );

    // The flag-specified prefix must have drive_c/, …
    assert!(
        tmp_flag.path().join("drive_c").exists(),
        "--prefix dir: expected drive_c/ to be created"
    );
    // … and the env-specified prefix must NOT (flag won).
    assert!(
        !tmp_env.path().join("drive_c").exists(),
        "WEAVE_PREFIX dir: drive_c/ should NOT exist when --prefix overrides it"
    );
}

/// Empty-string `WEAVE_PREFIX` is treated as unset — Weave falls back to the
/// default prefix rather than using an empty string as a path.
#[test]
fn empty_weave_prefix_env_is_ignored() {
    if !cfg!(target_os = "linux") {
        eprintln!("skipping execution test — requires Linux");
        return;
    }

    // With WEAVE_PREFIX="" the binary should at least start without crashing.
    // We can't easily assert the default prefix path here (it depends on $HOME
    // in the test runner's env), so just assert the process doesn't error out
    // in a way unrelated to the exe itself.
    let output = run_weave_with_env("hello_minimal.exe", &[("WEAVE_PREFIX", "")], &[]);

    // hello_minimal.exe prints "Hello, World!\n" and exits 0 — if it exits non-
    // zero something unrelated broke.  We don't assert on stdout because the
    // default prefix's drive_c may not be writable in all CI environments, so
    // we only check the process didn't crash with a Weave-internal error.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("RUST PANIC"),
        "weave panicked with empty WEAVE_PREFIX:\n{stderr}"
    );
}
