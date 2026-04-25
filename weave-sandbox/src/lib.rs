//! Filesystem sandboxing via Linux Landlock LSM.
//!
//! Called after the PE is loaded and the IAT is patched, but before execution
//! begins. Once applied, the restriction stays in effect for the lifetime of
//! the process — the guest PE code cannot open any file paths.
//!
//! Why path-level restrictions are sufficient for Phase 1
//! -------------------------------------------------------
//! The PE binary shares Weave's address space, so a seccomp filter would have
//! to allowlist every syscall Weave itself needs (mmap, write, exit, …), which
//! gives the guest the same syscall surface anyway. Real syscall isolation
//! requires an out-of-process model (Phase 4+).
//!
//! Landlock IS effective here because:
//! - It restricts *path-based* filesystem access — open(), stat(), unlink(), …
//! - File descriptors already open (stdout fd 1, stderr fd 2) remain usable.
//! - Console apps like hello.exe never open paths at runtime; all I/O goes
//!   through already-open handles.
//!
//! Graceful degradation
//! --------------------
//! Landlock requires Linux 5.13+. On older kernels (or when disabled in the
//! kernel config) the restriction is silently skipped and Weave runs without
//! filesystem isolation. A diagnostic line is printed to stderr in both cases.

#[cfg(target_os = "linux")]
use landlock::{
    Access, AccessFs, LandlockStatus, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};

use std::sync::atomic::{AtomicU8, Ordering};

/// Result of attempting to apply the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxStatus {
    /// Landlock is fully enforced — all filesystem access is denied.
    Active,
    /// Landlock is available but only partially enforced (older kernel).
    Partial,
    /// Landlock is not available on this kernel — no restriction applied.
    Unavailable,
    /// Sandboxing was explicitly disabled by the caller.
    Disabled,
}

// ──────────────────────────────────────────────────────────────────────────
// Runtime invariant: is the sandbox active right now?
//
// "Active" is defined per-OS:
//   - Linux: Landlock returned `FullyEnforced` or `PartiallyEnforced`. After
//     `restrict_self()` succeeds at either level, path-based filesystem access
//     is restricted to the allowlisted paths for the lifetime of the process.
//     The restriction is irreversible.
//   - Non-Linux (macOS/Windows dev hosts): no OS sandbox primitive is wired
//     up. `is_sandbox_active()` always returns false. Launching a Win32 guest
//     on these hosts therefore always panics through `assert_sandboxed!()` —
//     this is intentional. Guest execution on a dev machine without an
//     OS-level containment boundary is forbidden.
//
// The state is a single process-global `AtomicU8` set exactly once by
// `apply()`. There is no API to clear it: once active, always active for the
// lifetime of the process (matching Landlock's irreversibility).
// ──────────────────────────────────────────────────────────────────────────

const SANDBOX_UNSET: u8 = 0;
const SANDBOX_ACTIVE: u8 = 1;
const SANDBOX_NOT_ACTIVE: u8 = 2;

static SANDBOX_STATE: AtomicU8 = AtomicU8::new(SANDBOX_UNSET);

/// Returns `true` iff the sandbox is currently active in this process.
///
/// "Active" means `apply()` has been called and returned `Active` or
/// `Partial` (Linux Landlock fully or partially enforced). Any other state —
/// including "apply() not yet called" — returns `false`.
///
/// This is the single canonical check. Do not invent parallel state.
pub fn is_sandbox_active() -> bool {
    SANDBOX_STATE.load(Ordering::SeqCst) == SANDBOX_ACTIVE
}

/// Internal: record the outcome of `apply()` into the global state.
fn record_status(status: SandboxStatus) {
    let value = match status {
        SandboxStatus::Active | SandboxStatus::Partial => SANDBOX_ACTIVE,
        SandboxStatus::Unavailable | SandboxStatus::Disabled => SANDBOX_NOT_ACTIVE,
    };
    SANDBOX_STATE.store(value, Ordering::SeqCst);
}

/// Panic if the sandbox is not currently active.
///
/// Call this at every binary entry point, immediately before transferring
/// control to guest Win32 code. The macro takes one argument: a static
/// string naming the entry point (e.g. `"weave-cli"`). The panic message is
/// stable and machine-greppable: it always begins with
/// `weave: SANDBOX INVARIANT VIOLATION`.
///
/// Unsandboxed Win32 execution is forbidden by the security model
/// documented in `docs/SECURITY_AUDIT.md`. The OS-level containment
/// boundary IS the security boundary; without it the in-process execution
/// model has no containment at all.
#[macro_export]
macro_rules! assert_sandboxed {
    ($entry_point:expr) => {{
        if !$crate::is_sandbox_active() {
            panic!(
                "weave: SANDBOX INVARIANT VIOLATION at entry point `{}`: \
                 sandbox is not active. Unsandboxed Win32 guest execution is \
                 forbidden. See docs/SECURITY_AUDIT.md. \
                 (If you set WEAVE_DISABLE_SANDBOX=1 or passed --no-sandbox, \
                 that is precisely what this assert is here to block.)",
                $entry_point
            );
        }
    }};
}

/// Apply the Landlock filesystem sandbox to the current process.
///
/// Call this after IAT patching but before jumping to the PE entry point.
/// The restriction is irreversible: once applied it cannot be lifted.
///
/// `allowed_read_paths` — directories granted read-only access (files + subdirs).
/// Pass `&[]` to deny all path-based filesystem access (original all-deny behaviour).
/// Pass the PE binary's parent directory so apps can open files beside the exe.
///
/// If `enabled` is false the sandbox is skipped entirely (for `--no-sandbox`).
pub fn apply(enabled: bool, allowed_read_paths: &[&std::path::Path]) -> SandboxStatus {
    // Honor an environment-variable kill switch so CI can verify the
    // assert-sandboxed invariant fires when sandboxing is bypassed. This is
    // intentionally identical in effect to passing `--no-sandbox`.
    let env_disabled = std::env::var_os("WEAVE_DISABLE_SANDBOX")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);

    if !enabled || env_disabled {
        if env_disabled {
            eprintln!("weave: sandbox disabled (WEAVE_DISABLE_SANDBOX=1)");
        } else {
            eprintln!("weave: sandbox disabled (--no-sandbox)");
        }
        record_status(SandboxStatus::Disabled);
        return SandboxStatus::Disabled;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = allowed_read_paths;
        // Landlock is Linux-only. On macOS (dev machine) skip silently.
        record_status(SandboxStatus::Unavailable);
        return SandboxStatus::Unavailable;
    }

    #[cfg(target_os = "linux")]
    {
        let status = apply_landlock(allowed_read_paths);
        record_status(status);
        status
    }
}

#[cfg(target_os = "linux")]
fn apply_landlock(allowed_read_paths: &[&std::path::Path]) -> SandboxStatus {
    // Target ABI V1 (Linux 5.13+) — widest compatibility.
    // The crate degrades gracefully if the kernel supports fewer features.
    let abi = ABI::V1;

    // Create the ruleset — denies all filesystem path access by default.
    // Open file descriptors (stdout, stderr) remain usable regardless.
    let ruleset = match Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .and_then(|r| r.create())
    {
        Ok(r) => r,
        Err(e) => {
            // Landlock syscall failed — likely too-old kernel or not built in.
            eprintln!("weave: sandbox unavailable ({e}); running without filesystem isolation");
            return SandboxStatus::Unavailable;
        }
    };

    // Add read+write allow rules for each permitted path (files + subdirs).
    // try_fold so a single-path failure aborts rather than leaving a silent gap.
    //
    // Windows apps routinely write config next to the exe (Notepad++ langs.xml,
    // stylers.xml, config.xml, session.xml). Read-only denies those CreateFileW
    // calls with ACCESS_DENIED and breaks first-run initialisation. We grant the
    // full set of file + dir mutation rights on the PE's parent directory only —
    // nothing else in the filesystem is reachable.
    // ABI V1 access set — Truncate is V3+ and would be filtered out here.
    // Under V1, O_TRUNC is authorised by WriteFile alone.
    let rw_access = AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::WriteFile
        | AccessFs::MakeReg
        | AccessFs::MakeDir
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir;
    let ruleset = allowed_read_paths.iter().try_fold(
        ruleset,
        |r, path| -> Result<_, Box<dyn std::error::Error>> {
            let fd = PathFd::new(path)?;
            Ok(r.add_rule(PathBeneath::new(fd, rw_access))?)
        },
    );

    let ruleset = match ruleset {
        Ok(r) => r,
        Err(e) => {
            eprintln!("weave: sandbox unavailable ({e}); running without filesystem isolation");
            return SandboxStatus::Unavailable;
        }
    };

    // DNS resolution requires read access to a small set of system files:
    //   /etc/hosts       — static hostname→IP mappings
    //   /etc/resolv.conf — nameserver configuration
    //   /etc/nsswitch.conf — name service switch order (glibc getaddrinfo)
    // Add read-only rules for each file that exists on this host.
    // Non-existent files are silently skipped (minimal-permission principle).
    let ro_access = AccessFs::ReadFile | AccessFs::ReadDir;
    let dns_files: &[&str] = &[
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/nsswitch.conf",
    ];
    let ruleset = dns_files.iter().try_fold(
        ruleset,
        |r, path| -> Result<_, Box<dyn std::error::Error>> {
            let p = std::path::Path::new(path);
            if p.exists() {
                let fd = PathFd::new(p)?;
                Ok(r.add_rule(PathBeneath::new(fd, ro_access))?)
            } else {
                Ok(r)
            }
        },
    );

    let ruleset = match ruleset {
        Ok(r) => r,
        Err(e) => {
            eprintln!("weave: sandbox unavailable ({e}); running without filesystem isolation");
            return SandboxStatus::Unavailable;
        }
    };

    let result = ruleset.restrict_self();

    match result {
        Err(e) => {
            // Landlock syscall failed — likely too-old kernel or not built in.
            eprintln!("weave: sandbox unavailable ({e}); running without filesystem isolation");
            SandboxStatus::Unavailable
        }
        Ok(status) => match status.ruleset {
            RulesetStatus::FullyEnforced => {
                eprintln!("weave: sandbox active — filesystem access denied");
                SandboxStatus::Active
            }
            RulesetStatus::PartiallyEnforced => {
                eprintln!(
                    "weave: sandbox partial — some filesystem restrictions active \
                     (upgrade kernel for full isolation)"
                );
                SandboxStatus::Partial
            }
            RulesetStatus::NotEnforced => {
                match status.landlock {
                    LandlockStatus::NotImplemented => eprintln!(
                        "weave: sandbox unavailable — Landlock not built into this kernel \
                         (CONFIG_SECURITY_LANDLOCK=y required)"
                    ),
                    LandlockStatus::NotEnabled => eprintln!(
                        "weave: sandbox unavailable — Landlock disabled \
                         (add 'landlock' to CONFIG_LSM or lsm= kernel param)"
                    ),
                    _ => eprintln!(
                        "weave: sandbox unavailable — running without filesystem isolation"
                    ),
                }
                SandboxStatus::Unavailable
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_disabled_returns_disabled() {
        // apply(false, _) must always return Disabled, on any platform.
        // This is safe to call in tests — it is a pure no-op.
        assert_eq!(apply(false, &[]), SandboxStatus::Disabled);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_apply_enabled_non_linux_returns_unavailable() {
        // On macOS (the dev machine), Landlock is not available.
        // apply(true, _) must return Unavailable without panicking.
        assert_eq!(apply(true, &[]), SandboxStatus::Unavailable);
    }

    use std::sync::Mutex;

    /// Shared mutex guarding `SANDBOX_STATE` mutations across the test
    /// cases below. Cargo runs unit tests in parallel within one process;
    /// without serialization, two state-mutating tests can race and
    /// produce flaky panics.
    static STATE_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_assert_sandboxed_panics_when_inactive() {
        let _g = STATE_MUTEX.lock().unwrap();
        SANDBOX_STATE.store(SANDBOX_NOT_ACTIVE, Ordering::SeqCst);
        assert!(!is_sandbox_active());
        let result = std::panic::catch_unwind(|| {
            assert_sandboxed!("test-entry-point");
        });
        let err = result.expect_err("assert_sandboxed! must panic when sandbox is inactive");
        let msg = err
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .or_else(|| err.downcast_ref::<&'static str>().copied())
            .unwrap_or("");
        assert!(
            msg.contains("SANDBOX INVARIANT VIOLATION"),
            "panic message must contain the invariant marker, got: {msg}"
        );
        assert!(
            msg.contains("test-entry-point"),
            "panic message must name the entry point, got: {msg}"
        );
        SANDBOX_STATE.store(SANDBOX_UNSET, Ordering::SeqCst);
    }

    #[test]
    fn test_assert_sandboxed_passes_when_active() {
        let _g = STATE_MUTEX.lock().unwrap();
        SANDBOX_STATE.store(SANDBOX_ACTIVE, Ordering::SeqCst);
        assert!(is_sandbox_active());
        // Must not panic.
        assert_sandboxed!("test-entry-point");
        SANDBOX_STATE.store(SANDBOX_UNSET, Ordering::SeqCst);
    }

    #[test]
    fn test_is_sandbox_active_unset_returns_false() {
        let _g = STATE_MUTEX.lock().unwrap();
        SANDBOX_STATE.store(SANDBOX_UNSET, Ordering::SeqCst);
        assert!(!is_sandbox_active());
    }

    #[test]
    fn test_sandbox_status_eq() {
        // SandboxStatus derives PartialEq — verify the basic variant equality.
        assert_eq!(SandboxStatus::Active, SandboxStatus::Active);
        assert_eq!(SandboxStatus::Partial, SandboxStatus::Partial);
        assert_eq!(SandboxStatus::Unavailable, SandboxStatus::Unavailable);
        assert_eq!(SandboxStatus::Disabled, SandboxStatus::Disabled);
        assert_ne!(SandboxStatus::Active, SandboxStatus::Disabled);
    }
}
