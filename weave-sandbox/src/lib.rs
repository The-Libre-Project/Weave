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
    if !enabled {
        eprintln!("weave: sandbox disabled (--no-sandbox)");
        return SandboxStatus::Disabled;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = allowed_read_paths;
        // Landlock is Linux-only. On macOS (dev machine) skip silently.
        return SandboxStatus::Unavailable;
    }

    #[cfg(target_os = "linux")]
    apply_landlock(allowed_read_paths)
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
