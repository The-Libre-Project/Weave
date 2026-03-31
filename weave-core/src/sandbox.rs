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
use landlock::{Access, AccessFs, LandlockStatus, Ruleset, RulesetAttr, RulesetStatus, ABI};

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
/// If `enabled` is false the sandbox is skipped entirely (for `--no-sandbox`).
pub fn apply(enabled: bool) -> SandboxStatus {
    if !enabled {
        eprintln!("weave: sandbox disabled (--no-sandbox)");
        return SandboxStatus::Disabled;
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Landlock is Linux-only. On macOS (dev machine) skip silently.
        return SandboxStatus::Unavailable;
    }

    #[cfg(target_os = "linux")]
    apply_landlock()
}

#[cfg(target_os = "linux")]
fn apply_landlock() -> SandboxStatus {
    // Target ABI V1 (Linux 5.13+) — widest compatibility.
    // The crate degrades gracefully if the kernel supports fewer features.
    let abi = ABI::V1;

    let result = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .and_then(|r| r.create())
        // No add_rule() calls — deny ALL filesystem path access.
        // Open file descriptors (stdout, stderr) remain usable.
        .and_then(|r| r.restrict_self());

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
