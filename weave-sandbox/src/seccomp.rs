//! seccomp-BPF syscall filter for the child process.
//!
//! Applied in the forked child (SB1a) before jumping to the guest entry point.
//! Uses raw BPF instructions to build a minimal allowlist filter.

// --- BPF instruction encoding ---
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

// seccomp return values.
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
const SECCOMP_RET_TRAP: u32 = 0x0003_0000;

// x86_64 audit architecture identifier.
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

// Offsets into `struct seccomp_data`.
const DATA_NR: u32 = 0;
const DATA_ARCH: u32 = 4;

#[repr(C)]
pub struct sock_filter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct sock_fprog {
    len: u16,
    filter: *const sock_filter,
}

/// Base allowlist: syscalls every app needs (18 x86_64 syscalls).
///
/// read=0, write=1, close=3, mmap=9, mprotect=10, munmap=11, brk=12,
/// rt_sigaction=13, rt_sigprocmask=14, sigreturn=15, getpid=39, exit=60,
/// gettid=186, futex=202, restart_syscall=219, clock_gettime=228,
/// exit_group=231, openat=257,
/// landlock_create_ruleset=444, landlock_add_rule=445, landlock_restrict_self=446
/// (Linux 5.13+, needed by weave_sandbox::apply after seccomp is active)
const BASE_SYSCALLS: [u32; 21] = [
    0, 1, 3, 9, 10, 11, 12, 13, 14, 15, 39, 60, 186, 202, 219, 228, 231, 257, 444, 445, 446,
];

/// Per-app syscall additions registry.
///
/// To identify denied syscalls, run with `WEAVE_SECCOMP_LOG=1` and inspect
/// the kernel audit log via `ausearch --start recent -m SECCOMP` or `dmesg`.
///
/// NXEngine-evo (nx.exe) anticipated needs — SDL2 input, Vulkan, game-loop timing:
///   evdev ioctls (ioctl=16), clock_nanosleep=230, sched_yield=24, poll=7,
///   clock_gettime=228, gettimeofday=96, getpid=39, tgkill=234, gettid=186,
///   fcntl=72, dup=32, dup2=33, nanosleep=35, recvmsg=47, sendmsg=46,
///   shmctl=24 (IPC), shmdt=67, shmget=29, semtimedop=192, semop=62,
///   eventfd=284, timerfd_create=283, timerfd_settime=286
///
/// IrfanView (i_view64.exe) anticipated needs — file dialogs, image codecs, GDI:
///   ioctl=16, fstat=5, stat=4, lstat=6, newfstatat=262, newfstat=6,
///   readlink=89, access=21, faccessat=269, getdents=78, getdents64=217,
///   lseek=8, pread64=17, openat=257, read=0, write=1,
///   sendfile=40, copy_file_range=326,
///   mremap=25, msync=26, mincore=27, madvise=28, mbind=237,
///   getegid=108, geteuid=107, getgid=104, getuid=102, getresuid=118, getresgid=119,
///   getgroups=115, set_robust_list=273, get_robust_list=274,
///   sched_getparam=143, sched_getscheduler=144, sched_setscheduler=145, sched_setparam=146,
///   setpriority=141, getpriority=140,
///   sigaltstack=131, rt_sigqueueinfo=178, rt_tgsigqueueinfo=297,
///   prlimit64=302, arch_prctl=158
pub const APP_SYSCALLS: &[(&str, &[i64])] = &[
    ("hello.exe", &[]),
    ("testsprite2.exe", &[]),
    // TODO(#SB4b): Run with WEAVE_SECCOMP_LOG=1 to identify actual denied syscalls for nx.exe.
    // Anticipated: SDL2 input (evdev ioctls), Vulkan surface, game-loop timing.
    ("nx.exe", &[]),
    // TODO(#SB4b): Run with WEAVE_SECCOMP_LOG=1 to identify actual denied syscalls for i_view64.exe.
    // Anticipated: file dialog, image codec loading (mmap/mprotect), GDI surface.
    ("i_view64.exe", &[]),
    // TODO(#SB4c): Run with WEAVE_SECCOMP_LOG=1 to identify actual denied syscalls for 7za.exe.
    // Anticipated: file I/O (openat, read, write, fstat), memory mapping, CRT init.
    ("7za.exe", &[]),
    // TODO(#SB4c): Run with WEAVE_SECCOMP_LOG=1 to identify actual denied syscalls for notepad++.exe.
    // Anticipated: Scintilla editor, file dialogs, plugin loading, GDI rendering.
    ("notepad++.exe", &[]),
    // TODO(#SB4c): Run with WEAVE_SECCOMP_LOG=1 to identify actual denied syscalls for putty.exe.
    // Anticipated: terminal rendering (GDI), SSH/network, crypto, event loop.
    ("putty.exe", &[]),
    // TODO(#SB4c): Run with WEAVE_SECCOMP_LOG=1 to identify actual denied syscalls for Q-Dir_x64.exe.
    // Anticipated: shell namespace (FindFirstFile, SHBrowseForFolder), file pane population.
    ("Q-Dir_x64.exe", &[]),
];

/// Build a complete seccomp BPF program for the given list of allowed
/// syscalls, using `deny_action` as the return value for non-matched calls.
fn build_bpf(allowlist: &[u32], deny_action: u32) -> Vec<sock_filter> {
    let n = allowlist.len();
    let mut insns = Vec::with_capacity(n + 6);

    insns.push(sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: DATA_ARCH,
    });
    insns.push(sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 1,
        jf: 0,
        k: AUDIT_ARCH_X86_64,
    });
    insns.push(sock_filter {
        code: BPF_RET,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });
    insns.push(sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: DATA_NR,
    });

    // ALLOW is at instruction index n + 5 (0-based).
    // For check at index 4 + i: jt = (n + 5) - (4 + i + 1) = n - i
    for (i, &sysnr) in allowlist.iter().enumerate() {
        insns.push(sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: (n - i) as u8,
            jf: 0,
            k: sysnr,
        });
    }

    insns.push(sock_filter {
        code: BPF_RET,
        jt: 0,
        jf: 0,
        k: deny_action,
    });
    insns.push(sock_filter {
        code: BPF_RET,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    insns
}

/// Build the base BPF seccomp filter with the common 18-syscall allowlist.
pub fn build_base_filter() -> Vec<sock_filter> {
    build_bpf(&BASE_SYSCALLS, SECCOMP_RET_KILL_PROCESS)
}

/// Build a per-app BPF seccomp filter combining the base allowlist with
/// per-app `additions`.
///
/// `WEAVE_SECCOMP_LOG=1` logs denied syscalls to the kernel audit log and
/// continues. `WEAVE_SECCOMP_TRAP=1` takes precedence and delivers SIGSYS so
/// the CLI's diagnostic handler can report the syscall number before exiting.
pub fn build_app_filter(_app: &str, additions: &[i64]) -> Vec<sock_filter> {
    let trap_enabled = std::env::var("WEAVE_SECCOMP_TRAP")
        .ok()
        .is_some_and(|v| v == "1");
    let log_enabled = std::env::var("WEAVE_SECCOMP_LOG")
        .ok()
        .is_some_and(|v| v == "1");
    let deny_action = if trap_enabled {
        SECCOMP_RET_TRAP
    } else if log_enabled {
        SECCOMP_RET_LOG
    } else {
        SECCOMP_RET_KILL_PROCESS
    };

    let mut syscalls: Vec<u32> = BASE_SYSCALLS.to_vec();
    for &a in additions {
        syscalls.push(a as u32);
    }
    build_bpf(&syscalls, deny_action)
}

/// Apply a seccomp-BPF filter that allows only the allowlisted syscalls.
///
/// Must be called before any guest code runs. On success, prints
/// `PHASE: seccomp_applied` to stderr.
///
/// On non-Linux platforms this is a no-op that returns `Ok(())`.
pub fn apply_seccomp(exe_name: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        apply_seccomp_inner(exe_name)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = exe_name;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn apply_seccomp_inner(exe_name: &str) -> Result<(), String> {
    const SECCOMP_MODE_FILTER: libc::c_int = 2;

    // ── Look up per-app additions ──────────────────────────────────────
    let additions: &[i64] = APP_SYSCALLS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(exe_name))
        .map(|(_, add)| *add)
        .unwrap_or(&[]);

    let insns = build_app_filter(exe_name, additions);

    // ── PR_SET_NO_NEW_PRIVS (required for unprivileged SECCOMP_MODE_FILTER) ──

    let ret = unsafe {
        libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_NO_NEW_PRIVS as libc::c_long,
            1 as libc::c_long,
            0 as libc::c_long,
            0 as libc::c_long,
            0 as libc::c_long,
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("PR_SET_NO_NEW_PRIVS: {err}"));
    }

    // ── apply via prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) ──

    let prog = sock_fprog {
        len: insns.len() as u16,
        filter: insns.as_ptr(),
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_SECCOMP as libc::c_long,
            SECCOMP_MODE_FILTER as libc::c_long,
            &prog as *const sock_fprog as libc::c_long,
        )
    };

    if ret == 0 {
        if std::env::var("WEAVE_SECCOMP_TRAP")
            .ok()
            .is_some_and(|v| v == "1")
        {
            eprintln!("PHASE: seccomp_applied (trap mode)");
        } else if std::env::var("WEAVE_SECCOMP_LOG")
            .ok()
            .is_some_and(|v| v == "1")
        {
            eprintln!("PHASE: seccomp_applied (logging mode)");
        } else {
            eprintln!("PHASE: seccomp_applied");
        }
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        eprintln!("weave: seccomp failed ({err})");
        Err(format!("seccomp: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: extract the syscall numbers from a BPF filter's JEQ
    /// instructions (code = 0x15: BPF_JMP | BPF_JEQ | BPF_K).
    fn syscall_numbers(filter: &[sock_filter]) -> Vec<u32> {
        filter
            .iter()
            .filter(|i| i.code == (BPF_JMP | BPF_JEQ | BPF_K))
            .map(|i| i.k)
            .collect()
    }

    #[test]
    fn test_base_filter_includes_getpid() {
        let filter = build_base_filter();
        let nrs = syscall_numbers(&filter);
        assert!(nrs.contains(&39), "base filter must allow getpid (39)");
    }

    #[test]
    fn test_base_filter_denies_socket() {
        let filter = build_base_filter();
        let nrs = syscall_numbers(&filter);
        assert!(!nrs.contains(&41), "base filter must not allow socket (41)");
    }

    #[test]
    fn test_app_filter_adds_syscall() {
        let filter = build_app_filter("test_app", &[41]); // SYS_socket
        let nrs = syscall_numbers(&filter);
        assert!(
            nrs.contains(&41),
            "app filter with socket addition must allow socket (41)"
        );
    }

    #[test]
    fn test_trap_mode_changes_only_the_deny_action() {
        // The base allowlist remains unchanged; trap mode only changes the
        // final action for a denied syscall.
        std::env::set_var("WEAVE_SECCOMP_TRAP", "1");
        let filter = build_app_filter("test_app", &[]);
        std::env::remove_var("WEAVE_SECCOMP_TRAP");

        assert_eq!(filter[filter.len() - 2].k, SECCOMP_RET_TRAP);
        assert_eq!(
            syscall_numbers(&filter),
            syscall_numbers(&build_base_filter())
        );
    }

    #[test]
    fn test_base_filter_has_correct_length() {
        let filter = build_base_filter();
        // Prologue: 4 insns (LD arch, JEQ arch, RET kill, LD nr)
        // 18 base checks
        // Epilogue: 2 insns (RET deny, RET allow)
        assert_eq!(
            filter.len(),
            24,
            "base filter must have 4 + 18 + 2 = 24 instructions"
        );
    }

    #[test]
    fn test_app_filter_length_with_additions() {
        let filter = build_app_filter("test_app", &[16, 41, 234]); // ioctl, socket, tgkill
        let nrs = syscall_numbers(&filter);
        assert_eq!(nrs.len(), 21, "must have 18 base + 3 added syscalls");
        assert!(nrs.contains(&16));
        assert!(nrs.contains(&41));
        assert!(nrs.contains(&234));
    }

    #[test]
    fn test_apply_seccomp_returns_ok_on_non_linux() {
        assert!(apply_seccomp("test.exe").is_ok());
    }
}
