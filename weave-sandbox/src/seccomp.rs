//! seccomp-BPF syscall filter for the child process.
//!
//! Applied in the forked child (SB1a) before jumping to the guest entry point.
//! Uses raw BPF instructions to build a minimal allowlist filter.

/// Apply a seccomp-BPF filter that allows only the allowlisted syscalls.
///
/// Must be called before any guest code runs. On success, prints
/// `PHASE: seccomp_applied` to stderr.
///
/// On non-Linux platforms this is a no-op that returns `Ok(())`.
pub fn apply_seccomp() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        return apply_seccomp_inner();
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn apply_seccomp_inner() -> Result<(), String> {
    const SECCOMP_MODE_FILTER: libc::c_int = 2;

    // BPF instruction encoding.
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

    // x86_64 audit architecture identifier.
    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

    // Offsets into `struct seccomp_data`.
    const DATA_NR: u32 = 0;
    const DATA_ARCH: u32 = 4;

    #[repr(C)]
    struct sock_filter {
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

    // ── allowlist (18 x86_64 syscalls) ────────────────────────────────
    // read=0, write=1, close=3, mmap=9, mprotect=10, munmap=11, brk=12,
    // rt_sigaction=13, rt_sigprocmask=14, sigreturn=15, getpid=39, exit=60,
    // gettid=186, futex=202, restart_syscall=219, clock_gettime=228,
    // exit_group=231, openat=257
    const ALLOWED: [u32; 18] = [
        0, 1, 3, 9, 10, 11, 12, 13, 14, 15, 39, 60, 186, 202, 219, 228, 231, 257,
    ];

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

    // ── build BPF program ───────────────────────────────────────────────
    //
    // Instruction layout:
    //   0:     LD arch
    //   1:     JEQ AUDIT_ARCH_X86_64, +1, +0   (skip kill on match)
    //   2:     RET KILL_PROCESS                (wrong arch)
    //   3:     LD nr
    //   4..:   JEQ <syscall>, +jt, +0          (N checks)
    //   4+N:   RET KILL_PROCESS                (no syscall matched)
    //   5+N:   RET ALLOW                       (match label)

    let n = ALLOWED.len();
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
    for (i, &sysnr) in ALLOWED.iter().enumerate() {
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
        k: SECCOMP_RET_KILL_PROCESS,
    });
    insns.push(sock_filter {
        code: BPF_RET,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

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
        eprintln!("PHASE: seccomp_applied");
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

    #[test]
    #[cfg_attr(target_os = "linux", ignore = "requires seccomp-enabled kernel, tested in integration")]
    fn test_apply_seccomp_returns_ok_on_non_linux() {
        assert!(apply_seccomp().is_ok());
    }
}
