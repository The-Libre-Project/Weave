//! Thread Environment Block (TEB) and Process Environment Block (PEB) setup.
//!
//! Every Windows x86-64 binary expects the GS segment register to point to a
//! valid TEB. The TEB contains a pointer to the PEB, which contains a pointer
//! to the process parameters (which include stdin/stdout/stderr handles).
//!
//! On Linux x86-64, GS is not used by the kernel or Rust runtime (Rust uses
//! FS for thread-local storage). We set GS via arch_prctl(ARCH_SET_GS) to
//! point to our fake TEB before jumping to the PE entry point.
//!
//! Minimum layout we must populate for hello_minimal.exe:
//!
//!   TEB + 0x030 → Self pointer (points back to TEB base)
//!   TEB + 0x060 → pointer to PEB
//!   PEB + 0x020 → pointer to RTL_USER_PROCESS_PARAMETERS
//!   ProcessParameters + 0x028 → StandardOutput handle
//!
//! The StandardOutput handle is set to 1 — the Linux stdout file descriptor.
//! Our NtWriteFile stub passes this value directly to Linux write(2).

/// Holds the allocated TEB, PEB, and ProcessParameters buffers.
/// Must stay alive for the lifetime of the process (use `Box::leak` or keep
/// a reference in a static).
#[allow(dead_code)]
pub struct TebState {
    teb: Box<[u8; 4096]>,
    peb: Box<[u8; 4096]>,
    params: Box<[u8; 4096]>,
}

/// Allocate and initialise a minimal TEB/PEB and point GS at it.
///
/// On non-Linux platforms this returns `Ok(())` without doing anything —
/// the binary will fault when it reads GS, but at least it compiles.
pub fn setup() -> Result<TebState, String> {
    let mut teb = Box::new([0u8; 4096]);
    let mut peb = Box::new([0u8; 4096]);
    let mut params = Box::new([0u8; 4096]);

    let teb_ptr = teb.as_mut_ptr();
    let peb_ptr = peb.as_mut_ptr();
    let params_ptr = params.as_mut_ptr();

    unsafe {
        // TEB[0x030] = &TEB  (NT_TIB.Self — the TEB points to itself)
        write_u64(teb_ptr, 0x030, teb_ptr as u64);

        // TEB[0x060] = &PEB
        write_u64(teb_ptr, 0x060, peb_ptr as u64);

        // PEB[0x020] = &ProcessParameters
        write_u64(peb_ptr, 0x020, params_ptr as u64);

        // ProcessParameters[0x028] = stdout handle
        // We use fd 1 (Linux stdout) directly as the handle value.
        write_u64(params_ptr, 0x028, 1u64);
    }

    #[cfg(target_os = "linux")]
    {
        // arch_prctl(ARCH_SET_GS, teb_ptr)
        // ARCH_SET_GS = 0x1001, SYS_arch_prctl = 158
        let ret = unsafe {
            libc::syscall(libc::SYS_arch_prctl, 0x1001i64, teb_ptr as i64)
        };
        if ret != 0 {
            return Err(format!(
                "arch_prctl(ARCH_SET_GS) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    Ok(TebState { teb, peb, params })
}

unsafe fn write_u64(base: *mut u8, offset: usize, value: u64) {
    *(base.add(offset) as *mut u64) = value;
}
