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
//! TEB fields populated for Phase 1:
//!
//!   TEB + 0x030 → Self pointer (points back to TEB base)
//!   TEB + 0x058 → ThreadLocalStoragePointer → TLS slot array[0] → TLS data
//!   TEB + 0x060 → pointer to PEB
//!   PEB + 0x020 → pointer to RTL_USER_PROCESS_PARAMETERS
//!   ProcessParameters + 0x028 → StandardOutput handle (fd 1)
//!
//! The TLS slot array is a flat array of 64 u64 pointers. Slot 0 points to a
//! copy of the PE's raw TLS initialisation data (or a zeroed block if the PE
//! has no TLS). This is the minimum needed to keep CRT startup code from
//! crashing when it reads its per-thread state via GS:[0x58].

use crate::handles;
use crate::loader::LoadedImage;

// Number of TLS pointer slots to allocate.  The Windows CRT only uses slot 0
// in a single-threaded process, so 64 gives plenty of headroom.
const TLS_SLOTS: usize = 64;
// Minimum size for the per-thread TLS data block (in bytes).
const TLS_DATA_MIN: usize = 256;

/// Holds the allocated TEB, PEB, ProcessParameters, and TLS buffers.
/// Must stay alive for the lifetime of the process.
#[allow(dead_code)]
pub struct TebState {
    teb: Box<[u8; 4096]>,
    peb: Box<[u8; 4096]>,
    params: Box<[u8; 4096]>,
    tls_slots: Box<[u64; TLS_SLOTS]>,
    tls_data: Box<[u8]>,
}

/// Allocate and initialise the TEB/PEB/TLS and point GS at the TEB.
///
/// `image` is used only to locate and copy the PE's TLS raw data into the
/// per-thread TLS block. If the PE has no TLS, a zeroed block is used.
///
/// On non-Linux platforms this is a no-op at runtime (GS won't be set) but
/// the function still returns `Ok(state)` so the caller can hold the memory.
pub fn setup(image: &LoadedImage) -> Result<TebState, String> {
    let mut teb = Box::new([0u8; 4096]);
    let mut peb = Box::new([0u8; 4096]);
    let mut params = Box::new([0u8; 4096]);

    // ── TLS slot array and per-thread data block ──────────────────────────
    let mut tls_slots = Box::new([0u64; TLS_SLOTS]);

    let tls_size = image.tls_data_size.max(TLS_DATA_MIN);
    let mut tls_data = vec![0u8; tls_size].into_boxed_slice();

    // Copy PE raw TLS initialisation data into our block.
    if !image.tls_data.is_null() && image.tls_data_size > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(
                image.tls_data,
                tls_data.as_mut_ptr(),
                image.tls_data_size,
            );
        }
    }

    let teb_ptr = teb.as_mut_ptr();
    let peb_ptr = peb.as_mut_ptr();
    let params_ptr = params.as_mut_ptr();
    let tls_slots_ptr = tls_slots.as_mut_ptr();
    let tls_data_ptr = tls_data.as_mut_ptr();

    unsafe {
        // TLS slot 0 → per-thread data block
        (*tls_slots_ptr) = tls_data_ptr as u64;

        // TEB[0x030] = &TEB  (NT_TIB.Self — the TEB points to itself)
        write_u64(teb_ptr, 0x030, teb_ptr as u64);

        // TEB[0x058] = ThreadLocalStoragePointer → TLS slot array
        write_u64(teb_ptr, 0x058, tls_slots_ptr as u64);

        // TEB[0x060] = &PEB
        write_u64(teb_ptr, 0x060, peb_ptr as u64);

        // PEB[0x020] = &ProcessParameters
        write_u64(peb_ptr, 0x020, params_ptr as u64);

        // ProcessParameters[0x028] = stdout handle (Weave HANDLE table value)
        write_u64(params_ptr, 0x028, handles::STDOUT_HANDLE as u64);
    }

    #[cfg(target_os = "linux")]
    {
        // arch_prctl(ARCH_SET_GS, teb_ptr)
        let ret = unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1001i64, teb_ptr as i64) };
        if ret != 0 {
            return Err(format!(
                "arch_prctl(ARCH_SET_GS) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    Ok(TebState {
        teb,
        peb,
        params,
        tls_slots,
        tls_data,
    })
}

unsafe fn write_u64(base: *mut u8, offset: usize, value: u64) {
    *(base.add(offset) as *mut u64) = value;
}
