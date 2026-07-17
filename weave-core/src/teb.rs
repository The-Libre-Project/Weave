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

use std::mem::ManuallyDrop;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use crate::handles;
use crate::loader::LoadedImage;

// Number of TLS pointer slots to allocate.  The Windows CRT only uses slot 0
// in a single-threaded process, so 64 gives plenty of headroom.
const TLS_SLOTS: usize = 64;

// TLS template from the main PE image — set in setup(), read in setup_thread().
// tls_data is a pointer into the mapped PE image and lives for the process lifetime.
static PE_TLS_SRC: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static PE_TLS_SRC_SIZE: AtomicUsize = AtomicUsize::new(0);
// Minimum size for the per-thread TLS data block (in bytes).
const TLS_DATA_MIN: usize = 256;

// TEB reservation size. Real Windows 10 x64 per-thread data (static TLS, NT
// heap thread state, CRT per-thread vars) has been observed at GS+0x68e10
// (~429KB) under DXVK/MinGW builds. 512KB covers that with margin.
const TEB_SIZE: usize = 0x80000;

/// Holds the allocated TEB, PEB, ProcessParameters, and TLS buffers.
/// Must stay alive for the lifetime of the process.
#[allow(dead_code)]
pub struct TebState {
    teb: Box<[u8]>,
    peb: Box<[u8; 4096]>,
    params: Box<[u8; 4096]>,
    /// TLS slots array. Backed by MAP_32BIT mmap on Linux; freed via munmap
    /// in the custom Drop impl (not via Box drop, which would call free()).
    tls_slots: ManuallyDrop<Box<[u64]>>,
    /// TLS data block. Same backing/free scheme as tls_slots.
    tls_data: ManuallyDrop<Box<[u8]>>,
}

impl Drop for TebState {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        unsafe {
            let slots_sz = std::mem::size_of::<u64>() * TLS_SLOTS;
            libc::munmap(self.tls_slots.as_ptr() as *mut libc::c_void, slots_sz);
            libc::munmap(
                self.tls_data.as_ptr() as *mut libc::c_void,
                self.tls_data.len(),
            );
        }
    }
}

/// Allocate memory below 4 GiB using MAP_32BIT. Returns a leaked pointer.
/// MSVC CRT code does 32-bit stores to TLS data structures (e.g. `_onexit_table`).
/// When the TLS data is at a high address (>4 GiB), these stores corrupt adjacent
/// 64-bit pointer fields (producing addresses like PE_base&0xFFFFFFFF00000000).
/// MAP_32BIT keeps data under 4 GiB so the corrupted high bits remain 0.
/// Falls back to `mmap(NULL, ...)` (non-MAP_32BIT) when unavailable.
#[cfg(target_os = "linux")]
fn alloc_low<T: Default + Copy>(n: usize) -> (*mut T, usize) {
    const MAP_32BIT: i32 = 0x40;
    let size = n * std::mem::size_of::<T>();
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_32BIT,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        panic!("MAP_32BIT allocation of {size} bytes failed");
    }
    (ptr as *mut T, size)
}

#[cfg(not(target_os = "linux"))]
fn alloc_low<T: Default + Copy>(n: usize) -> (*mut T, usize) {
    let size = n * std::mem::size_of::<T>();
    let ptr = unsafe { std::alloc::alloc(std::alloc::Layout::from_size_align(size, 16).unwrap()) };
    (ptr as *mut T, size)
}

pub fn setup(image: &LoadedImage) -> Result<TebState, String> {
    let mut teb = vec![0u8; TEB_SIZE].into_boxed_slice();
    let mut peb = Box::new([0u8; 4096]);
    let mut params = Box::new([0u8; 4096]);

    // ── TLS slot array and per-thread data block (below 4 GiB) ──────────
    // MSVC CRT code does 32-bit stores to CRT internal structs in TLS data
    // (e.g. `_onexit_table` init via the wrappers at Audacity RVAs 0x53da10/5c/e0).
    // MAP_32BIT prevents corruption of adjacent 64-bit pointer fields.
    let (tls_slots_raw, _) = alloc_low::<u64>(TLS_SLOTS);
    let tls_size = image.tls_data_size.max(TLS_DATA_MIN);
    let (tls_data_raw, _) = alloc_low::<u8>(tls_size);
    // SAFETY: alloc_low returns valid mmap'd memory. Wrap in ManuallyDrop so
    // our custom Drop (via munmap) runs instead of the Box drop (via free).
    let tls_slots = ManuallyDrop::new(unsafe {
        Box::from_raw(std::ptr::slice_from_raw_parts_mut(tls_slots_raw, TLS_SLOTS))
    });
    let tls_data = ManuallyDrop::new(unsafe {
        Box::from_raw(std::ptr::slice_from_raw_parts_mut(tls_data_raw, tls_size))
    });

    // Store TLS template for threads spawned later via CreateThread.
    // The PE image stays mapped for the process lifetime, so this pointer is valid.
    PE_TLS_SRC.store(image.tls_data as *mut u8, Ordering::Relaxed);
    PE_TLS_SRC_SIZE.store(image.tls_data_size, Ordering::Relaxed);

    // Copy PE raw TLS initialisation data into our block.
    if !image.tls_data.is_null() && image.tls_data_size > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(image.tls_data, tls_data_raw, image.tls_data_size);
        }
    }

    let teb_ptr = teb.as_mut_ptr();
    let peb_ptr = peb.as_mut_ptr();
    let params_ptr = params.as_mut_ptr();
    // SAFETY: mmap MAP_32BIT memory below 4 GiB. Read-only for the TEB setup.
    let tls_slots_ptr = tls_slots.as_ptr() as *mut u64;
    let tls_data_ptr = tls_data.as_ptr() as *mut u8;

    // Determine the current thread's stack bounds so we can populate
    // NT_TIB.StackBase (high addr) and NT_TIB.StackLimit (low addr).
    // Windows code (including the MSVC CRT security cookie initialisation)
    // reads these fields during startup. Leaving them as 0 causes crashes.
    #[cfg(target_os = "linux")]
    let (stack_base, stack_limit) = {
        let mut attr: libc::pthread_attr_t = unsafe { std::mem::zeroed() };
        let mut stack_addr: *mut libc::c_void = std::ptr::null_mut();
        let mut stack_size: libc::size_t = 0;
        unsafe {
            libc::pthread_getattr_np(libc::pthread_self(), &mut attr);
            libc::pthread_attr_getstack(&attr, &mut stack_addr, &mut stack_size);
            libc::pthread_attr_destroy(&mut attr);
        }
        let low = stack_addr as u64;
        let high = low + stack_size as u64;
        (high, low) // StackBase = high addr, StackLimit = low addr
    };

    #[cfg(not(target_os = "linux"))]
    let (stack_base, stack_limit) = (0u64, 0u64);

    unsafe {
        // TLS slot 0 → per-thread data block
        (*tls_slots_ptr) = tls_data_ptr as u64;

        // NT_TIB.StackBase  — TEB[0x008]: high end of the stack (grows down)
        write_u64(teb_ptr, 0x008, stack_base);

        // NT_TIB.StackLimit — TEB[0x010]: low end of the stack (guard page)
        write_u64(teb_ptr, 0x010, stack_limit);

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

/// Allocate and initialise a TEB for a thread spawned via CreateThread.
///
/// Must be called at the top of the thread closure, before any PE code runs.
/// The returned `TebState` must be kept alive until the thread exits — drop it
/// at end of scope so GS-relative memory stays valid for the thread's lifetime.
///
/// Uses the TLS template stored by `setup()` so each thread gets its own
/// initialised copy of the PE's static TLS data.
pub fn setup_thread() -> TebState {
    let mut teb = vec![0u8; TEB_SIZE].into_boxed_slice();
    let mut peb = Box::new([0u8; 4096]);
    let mut params = Box::new([0u8; 4096]);
    let (tls_slots_raw, _) = alloc_low::<u64>(TLS_SLOTS);
    let src_ptr = PE_TLS_SRC.load(Ordering::Relaxed);
    let src_size = PE_TLS_SRC_SIZE.load(Ordering::Relaxed);
    let tls_size = src_size.max(TLS_DATA_MIN);
    let (tls_data_raw, _) = alloc_low::<u8>(tls_size);
    let tls_slots = ManuallyDrop::new(unsafe {
        Box::from_raw(std::ptr::slice_from_raw_parts_mut(tls_slots_raw, TLS_SLOTS))
    });
    let tls_data = ManuallyDrop::new(unsafe {
        Box::from_raw(std::ptr::slice_from_raw_parts_mut(tls_data_raw, tls_size))
    });

    if !src_ptr.is_null() && src_size > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(src_ptr, tls_data.as_ptr() as *mut u8, src_size);
        }
    }

    let teb_ptr = teb.as_mut_ptr();
    let peb_ptr = peb.as_mut_ptr();
    let params_ptr = params.as_mut_ptr();
    let tls_slots_ptr = tls_slots.as_ptr() as *mut u64;
    let tls_data_ptr = tls_data.as_ptr() as *mut u8;

    #[cfg(target_os = "linux")]
    let (stack_base, stack_limit) = {
        let mut attr: libc::pthread_attr_t = unsafe { std::mem::zeroed() };
        let mut stack_addr: *mut libc::c_void = std::ptr::null_mut();
        let mut stack_size: libc::size_t = 0;
        unsafe {
            libc::pthread_getattr_np(libc::pthread_self(), &mut attr);
            libc::pthread_attr_getstack(&attr, &mut stack_addr, &mut stack_size);
            libc::pthread_attr_destroy(&mut attr);
        }
        let low = stack_addr as u64;
        let high = low + stack_size as u64;
        (high, low)
    };

    #[cfg(not(target_os = "linux"))]
    let (stack_base, stack_limit) = (0u64, 0u64);

    unsafe {
        (*tls_slots_ptr) = tls_data_ptr as u64;
        write_u64(teb_ptr, 0x008, stack_base);
        write_u64(teb_ptr, 0x010, stack_limit);
        write_u64(teb_ptr, 0x030, teb_ptr as u64);
        write_u64(teb_ptr, 0x058, tls_slots_ptr as u64);
        write_u64(teb_ptr, 0x060, peb_ptr as u64);
        write_u64(peb_ptr, 0x020, params_ptr as u64);
        write_u64(params_ptr, 0x028, handles::STDOUT_HANDLE as u64);
    }

    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1001i64, teb_ptr as i64) };
        if ret != 0 {
            eprintln!(
                "weave: CreateThread TEB arch_prctl failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    TebState {
        teb,
        peb,
        params,
        tls_slots,
        tls_data,
    }
}
