//! Signal-to-exception translation for PE code running on Linux.
//!
//! When PE code crashes (SIGSEGV, SIGFPE, SIGILL, SIGBUS), the Linux kernel
//! delivers a signal. This module intercepts those signals and:
//!
//!   1. Checks whether the faulting instruction pointer (RIP) is inside the
//!      mapped PE image. If not, the fault is in Weave's own Rust code — the
//!      default handler is restored and the signal is re-raised so Rust's panic
//!      machinery handles it normally.
//!
//!   2. If the fault IS in PE code, it builds a crash report:
//!      - The Windows exception code equivalent of the Linux signal
//!      - The faulting address and PE-relative RVA
//!      - The function range from the PE's .pdata exception table (so we know
//!        which function crashed without a symbol table)
//!      - A full general-purpose register dump in Windows CONTEXT order
//!
//!   3. Exits with the Windows exception code as the process exit status
//!      (e.g., 0xC0000005 for STATUS_ACCESS_VIOLATION), matching what Windows
//!      itself returns when an unhandled exception terminates a process.
//!
//! Full SEH dispatch (building EXCEPTION_RECORD + CONTEXT and walking the
//! .pdata exception handler chain) is Phase 2 work.

use crate::loader::LoadedImage;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

// ── Lock-free loaded-module range table ────────────────────────────────────
//
// Signal-handler safe — no locks, no heap, fixed-size array.  Allows the
// signal handler to identify crashes in loaded DLLs (not just the main PE).
const MAX_LOADED_MODULES: usize = 256;
static LOADED_MODULES_BASE: [AtomicUsize; MAX_LOADED_MODULES] =
    [const { AtomicUsize::new(0) }; MAX_LOADED_MODULES];
static LOADED_MODULES_SIZE: [AtomicUsize; MAX_LOADED_MODULES] =
    [const { AtomicUsize::new(0) }; MAX_LOADED_MODULES];
static LOADED_MODULES_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Register a loaded module so the signal handler can identify crashes within it.
/// Signal-handler safe — uses relaxed atomics.
pub fn register_loaded_module(base: usize, size: usize) {
    let idx = LOADED_MODULES_COUNT.fetch_add(1, Ordering::Relaxed);
    if idx < MAX_LOADED_MODULES {
        LOADED_MODULES_BASE[idx].store(base, Ordering::Relaxed);
        LOADED_MODULES_SIZE[idx].store(size, Ordering::Relaxed);
    }
}

/// Check if an address falls within any registered loaded module.
fn addr_in_loaded_module(rip: usize) -> bool {
    find_loaded_module(rip).is_some()
}

/// Find the base address of the loaded module containing `rip`, if any.
fn find_loaded_module(rip: usize) -> Option<usize> {
    let count = LOADED_MODULES_COUNT.load(Ordering::Relaxed);
    for i in 0..count.min(MAX_LOADED_MODULES) {
        let b = LOADED_MODULES_BASE[i].load(Ordering::Relaxed);
        let s = LOADED_MODULES_SIZE[i].load(Ordering::Relaxed);
        if rip >= b && rip < b + s {
            return Some(b);
        }
    }
    None
}

/// Find the INDEX of the loaded module containing `rip`, if any.
/// Returns the index into LOADED_MODULES_BASE/SIZE.
fn find_loaded_module_index(rip: usize) -> Option<usize> {
    let count = LOADED_MODULES_COUNT.load(Ordering::Relaxed);
    for i in 0..count.min(MAX_LOADED_MODULES) {
        let b = LOADED_MODULES_BASE[i].load(Ordering::Relaxed);
        let s = LOADED_MODULES_SIZE[i].load(Ordering::Relaxed);
        if rip >= b && rip < b + s {
            return Some(i);
        }
    }
    None
}

// ── Global PE metadata for async-signal-safe access ──────────────────────────
//
// Signal handlers cannot safely access complex data structures (locks, heap,
// etc.), so we cache only what we need as plain atomics.

/// Global unhandled-exception filter, installed by `SetUnhandledExceptionFilter`.
/// Called from `dispatch_exception` when no SEH handler is found.
pub static UEF_HANDLER: AtomicUsize = AtomicUsize::new(0);

pub(crate) static PE_BASE: AtomicUsize = AtomicUsize::new(0);
pub(crate) static PE_SIZE: AtomicUsize = AtomicUsize::new(0);
pub(crate) static PDATA_RVA: AtomicUsize = AtomicUsize::new(0);
pub(crate) static PDATA_SIZE: AtomicUsize = AtomicUsize::new(0);
/// IMAGE_FILE_HEADER.Machine value of the loaded guest PE.
/// 0x014c = IMAGE_FILE_MACHINE_I386 (32-bit); 0x8664 = AMD64 (64-bit).
/// Stored as u32 so it fits in an AtomicU32; only the low 16 bits are used.
pub(crate) static PE_MACHINE: AtomicU32 = AtomicU32::new(0);

// ── SEH runaway cap ──────────────────────────────────────────────────────────
//
// When a guest fault is dispatched through the SEH chain and no handler
// actually consumes it (or a handler returns EXCEPTION_CONTINUE_EXECUTION
// without advancing RIP past the faulting instruction), the signal handler
// returns to the same RIP, faults again, and spins forever.  Observed
// instance: Task 01b Dispatch 2 — wget.exe NULL-deref at +0x12b5 produced
// 89M log lines / 4.1 GB of stderr before being killed externally.
//
// Cap consecutive re-faults at the same RIP and terminate cleanly with a
// diagnostic rather than letting the process spin.  The threshold is
// conservative: a legitimate tight watchdog retry loop in guest code could
// briefly trip this, but 16 identical-RIP faults in a row is well beyond
// any known Windows pattern and firmly indicates unhandled-fault spin.
//
// Signal-handler safety: both counters are plain atomics (no locks, no
// heap).  Writes use `libc::write` to a fixed stack buffer; termination
// uses `libc::_exit` to skip atexit handlers that are not async-signal-safe.
#[cfg(target_os = "linux")]
const SEH_RUNAWAY_CAP: u32 = 16;

#[cfg(target_os = "linux")]
static LAST_FAULT_RIP: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_os = "linux")]
static CONSECUTIVE_FAULTS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

// ── Public API ────────────────────────────────────────────────────────────────

/// Register the PE's address range and install signal handlers.
///
/// Must be called after [`crate::teb::setup`] and before jumping to the entry
/// point.  Replaces any previously installed handlers for the four crash
/// signals.  On non-Linux platforms this is a no-op.
pub fn install(image: &LoadedImage) {
    PE_BASE.store(image.base as usize, Ordering::Relaxed);
    PE_SIZE.store(image.size, Ordering::Relaxed);
    PDATA_RVA.store(image.pdata_rva, Ordering::Relaxed);
    PDATA_SIZE.store(image.pdata_size, Ordering::Relaxed);
    PE_MACHINE.store(u32::from(image.machine), Ordering::Relaxed);

    #[cfg(target_os = "linux")]
    {
        install_one(libc::SIGSEGV);
        install_one(libc::SIGFPE);
        install_one(libc::SIGILL);
        install_one(libc::SIGBUS);
        install_one(libc::SIGABRT);
        eprintln!("weave: exception handlers installed");
    }
}

/// Return the base address at which the guest PE is mapped.
///
/// Returns 0 if called before [`install`].
pub fn pe_base() -> usize {
    PE_BASE.load(Ordering::Relaxed)
}

/// Return the size (in bytes) of the mapped guest PE image.
///
/// Returns 0 if called before [`install`].
pub fn pe_size() -> usize {
    PE_SIZE.load(Ordering::Relaxed)
}

/// Return the IMAGE_FILE_HEADER.Machine value of the guest PE.
///
/// Common values: 0x014c (IMAGE_FILE_MACHINE_I386 — 32-bit x86),
/// 0x8664 (IMAGE_FILE_MACHINE_AMD64 — 64-bit x86-64).
/// Returns 0 if called before [`install`].
pub fn pe_machine() -> u16 {
    PE_MACHINE.load(Ordering::Relaxed) as u16
}

// ── Signal handler installation ───────────────────────────────────────────────

// Alternate signal stack — written once at startup, before any threads.
#[cfg(target_os = "linux")]
static mut ALT_STACK_BUF: [u8; 65536] = [0u8; 65536];

#[cfg(target_os = "linux")]
fn install_one(sig: libc::c_int) {
    unsafe {
        // Set up an alternate signal stack so delivery works even when RSP is
        // in a PE stack segment (or otherwise invalid at fault time).
        static ALTSTACK_INSTALLED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        if !ALTSTACK_INSTALLED.swap(true, Ordering::Relaxed) {
            let ss = libc::stack_t {
                ss_sp: std::ptr::addr_of_mut!(ALT_STACK_BUF) as *mut _,
                ss_flags: 0,
                ss_size: 65536,
            };
            libc::sigaltstack(&ss as *const _, std::ptr::null_mut());
        }

        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        sa.sa_sigaction = on_fatal_signal as unsafe extern "C" fn(_, _, _) as usize;
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

// ── Signal handler ────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
unsafe extern "C" fn on_fatal_signal(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    ctx: *mut libc::c_void,
) {
    unsafe {
        libc::write(
            2,
            b"weave: signal handler entered\n".as_ptr() as *const _,
            30,
        );
    }
    let uctx = ctx as *const libc::ucontext_t;
    let rip = unsafe { (*uctx).uc_mcontext.gregs[libc::REG_RIP as usize] as usize };
    let rsi = unsafe { (*uctx).uc_mcontext.gregs[libc::REG_RSI as usize] as usize };
    unsafe {
        libc::write(2, b"weave: sh got rip\n".as_ptr() as *const _, 18);
    }
    // Debug: print the fault address to understand where crashes happen.
    // Hex-format RIP into a small stack buffer.
    let mut rip_hex = [0u8; 48];
    rip_hex[..19].copy_from_slice(b"weave: fault rip=0x");
    let nibble = |v: u8| if v < 10 { b'0' + v } else { b'a' + v - 10 };
    for i in 0..16 {
        let shift = (15 - i) * 4;
        rip_hex[19 + i] = nibble(((rip as u64 >> shift) & 0xf) as u8);
    }
    rip_hex[35] = b'\n';
    unsafe {
        libc::write(2, rip_hex.as_ptr() as *const _, 36);
    }

    let base = PE_BASE.load(Ordering::Relaxed);
    let size = PE_SIZE.load(Ordering::Relaxed);

    if (base != 0 && rip >= base && rip < base + size) || addr_in_loaded_module(rip) {
        let _in_loaded = addr_in_loaded_module(rip);
        // ── SEH runaway cap ──────────────────────────────────────────────── ────────────────────────────────────────────────
        // If the same RIP faults repeatedly, no handler is actually resolving
        // the exception.  Cap consecutive identical-RIP faults and terminate
        // cleanly rather than spinning forever.  See `SEH_RUNAWAY_CAP`
        // rationale at the top of this file.  All operations here are
        // async-signal-safe: atomic load/store, fixed stack buffer, libc::write,
        // libc::_exit (not exit — we skip atexit handlers inside a handler).
        {
            let prev = LAST_FAULT_RIP.load(Ordering::Relaxed);
            let count = if prev == rip {
                CONSECUTIVE_FAULTS.fetch_add(1, Ordering::Relaxed) + 1
            } else {
                LAST_FAULT_RIP.store(rip, Ordering::Relaxed);
                CONSECUTIVE_FAULTS.store(1, Ordering::Relaxed);
                1
            };
            if count > SEH_RUNAWAY_CAP {
                unsafe {
                    let mut buf = [0u8; 128];
                    let mut pos = 0usize;
                    let nibble = |n: u64| {
                        if n < 10 {
                            b'0' + n as u8
                        } else {
                            b'a' + n as u8 - 10
                        }
                    };
                    for &b in b"weave: SEH runaway at rip=0x" {
                        if pos < buf.len() {
                            buf[pos] = b;
                            pos += 1;
                        }
                    }
                    for sh in (0..16u32).rev() {
                        let n = (rip as u64 >> (sh * 4)) & 0xf;
                        if pos < buf.len() {
                            buf[pos] = nibble(n);
                            pos += 1;
                        }
                    }
                    for &b in b" -- unhandled guest fault looping; terminating\n" {
                        if pos < buf.len() {
                            buf[pos] = b;
                            pos += 1;
                        }
                    }
                    libc::write(2, buf.as_ptr() as *const libc::c_void, pos);
                    libc::_exit(134);
                }
            }
        }

        // Fault in PE code — try SEH dispatch first (Windows delivers hardware
        // exceptions through KiUserExceptionDispatcher → RtlDispatchException).
        let fault_addr = unsafe { (*info).si_addr() } as usize;
        let rva = (rip - base) as u32;
        // Log RIP/RVA/fault_addr before SEH dispatch (dispatch can crash recursively,
        // making post-dispatch logging unreachable).
        unsafe {
            let mut buf = [0u8; 128];
            let mut pos = 0usize;
            let nibble = |n: u64| {
                if n < 10 {
                    b'0' + n as u8
                } else {
                    b'a' + n as u8 - 10
                }
            };
            for &b in b"weave: sh fault rip=0x" {
                if pos < buf.len() {
                    buf[pos] = b;
                    pos += 1;
                }
            }
            for sh in (0..16u32).rev() {
                let n = (rip as u64 >> (sh * 4)) & 0xf;
                if pos < buf.len() {
                    buf[pos] = nibble(n);
                    pos += 1;
                }
            }
            for &b in b" rva=0x" {
                if pos < buf.len() {
                    buf[pos] = b;
                    pos += 1;
                }
            }
            for sh in (0..8u32).rev() {
                let n = (rva as u64 >> (sh * 4)) & 0xf;
                if pos < buf.len() {
                    buf[pos] = nibble(n);
                    pos += 1;
                }
            }
            for &b in b" fault=0x" {
                if pos < buf.len() {
                    buf[pos] = b;
                    pos += 1;
                }
            }
            for sh in (0..16u32).rev() {
                let n = (fault_addr as u64 >> (sh * 4)) & 0xf;
                if pos < buf.len() {
                    buf[pos] = nibble(n);
                    pos += 1;
                }
            }
            for &b in b" rsi=0x" {
                if pos < buf.len() {
                    buf[pos] = b;
                    pos += 1;
                }
            }
            for sh in (0..16u32).rev() {
                let n = (rsi as u64 >> (sh * 4)) & 0xf;
                if pos < buf.len() {
                    buf[pos] = nibble(n);
                    pos += 1;
                }
            }
            buf[pos] = b'\n';
            pos += 1;
            libc::write(2, buf.as_ptr() as *const _, pos);
        }
        // Log the loaded module base if RIP is in a pre-loaded side DLL.
        if let Some(mod_base) = find_loaded_module(rip) {
            let mod_idx = find_loaded_module_index(rip).unwrap_or(usize::MAX);
            let mod_rva = rip - mod_base;
            let mut mbuf = [0u8; 80];
            let mut mpos = 0usize;
            let nibble = |n: u64| {
                if n < 10 {
                    b'0' + n as u8
                } else {
                    b'a' + n as u8 - 10
                }
            };
            for &b in b"weave: sh mod[" {
                mbuf[mpos] = b;
                mpos += 1;
            }
            // Module index as decimal (0-255)
            if mod_idx >= 100 {
                mbuf[mpos] = b'0' + (mod_idx / 100) as u8;
                mpos += 1;
            }
            if mod_idx >= 10 {
                mbuf[mpos] = b'0' + ((mod_idx / 10) % 10) as u8;
                mpos += 1;
            }
            mbuf[mpos] = b'0' + (mod_idx % 10) as u8;
            mpos += 1;
            for &b in b"] rva=0x" {
                mbuf[mpos] = b;
                mpos += 1;
            }
            for sh in (0..8u32).rev() {
                mbuf[mpos] = nibble((mod_rva as u64 >> (sh * 4)) & 0xf);
                mpos += 1;
            }
            for &b in b" base=0x" {
                mbuf[mpos] = b;
                mpos += 1;
            }
            for sh in (0..16u32).rev() {
                mbuf[mpos] = nibble((mod_base as u64 >> (sh * 4)) & 0xf);
                mpos += 1;
            }
            mbuf[mpos] = b'\n';
            mpos += 1;
            unsafe {
                libc::write(2, mbuf.as_ptr() as *const _, mpos);
            }
            // ── C++ `this` diagnostic ──────────────────────────────────────
            // In x64 Win64 ABI, RCX holds the `this` pointer for non-static
            // member functions.  Print RCX and, if non-null, try to read the
            // vtable pointer at [RCX] via /proc/self/mem.  Also print RDI
            // (used for `this` in some MSVC calling-convention variants) and
            // the return-address chain at [RSP..RSP+32].
            {
                let gregs = (*uctx).uc_mcontext.gregs;
                let rcx = gregs[libc::REG_RCX as usize] as usize;
                let rdi = gregs[libc::REG_RDI as usize] as usize;
                let _rsp = gregs[libc::REG_RSP as usize] as usize;
                let mut tbuf = [0u8; 160];
                let mut tpos = 0usize;
                let nibble = |n: u64| {
                    if n < 10 {
                        b'0' + n as u8
                    } else {
                        b'a' + n as u8 - 10
                    }
                };
                macro_rules! push {
                    ($s:expr) => {
                        for &b in $s {
                            if tpos < tbuf.len() {
                                tbuf[tpos] = b;
                                tpos += 1;
                            }
                        }
                    };
                }
                macro_rules! push_hex16 {
                    ($v:expr) => {
                        push!(b"0x");
                        for sh in (0..16u32).rev() {
                            let n = ($v as u64 >> (sh * 4)) & 0xf;
                            if tpos < tbuf.len() {
                                tbuf[tpos] = nibble(n);
                                tpos += 1;
                            }
                        }
                    };
                }
                push!(b"weave: sh this(rcx)=");
                push_hex16!(rcx);
                push!(b" rdi=");
                push_hex16!(rdi);
                // Try to read vtable pointer at [this] via /proc/self/mem.
                if rcx != 0 {
                    let mem_path = b"/proc/self/mem\0";
                    let fd = libc::open(mem_path.as_ptr() as *const libc::c_char, libc::O_RDONLY);
                    if fd >= 0 {
                        let mut vptr = 0usize;
                        let n = libc::pread(
                            fd,
                            &mut vptr as *mut usize as *mut libc::c_void,
                            8,
                            rcx as i64,
                        );
                        libc::close(fd);
                        if n == 8 {
                            push!(b" vptr=");
                            push_hex16!(vptr);
                            // Read first 16 bytes of vtable (func pointers 0-1).
                            let mem_fd2 = libc::open(
                                mem_path.as_ptr() as *const libc::c_char,
                                libc::O_RDONLY,
                            );
                            if mem_fd2 >= 0 {
                                let mut vtab = [0u8; 16];
                                let vn = libc::pread(
                                    mem_fd2,
                                    vtab.as_mut_ptr() as *mut libc::c_void,
                                    16,
                                    vptr as i64,
                                );
                                libc::close(mem_fd2);
                                if vn > 0 {
                                    push!(b" vt=[");
                                    for (vi, &vb) in vtab[..vn as usize].iter().enumerate() {
                                        if vi > 0 {
                                            push!(b" ");
                                        }
                                        if tpos < tbuf.len() - 2 {
                                            tbuf[tpos] = nibble((vb as u64 >> 4) & 0xf);
                                            tbuf[tpos + 1] = nibble(vb as u64 & 0xf);
                                            tpos += 2;
                                        }
                                    }
                                    push!(b"]");
                                } else {
                                    push!(b" vt=<unreadable>");
                                }
                            }
                        } else {
                            push!(b" vptr=<unreadable>");
                        }
                    }
                }
                push!(b"\n");
                unsafe { libc::write(2, tbuf.as_ptr() as *const _, tpos) };
            }
        } else if base != 0 && (rip < base || rip >= base + size) {
            unsafe {
                libc::write(
                    2,
                    b"weave: sh rip NOT in any loaded module or PE\n".as_ptr() as *const _,
                    48,
                );
            }
        }
        let win_code = signal_to_exception_code(sig);

        // Try to dispatch through SEH. If a handler catches it, the ucontext
        // is updated and we return from the signal handler to resume PE code.
        #[cfg(target_arch = "x86_64")]
        {
            let uctx_mut = ctx as *mut libc::ucontext_t;
            let seh_handled = unsafe {
                crate::unwind::dispatch_hardware_exception(win_code, fault_addr, uctx_mut)
            };
            unsafe {
                libc::write(2, b"weave: sh dispatch returned\n".as_ptr() as *const _, 28);
            }
            if seh_handled {
                // Diagnostic: SEH handler caught the exception — log before resuming.
                // Use only stack buffers + write() — no heap, no format!, async-signal-safe.
                let rva = (rip - base) as u32;
                let mut buf = [0u8; 80];
                let mut pos = 0usize;
                let nibble = |n: u64| {
                    if n < 10 {
                        b'0' + n as u8
                    } else {
                        b'a' + n as u8 - 10
                    }
                };
                macro_rules! push_bytes {
                    ($s:expr) => {
                        for &b in $s {
                            if pos < buf.len() {
                                buf[pos] = b;
                                pos += 1;
                            }
                        }
                    };
                }
                macro_rules! push_hex16 {
                    ($v:expr) => {
                        push_bytes!(b"0x");
                        for sh in (0..16u32).rev() {
                            let n = ($v as u64 >> (sh * 4)) & 0xf;
                            if pos < buf.len() {
                                buf[pos] = nibble(n);
                                pos += 1;
                            }
                        }
                    };
                }
                macro_rules! push_hex8 {
                    ($v:expr) => {
                        push_bytes!(b"0x");
                        for sh in (0..8u32).rev() {
                            let n = ($v as u64 >> (sh * 4)) & 0xf;
                            if pos < buf.len() {
                                buf[pos] = nibble(n);
                                pos += 1;
                            }
                        }
                    };
                }
                push_bytes!(b"weave: SEH dispatched rip=");
                push_hex16!(rip);
                push_bytes!(b" rva=");
                push_hex8!(rva);
                push_bytes!(b"\n");
                unsafe { libc::write(2, buf.as_ptr() as *const libc::c_void, pos) };
                return; // Handler found — resume at updated RIP
            }
        }

        // No SEH handler found — fall through to crash report.
        let rva = (rip - base) as u32;
        let func_range = find_runtime_function(base, rva);

        print_crash_report(sig, win_code, rip, rva, fault_addr, func_range, uctx);
        unsafe { libc::exit(win_code as i32) };
    } else {
        // Fault in Weave's own Rust code — print a diagnostic first so we know
        // which stub crashed, then restore the default handler and re-raise.
        let fault_addr = unsafe { (*info).si_addr() } as usize;
        // Do not dereference RSP here. A host fault can leave it unmapped or
        // point at a guard page; the detailed reporter uses /proc/self/mem.
        unsafe {
            let line = b"weave: host fault; stack dereference skipped\n";
            libc::write(2, line.as_ptr() as *const libc::c_void, line.len());
        }
        print_weave_crash(sig, rip, fault_addr, base, uctx);
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }
}

// ── Non-PE crash diagnostic ───────────────────────────────────────────────────

/// Print a minimal crash report when the fault is in Weave's own Rust code.
///
/// This fires when PuTTY calls a Weave stub that itself crashes — the RIP
/// is inside Weave's binary, not the PE image. Print the RIP and a few key
/// registers so we know which stub failed, then fall through to re-raise.
#[cfg(target_os = "linux")]
fn print_weave_crash(
    sig: libc::c_int,
    rip: usize,
    fault_addr: usize,
    pe_base: usize,
    uctx: *const libc::ucontext_t,
) {
    let gregs = unsafe { (*uctx).uc_mcontext.gregs };
    let rax = gregs[libc::REG_RAX as usize] as u64;
    let rbx = gregs[libc::REG_RBX as usize] as u64;
    let rcx = gregs[libc::REG_RCX as usize] as u64;
    let rdx = gregs[libc::REG_RDX as usize] as u64;
    let rsp = gregs[libc::REG_RSP as usize] as u64;
    let r8 = gregs[libc::REG_R8 as usize] as u64;

    // Try to identify the crashing function via dladdr (async-signal-safe on Linux).
    let mut dli: libc::Dl_info = unsafe { std::mem::zeroed() };
    let has_sym = unsafe { libc::dladdr(rip as *const _, &mut dli) != 0 };
    if has_sym {
        let sym = if !dli.dli_sname.is_null() {
            unsafe { std::ffi::CStr::from_ptr(dli.dli_sname) }.to_bytes()
        } else {
            b"<no symbol>"
        };
        unsafe {
            libc::write(2, b"weave:   sym     = ".as_ptr() as *const _, 18);
            libc::write(2, sym.as_ptr() as *const _, sym.len());
            libc::write(2, b"\n".as_ptr() as *const _, 1);
        }
    }

    // Read 8 bytes at fault address and 16 bytes at RIP via /proc/self/mem.
    let (fault_preview, rip_preview) = {
        let path = b"/proc/self/mem\0";
        let fd = unsafe { libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDONLY) };
        let mut fault_hex = [b'?'; 23]; // "?? ?? ?? ?? ?? ?? ?? ??"
        let mut rip_hex = [b'?'; 47]; // 16 bytes formatted as hex
        if fd >= 0 {
            let mut buf = [0u8; 8];
            let n = unsafe {
                libc::pread(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    8,
                    fault_addr as i64,
                )
            };
            if n > 0 {
                fault_hex = *b"?? ?? ?? ?? ?? ?? ?? ??";
                let nibble = |v: u8| if v < 10 { b'0' + v } else { b'a' + v - 10 };
                for (i, &byte) in buf[..n as usize].iter().enumerate() {
                    if i * 3 + 1 < fault_hex.len() {
                        fault_hex[i * 3] = nibble(byte >> 4);
                        fault_hex[i * 3 + 1] = nibble(byte & 0xf);
                    }
                }
            }
            // Bytes at RIP — lets us disassemble the crashing instruction post-mortem.
            let mut rbuf = [0u8; 16];
            let rn =
                unsafe { libc::pread(fd, rbuf.as_mut_ptr() as *mut libc::c_void, 16, rip as i64) };
            unsafe { libc::close(fd) };
            if rn > 0 {
                rip_hex = *b"?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??";
                let nibble = |v: u8| if v < 10 { b'0' + v } else { b'a' + v - 10 };
                for (i, &byte) in rbuf[..rn as usize].iter().enumerate() {
                    if i * 3 + 1 < rip_hex.len() {
                        rip_hex[i * 3] = nibble(byte >> 4);
                        rip_hex[i * 3 + 1] = nibble(byte & 0xf);
                    }
                }
            }
        }
        (fault_hex, rip_hex)
    };

    let sig_name: &[u8] = match sig {
        libc::SIGSEGV => b"SIGSEGV",
        libc::SIGFPE => b"SIGFPE",
        libc::SIGILL => b"SIGILL",
        libc::SIGBUS => b"SIGBUS",
        libc::SIGABRT => b"SIGABRT",
        _ => b"SIG???",
    };

    // Read [RSP] and [RSP-8] via /proc/self/mem to detect ret-to-garbage vs
    // call-to-garbage. A `ret` pops the return address off the stack, so at
    // crash time [RSP-8] holds what was popped; a `call rax` leaves RSP
    // unchanged so [RSP] is the return address pushed by that call.
    let read_u64_at = |addr: u64| -> u64 {
        if addr == 0 {
            return 0;
        }
        let path = b"/proc/self/mem\0";
        let fd = unsafe { libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDONLY) };
        if fd < 0 {
            return 0;
        }
        let mut val = 0u64;
        let n = unsafe {
            libc::pread(
                fd,
                &mut val as *mut u64 as *mut libc::c_void,
                8,
                addr as i64,
            )
        };
        unsafe { libc::close(fd) };
        if n == 8 {
            val
        } else {
            0
        }
    };
    let stack_top = read_u64_at(rsp); // [RSP]   — ret addr if call crashed
    let stack_prev = read_u64_at(rsp.saturating_sub(8)); // [RSP-8] — ret addr if ret crashed
                                                         // Walk caller stack frames for backtrace (up to 8 entries).
    let mut bt_entries = [0u64; 8];
    let bt_count = {
        let mut count = 0usize;
        let mut fp = rsp;
        for _ in 0..8 {
            let ra = read_u64_at(fp);
            if ra == 0 {
                break;
            }
            bt_entries[count] = ra;
            count += 1;
            fp = fp.wrapping_add(8);
        }
        count
    };

    // Build message using only stack buffers (no heap) for signal safety.
    // Keep enough room for the full register block and the "RIP maps" line;
    // the latter is the fastest way to distinguish libc faults from Weave code.
    let mut msg = [0u8; 4096];
    let mut pos = 0usize;

    macro_rules! push {
        ($s:expr) => {
            for &b in $s {
                if pos < msg.len() - 1 {
                    msg[pos] = b;
                    pos += 1;
                }
            }
        };
    }
    macro_rules! push_hex {
        ($v:expr, $w:expr) => {{
            let v: u64 = $v as u64;
            let nibble = |n: u64| {
                if n < 10 {
                    b'0' + n as u8
                } else {
                    b'a' + n as u8 - 10
                }
            };
            push!(b"0x");
            let digits = $w * 2;
            for shift in (0..digits).rev() {
                let n = (v >> (shift * 4)) & 0xf;
                push!(&[nibble(n)]);
            }
        }};
    }

    push!(b"\nweave: CRASH in Weave stub (not in PE) -- ");
    push!(sig_name);
    push!(b"\nweave:   RIP       = ");
    push_hex!(rip, 8);
    push!(b"\nweave:   fault     = ");
    push_hex!(fault_addr, 8);
    push!(b"  [");
    for &b in &fault_preview {
        if pos < msg.len() - 1 {
            msg[pos] = b;
            pos += 1;
        }
    }
    push!(b"]");
    push!(b"\nweave:   bytes@RIP = [");
    for &b in &rip_preview {
        if pos < msg.len() - 1 {
            msg[pos] = b;
            pos += 1;
        }
    }
    push!(b"]");
    push!(b"\nweave:   PE base   = ");
    push_hex!(pe_base, 8);
    push!(b"\nweave:   RSP       = ");
    push_hex!(rsp, 8);
    push!(b"\nweave:   RCX       = ");
    push_hex!(rcx, 8);
    push!(b"\nweave:   RDX       = ");
    push_hex!(rdx, 8);
    push!(b"\nweave:   R8        = ");
    push_hex!(r8, 8);
    push!(b"\nweave:   RAX       = ");
    push_hex!(rax, 8);
    push!(b"\nweave:   RBX       = ");
    push_hex!(rbx, 8);
    push!(b"\nweave:   [RSP]     = ");
    push_hex!(stack_top, 8);
    push!(b"  (ret addr if call faulted)");
    push!(b"\nweave:   [RSP-8]   = ");
    push_hex!(stack_prev, 8);
    push!(b"  (ret addr if ret faulted)");

    // Backtrace: walk up the return-address chain on the stack.
    // With RSP=0 we can only emit raw RIP if dladdr resolved anything.
    if bt_count > 0 && (stack_top != 0 || stack_prev != 0) {
        push!(b"\nweave:   backtrace:");
        for (i, &ba) in bt_entries[..std::cmp::min(bt_count, 4usize)]
            .iter()
            .enumerate()
        {
            if ba == 0 {
                break;
            }
            push!(b"\nweave:     [");
            // Single hex digit for index
            push!(&[(if i < 10 {
                b'0' + i as u8
            } else {
                b'a' + i as u8 - 10
            })]);
            push!(b"] ");
            push_hex!(ba, 8);
        }
    }

    // Look up /proc/self/maps to find which library RIP is in.
    // Async-signal-safe: only open/read/close syscalls + stack buffers.
    {
        let maps_path = b"/proc/self/maps\0";
        let fd = unsafe { libc::open(maps_path.as_ptr() as *const libc::c_char, libc::O_RDONLY) };
        if fd >= 0 {
            let mut buf = [0u8; 512];
            let mut line = [0u8; 256];
            let mut line_pos = 0usize;
            let mut found_line = [0u8; 256];
            let mut found = false;
            'outer: loop {
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n <= 0 {
                    break;
                }
                for &ch in &buf[..n as usize] {
                    if ch == b'\n' || line_pos >= line.len() - 1 {
                        // Parse this line: "START-END perms offset dev inode [path]"
                        // START and END are hex without 0x prefix.
                        let line_slice = &line[..line_pos];
                        let mut i = 0usize;
                        // Parse start address
                        let mut start_addr = 0usize;
                        while i < line_slice.len() && line_slice[i] != b'-' {
                            let d = line_slice[i];
                            let v = if d.is_ascii_digit() {
                                (d - b'0') as usize
                            } else if (b'a'..=b'f').contains(&d) {
                                (d - b'a' + 10) as usize
                            } else {
                                break;
                            };
                            start_addr = start_addr * 16 + v;
                            i += 1;
                        }
                        i += 1; // skip '-'
                        let mut end_addr = 0usize;
                        while i < line_slice.len() && line_slice[i] != b' ' {
                            let d = line_slice[i];
                            let v = if d.is_ascii_digit() {
                                (d - b'0') as usize
                            } else if (b'a'..=b'f').contains(&d) {
                                (d - b'a' + 10) as usize
                            } else {
                                break;
                            };
                            end_addr = end_addr * 16 + v;
                            i += 1;
                        }
                        let rip_usize = rip;
                        if start_addr <= rip_usize && rip_usize < end_addr {
                            found_line[..line_pos].copy_from_slice(line_slice);
                            found = true;
                            break 'outer;
                        }
                        line_pos = 0;
                    } else {
                        line[line_pos] = ch;
                        line_pos += 1;
                    }
                }
            }
            unsafe { libc::close(fd) };
            push!(b"\nweave:   RIP maps  = ");
            if found {
                for &b in &found_line[..found_line.iter().position(|&x| x == 0).unwrap_or(256)] {
                    if pos < msg.len() - 1 {
                        msg[pos] = b;
                        pos += 1;
                    }
                }
            } else {
                push!(b"<not found>");
            }
        } else {
            push!(b"\nweave:   RIP maps  = <open /proc/self/maps failed>");
        }
    }

    push!(b"\n");

    unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, pos) };
}

// ── .pdata exception table lookup ─────────────────────────────────────────────

/// Windows x64 RUNTIME_FUNCTION — one 12-byte entry per function in .pdata.
/// The table is sorted by BeginAddress, enabling binary search.
#[repr(C)]
#[cfg(target_os = "linux")]
struct RuntimeFunction {
    begin_address: u32,       // RVA of first instruction
    end_address: u32,         // RVA one past the last instruction
    unwind_info_address: u32, // RVA of associated UNWIND_INFO
}

/// Return the [begin, end) RVA range of the function containing `rva`.
///
/// Uses a linear scan — .pdata is sorted so binary search is possible, but
/// linear is fast enough for a crash report path that runs once then exits.
#[cfg(target_os = "linux")]
fn find_runtime_function(base: usize, rva: u32) -> Option<(u32, u32)> {
    let pdata_rva = PDATA_RVA.load(Ordering::Relaxed);
    let pdata_size = PDATA_SIZE.load(Ordering::Relaxed);
    if pdata_rva == 0 || pdata_size < std::mem::size_of::<RuntimeFunction>() {
        return None;
    }
    let count = pdata_size / std::mem::size_of::<RuntimeFunction>();
    let ptr = (base + pdata_rva) as *const RuntimeFunction;
    for i in 0..count {
        let e = unsafe { &*ptr.add(i) };
        if rva >= e.begin_address && rva < e.end_address {
            return Some((e.begin_address, e.end_address));
        }
    }
    None
}

// ── Crash report ──────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn print_crash_report(
    sig: libc::c_int,
    win_code: u32,
    rip: usize,
    rva: u32,
    fault_addr: usize,
    func_range: Option<(u32, u32)>,
    uctx: *const libc::ucontext_t,
) {
    // Emit a minimal crash line FIRST — before any unsafe reads or heap
    // allocations — so we always get at least one line of output even if
    // a secondary fault kills the process mid-way through this function.
    // Uses only stack + write(2) — fully async-signal-safe.
    {
        let mut buf = [0u8; 64];
        let mut pos = 0usize;
        let nibble = |n: u64| {
            if n < 10 {
                b'0' + n as u8
            } else {
                b'a' + n as u8 - 10
            }
        };
        macro_rules! push_b {
            ($s:expr) => {
                for &b in $s {
                    if pos < buf.len() {
                        buf[pos] = b;
                        pos += 1;
                    }
                }
            };
        }
        macro_rules! push_hex16 {
            ($v:expr) => {
                push_b!(b"0x");
                for sh in (0..16u32).rev() {
                    let n = ($v as u64 >> (sh * 4)) & 0xf;
                    if pos < buf.len() {
                        buf[pos] = nibble(n);
                        pos += 1;
                    }
                }
            };
        }
        push_b!(b"weave: CRASH in PE rip=");
        push_hex16!(rip);
        push_b!(b"\n");
        unsafe { libc::write(2, buf.as_ptr() as *const libc::c_void, pos) };
    }

    // format! + libc::write is intentional: we are about to exit(), so heap
    // allocation inside the signal handler is safe in practice.
    let gregs = unsafe { (*uctx).uc_mcontext.gregs };

    let sig_name = match sig {
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGFPE => "SIGFPE",
        libc::SIGILL => "SIGILL",
        libc::SIGBUS => "SIGBUS",
        _ => "SIG???",
    };

    let func_line = match func_range {
        Some((begin, end)) => format!("rva [{begin:#010x}, {end:#010x})"),
        None => "not found in .pdata".to_string(),
    };

    // Dump 16 bytes before RIP and 16 bytes at RIP via /proc/self/mem so we
    // never trigger a secondary SIGSEGV on unmapped pages.
    let mem_path = b"/proc/self/mem\0";
    let mem_fd = unsafe { libc::open(mem_path.as_ptr() as *const libc::c_char, libc::O_RDONLY) };

    let pre_hex = {
        let pre_rip = rip.saturating_sub(16);
        let mut hex = String::from("(unreadable)");
        if mem_fd >= 0 {
            let mut buf = [0u8; 16];
            let n = unsafe {
                libc::pread(
                    mem_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    16,
                    pre_rip as i64,
                )
            };
            if n > 0 {
                hex = buf[..n as usize]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
            }
        }
        hex
    };
    let insn_hex = {
        let mut hex = String::from("(unreadable)");
        if mem_fd >= 0 {
            let mut buf = [0u8; 16];
            let n = unsafe {
                libc::pread(
                    mem_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    16,
                    rip as i64,
                )
            };
            if n > 0 {
                hex = buf[..n as usize]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
            }
        }
        hex
    };

    // Read 16 bytes at the fault address via /proc/self/mem (safe — doesn't
    // re-raise SIGSEGV even if the page is unmapped or read-only).
    let fault_bytes_hex = {
        let mut hex = String::from("(unreadable)");
        if mem_fd >= 0 {
            let mut buf = [0u8; 16];
            let n = unsafe {
                libc::pread(
                    mem_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    16,
                    fault_addr as i64,
                )
            };
            if n > 0 {
                hex = buf[..n as usize]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
            }
        }
        hex
    };
    if mem_fd >= 0 {
        unsafe { libc::close(mem_fd) };
    }

    // Check /proc/self/maps to find the memory region containing fault_addr.
    let fault_region = {
        let path = b"/proc/self/maps\0";
        let fd = unsafe { libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDONLY) };
        let mut region = String::from("(unknown)");
        if fd >= 0 {
            let mut buf = [0u8; 8192];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 8192) };
            unsafe { libc::close(fd) };
            if n > 0 {
                if let Ok(maps) = std::str::from_utf8(&buf[..n as usize]) {
                    for line in maps.lines() {
                        // Each line: "start-end perms offset dev inode pathname"
                        let parts: Vec<&str> = line.splitn(6, ' ').collect();
                        if parts.len() >= 2 {
                            let range: Vec<&str> = parts[0].splitn(2, '-').collect();
                            if range.len() == 2 {
                                if let (Ok(start), Ok(end)) = (
                                    usize::from_str_radix(range[0], 16),
                                    usize::from_str_radix(range[1], 16),
                                ) {
                                    if fault_addr >= start && fault_addr < end {
                                        region = format!("{} [{}]", parts[1], line);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        region
    };

    let cfg_count = crate::cfg::cfg_dispatch_count();
    let msg = format!(
        "\nweave: CRASH — {sig_name} in PE code\n\
         weave:   exception = {win_code:#010x}  ({})\n\
         weave:   RIP       = {rip:#018x}  (PE rva {rva:#010x})\n\
         weave:   pre-insn  = [{pre_hex}]\n\
         weave:   insn      = [{insn_hex}]\n\
         weave:   fault     = {fault_addr:#018x}  [{fault_bytes_hex}]\n\
         weave:   region    = {fault_region}\n\
         weave:   function  = {func_line}\n\
         weave:   CFG dispatches so far = {cfg_count}\n\
         weave:   rax={:#018x}  rbx={:#018x}  rcx={:#018x}\n\
         weave:   rdx={:#018x}  rsi={:#018x}  rdi={:#018x}\n\
         weave:   rsp={:#018x}  rbp={:#018x}\n\
         weave:   r8 ={:#018x}  r9 ={:#018x}  r10={:#018x}\n\
         weave:   r11={:#018x}  r12={:#018x}  r13={:#018x}\n\
         weave:   r14={:#018x}  r15={:#018x}\n",
        exception_name(win_code),
        gregs[libc::REG_RAX as usize] as u64,
        gregs[libc::REG_RBX as usize] as u64,
        gregs[libc::REG_RCX as usize] as u64,
        gregs[libc::REG_RDX as usize] as u64,
        gregs[libc::REG_RSI as usize] as u64,
        gregs[libc::REG_RDI as usize] as u64,
        gregs[libc::REG_RSP as usize] as u64,
        gregs[libc::REG_RBP as usize] as u64,
        gregs[libc::REG_R8 as usize] as u64,
        gregs[libc::REG_R9 as usize] as u64,
        gregs[libc::REG_R10 as usize] as u64,
        gregs[libc::REG_R11 as usize] as u64,
        gregs[libc::REG_R12 as usize] as u64,
        gregs[libc::REG_R13 as usize] as u64,
        gregs[libc::REG_R14 as usize] as u64,
        gregs[libc::REG_R15 as usize] as u64,
    );

    unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len()) };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn signal_to_exception_code(sig: libc::c_int) -> u32 {
    match sig {
        libc::SIGSEGV => 0xC000_0005, // STATUS_ACCESS_VIOLATION
        libc::SIGFPE => 0xC000_0094,  // STATUS_INTEGER_DIVIDE_BY_ZERO
        libc::SIGILL => 0xC000_001D,  // STATUS_ILLEGAL_INSTRUCTION
        libc::SIGBUS => 0xC000_0006,  // STATUS_IN_PAGE_ERROR
        _ => 0xC000_0001,             // STATUS_UNSUCCESSFUL
    }
}

#[cfg(target_os = "linux")]
fn exception_name(code: u32) -> &'static str {
    match code {
        0xC000_0005 => "STATUS_ACCESS_VIOLATION",
        0xC000_0094 => "STATUS_INTEGER_DIVIDE_BY_ZERO",
        0xC000_001D => "STATUS_ILLEGAL_INSTRUCTION",
        0xC000_0006 => "STATUS_IN_PAGE_ERROR",
        _ => "STATUS_UNSUCCESSFUL",
    }
}
