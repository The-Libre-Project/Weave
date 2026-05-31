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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};

// ── Global PE metadata for async-signal-safe access ──────────────────────────
//
// Signal handlers cannot safely access complex data structures (locks, heap,
// etc.), so we cache only what we need as plain atomics.

pub(crate) static PE_BASE: AtomicUsize = AtomicUsize::new(0);
pub(crate) static PE_SIZE: AtomicUsize = AtomicUsize::new(0);
pub(crate) static PDATA_RVA: AtomicUsize = AtomicUsize::new(0);
pub(crate) static PDATA_SIZE: AtomicUsize = AtomicUsize::new(0);

// ── TRACE-D: INT3-based entry hooks for Q-Dir pool analysis ──────────────────
//
// Two breakpoints (corrected after Run 1 findings):
//   (a) RVA 0x787d4 — `call sub_pool_helper` callsite in sub_78698 heavy path.
//       rdi at this point IS the pool object ptr (same as at the 0x7880d crash).
//       Run 1 showed rdi at 0x78698 entry = 0xa (path count, not ptr); moved
//       hook to callsite where rdi is loaded.
//   (b) RVA 0x7795c — pool-init helper (VA 0x47795c with base 0x400000).
//       Corrected from Run 1 which mistakenly used the VA as the RVA.
//
// The INT3 bytes are written only when PE size matches the Q-Dir fingerprint
// (0x1f3000).  Each hook fires at most once (AtomicBool one-shot guard) to
// avoid log spam.

/// Original code byte saved before writing 0xCC at RVA 0x787d4 (callsite).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static Q_DIR_TRACE_D_ORIG_78698: AtomicU8 = AtomicU8::new(0);

/// Original code byte saved before writing 0xCC at RVA 0x7795c (helper).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static Q_DIR_TRACE_D_ORIG_47795C: AtomicU8 = AtomicU8::new(0);

/// Return address of the 0x7795c helper call, captured at entry breakpoint.
/// Used to plant the exit (return-value) INT3.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static Q_DIR_TRACE_D_HELPER_RET_VA: AtomicU64 = AtomicU64::new(0);

/// Original byte at the dynamically-planted helper-return INT3.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static Q_DIR_TRACE_D_ORIG_RET: AtomicU8 = AtomicU8::new(0);

/// One-shot guard: heavy-path entry hook already fired.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static Q_DIR_TRACE_D_ENTRY_FIRED: AtomicBool = AtomicBool::new(false);

/// One-shot guard: helper-entry hook already fired.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static Q_DIR_TRACE_D_HELPER_FIRED: AtomicBool = AtomicBool::new(false);

/// One-shot guard: helper-return hook already fired.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static Q_DIR_TRACE_D_RETURN_FIRED: AtomicBool = AtomicBool::new(false);

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

    #[cfg(target_os = "linux")]
    {
        install_one(libc::SIGSEGV);
        install_one(libc::SIGFPE);
        install_one(libc::SIGILL);
        install_one(libc::SIGBUS);
        install_one(libc::SIGABRT);
        install_one(libc::SIGTRAP);
        eprintln!("weave: exception handlers installed");
    }

    // TRACE-D: plant INT3 breakpoints for the Q-Dir pool analysis.
    // Only runs when PE size matches the Q-Dir fingerprint.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    q_dir_trace_d_install_hooks(image.base as usize, image.size);
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
    unsafe {
        libc::write(2, b"weave: sh got rip\n".as_ptr() as *const _, 18);
    }

    let base = PE_BASE.load(Ordering::Relaxed);
    let size = PE_SIZE.load(Ordering::Relaxed);

    // ── TRACE-D: SIGTRAP dispatch (INT3 breakpoint hooks) ─────────────────
    // Must come BEFORE the SIGSEGV/crash path so INT3 breakpoints don't fall
    // through to the fatal-fault reporter.  RIP on x86 points one byte PAST
    // the INT3 when the SIGTRAP is delivered; the original instruction address
    // is (rip - 1).
    #[cfg(target_arch = "x86_64")]
    if sig == libc::SIGTRAP && base != 0 {
        let bp_rip = rip.wrapping_sub(1); // address of the INT3 byte
        let uctx_mut = ctx as *mut libc::ucontext_t;
        if q_dir_trace_d_on_sigtrap(base, size, bp_rip, uctx_mut) {
            return; // hook handled — resume normal execution
        }
    }

    if base != 0 && rip >= base && rip < base + size {
        // ── SEH runaway cap ────────────────────────────────────────────────
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
            let mut buf = [0u8; 96];
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
            buf[pos] = b'\n';
            pos += 1;
            libc::write(2, buf.as_ptr() as *const _, pos);
        }
        if rva == 0x78698 {
            log_q_dir_78698_entry(base, size, uctx);
        }
        if rva == 0x786eb || rva == 0x78700 {
            log_q_dir_786eb_enter(base, size, rva);
            log_q_dir_786eb_diag(base, size, uctx);
        }
        if rva == 0x7880d {
            log_q_dir_7880d_enter(base, size, rva);
            log_q_dir_7880d_diag(base, size, uctx);
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

/// Q-Dir E3-M5b evidence: caller ID for heap init `0x78698` / crash `0x7880d` / `0x786eb`.
#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
fn log_q_dir_7880d_enter(_pe_base: usize, _pe_size: usize, _rva: u32) {}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
fn log_q_dir_7880d_diag(_pe_base: usize, _pe_size: usize, _ctx: *const libc::ucontext_t) {}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
fn log_q_dir_786eb_enter(_pe_base: usize, _pe_size: usize, _rva: u32) {}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
fn log_q_dir_786eb_diag(_pe_base: usize, _pe_size: usize, _ctx: *const libc::ucontext_t) {}

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
fn log_q_dir_78698_entry(_pe_base: usize, _pe_size: usize, _ctx: *const libc::ucontext_t) {}

/// Q-Dir `sub_78698` — heap init (disasm: `mov esi, ecx` then `cmp esi, 2`).
const Q_DIR_HEAP_INIT_LO: u32 = 0x78698;
const Q_DIR_HEAP_INIT_HI: u32 = 0x79100;
/// Return RIP after `call 0x78698` at `0x790f1` / `0x79424`.
const Q_DIR_CALL_RET_790F1: u32 = 0x790f6;
const Q_DIR_CALL_RET_79424: u32 = 0x79429;
/// Light-path freelist head (`mov rax, [rip+0xdaafd]` at `0x786dc`).
const Q_DIR_FREELIST_HEAD_RVA: usize = 0x1531e0;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn q_dir_diag_pread_u32(addr: usize) -> Option<u32> {
    let mem_path = b"/proc/self/mem\0";
    let fd = unsafe { libc::open(mem_path.as_ptr() as *const libc::c_char, libc::O_RDONLY) };
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 4];
    let n = unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, 4, addr as i64) };
    unsafe { libc::close(fd) };
    if n == 4 {
        Some(u32::from_le_bytes(buf))
    } else {
        None
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn q_dir_diag_pread_u64(addr: usize) -> Option<u64> {
    let mem_path = b"/proc/self/mem\0";
    let fd = unsafe { libc::open(mem_path.as_ptr() as *const libc::c_char, libc::O_RDONLY) };
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 8];
    let n = unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, 8, addr as i64) };
    unsafe { libc::close(fd) };
    if n == 8 {
        Some(u64::from_le_bytes(buf))
    } else {
        None
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn log_q_dir_7880d_enter(pe_base: usize, pe_size: usize, rva: u32) {
    let mut buf = [0u8; 128];
    let mut pos = 0usize;
    q_dir_diag_write_bytes(&mut buf, &mut pos, b"weave: q-dir 7880d enter pe_base=");
    q_dir_diag_write_hex(&mut buf, &mut pos, pe_base as u64, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" pe_size=");
    q_dir_diag_write_hex(&mut buf, &mut pos, pe_size as u64, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" rva=");
    q_dir_diag_write_hex(&mut buf, &mut pos, rva as u64, 8);
    q_dir_diag_write_byte(&mut buf, &mut pos, b'\n');
    unsafe { libc::write(2, buf.as_ptr() as *const _, pos) };
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn q_dir_guest_rva(pe_base: usize, pe_size: usize, rip: u64) -> Option<u32> {
    let rip = rip as usize;
    if rip >= pe_base && rip < pe_base + pe_size {
        Some((rip - pe_base) as u32)
    } else {
        None
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn q_dir_inside_heap_init(rva: u32) -> bool {
    rva >= Q_DIR_HEAP_INIT_LO && rva < Q_DIR_HEAP_INIT_HI
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn q_dir_call_site_label(ret_rva: u32) -> &'static [u8] {
    if ret_rva == Q_DIR_CALL_RET_790F1 {
        b"site=0x790f1(ecx=[0x152fb0])"
    } else if ret_rva == Q_DIR_CALL_RET_79424 {
        b"site=0x79424(ecx=edi)"
    } else {
        b"site=unknown"
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn log_q_dir_78698_caller_id(pe_base: usize, pe_size: usize, rbp: u64, rsp: u64) {
    let mut caller_ret = 0u32;
    let mut frame = rbp as usize;
    for _ in 0..16 {
        if frame == 0 {
            break;
        }
        let ret = q_dir_diag_pread_u64(frame.wrapping_add(8)).unwrap_or(0);
        if let Some(rva) = q_dir_guest_rva(pe_base, pe_size, ret) {
            if !q_dir_inside_heap_init(rva) {
                caller_ret = rva;
                break;
            }
        }
        let next = q_dir_diag_pread_u64(frame).unwrap_or(0);
        if next == 0 || next <= frame as u64 {
            break;
        }
        frame = next as usize;
    }
    if caller_ret == 0 {
        for off in (0..0x100).step_by(8) {
            let slot = q_dir_diag_pread_u64((rsp as usize).wrapping_add(off)).unwrap_or(0);
            if let Some(rva) = q_dir_guest_rva(pe_base, pe_size, slot) {
                if !q_dir_inside_heap_init(rva) {
                    caller_ret = rva;
                    break;
                }
            }
        }
    }
    let mut buf = [0u8; 256];
    let mut pos = 0usize;
    q_dir_diag_write_bytes(&mut buf, &mut pos, b"weave: q-dir 78698 caller ret_rva=");
    q_dir_diag_write_hex(&mut buf, &mut pos, caller_ret as u64, 8);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" ");
    q_dir_diag_write_bytes(&mut buf, &mut pos, q_dir_call_site_label(caller_ret));
    q_dir_diag_write_byte(&mut buf, &mut pos, b'\n');
    unsafe { libc::write(2, buf.as_ptr() as *const _, pos) };
}

/// Log if we fault exactly at `0x78698` prologue (rare; cheap one-shot).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn log_q_dir_78698_entry(pe_base: usize, pe_size: usize, ctx: *const libc::ucontext_t) {
    let gregs = unsafe { (*ctx).uc_mcontext.gregs };
    let ecx = gregs[libc::REG_RCX as usize] as u64;
    let rdi = gregs[libc::REG_RDI as usize] as u64;
    let rsp = gregs[libc::REG_RSP as usize] as u64;
    let ret_rip = q_dir_diag_pread_u64(rsp as usize).unwrap_or(0);
    let ret_rva = q_dir_guest_rva(pe_base, pe_size, ret_rip).unwrap_or(0);
    let mut buf = [0u8; 384];
    let mut pos = 0usize;
    q_dir_diag_write_bytes(&mut buf, &mut pos, b"weave: q-dir 78698 entry ecx=");
    q_dir_diag_write_hex(&mut buf, &mut pos, ecx, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" rdi=");
    q_dir_diag_write_hex(&mut buf, &mut pos, rdi, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" [rdi+4]=");
    let chunk = if rdi != 0 {
        q_dir_diag_pread_u32((rdi as usize).wrapping_add(4))
            .map(u64::from)
            .unwrap_or(0xffff_ffff)
    } else {
        0
    };
    q_dir_diag_write_hex(&mut buf, &mut pos, chunk, 8);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" ret_rva=");
    q_dir_diag_write_hex(&mut buf, &mut pos, ret_rva as u64, 8);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" ");
    q_dir_diag_write_bytes(&mut buf, &mut pos, q_dir_call_site_label(ret_rva));
    q_dir_diag_write_byte(&mut buf, &mut pos, b'\n');
    unsafe { libc::write(2, buf.as_ptr() as *const _, pos) };
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn log_q_dir_786eb_enter(pe_base: usize, pe_size: usize, rva: u32) {
    let mut buf = [0u8; 128];
    let mut pos = 0usize;
    q_dir_diag_write_bytes(&mut buf, &mut pos, b"weave: q-dir 786eb enter pe_base=");
    q_dir_diag_write_hex(&mut buf, &mut pos, pe_base as u64, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" pe_size=");
    q_dir_diag_write_hex(&mut buf, &mut pos, pe_size as u64, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" rva=");
    q_dir_diag_write_hex(&mut buf, &mut pos, rva as u64, 8);
    q_dir_diag_write_byte(&mut buf, &mut pos, b'\n');
    unsafe { libc::write(2, buf.as_ptr() as *const _, pos) };
}

/// Light-path fault at `0x786eb` / `0x78700`: `mov edx, [rax+8]` freelist walk in `0x78698`.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn log_q_dir_786eb_diag(pe_base: usize, pe_size: usize, ctx: *const libc::ucontext_t) {
    let gregs = unsafe { (*ctx).uc_mcontext.gregs };
    let rax = gregs[libc::REG_RAX as usize] as u64;
    let rbx = gregs[libc::REG_RBX as usize] as u64;
    let rcx = gregs[libc::REG_RCX as usize] as u64;
    let rdx = gregs[libc::REG_RDX as usize] as u64;
    let rsi = gregs[libc::REG_RSI as usize] as u64;
    let rdi = gregs[libc::REG_RDI as usize] as u64;
    let rbp = gregs[libc::REG_RBP as usize] as u64;
    let rsp = gregs[libc::REG_RSP as usize] as u64;

    let freelist =
        q_dir_diag_pread_u64(pe_base + Q_DIR_FREELIST_HEAD_RVA).unwrap_or(0xffff_ffff_ffff_ffff);
    let mut buf = [0u8; 640];
    let mut pos = 0usize;
    q_dir_diag_write_bytes(
        &mut buf,
        &mut pos,
        b"weave: q-dir 786eb light-path insn=mov edx,[rax+8] fault_addr=rax+8\n",
    );
    q_dir_diag_write_bytes(&mut buf, &mut pos, b"weave: q-dir 786eb globals 0x1531e0=");
    q_dir_diag_write_hex(&mut buf, &mut pos, freelist, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" 0x152fb0=");
    let ctr = q_dir_diag_pread_u64(pe_base + 0x152fb0).unwrap_or(0xffff_ffff_ffff_ffff);
    q_dir_diag_write_hex(&mut buf, &mut pos, ctr, 16);
    q_dir_diag_write_byte(&mut buf, &mut pos, b'\n');
    unsafe { libc::write(2, buf.as_ptr() as *const _, pos) };

    pos = 0;
    q_dir_diag_write_bytes(&mut buf, &mut pos, b"weave: q-dir 786eb regs rax=");
    q_dir_diag_write_hex(&mut buf, &mut pos, rax, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" (freelist head load) rbx=");
    q_dir_diag_write_hex(&mut buf, &mut pos, rbx, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" rcx=");
    q_dir_diag_write_hex(&mut buf, &mut pos, rcx, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" rdx=");
    q_dir_diag_write_hex(&mut buf, &mut pos, rdx, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" rsi=");
    q_dir_diag_write_hex(&mut buf, &mut pos, rsi, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" (78698 1st-arg ecx) rdi=");
    q_dir_diag_write_hex(&mut buf, &mut pos, rdi, 16);
    q_dir_diag_write_byte(&mut buf, &mut pos, b'\n');
    unsafe { libc::write(2, buf.as_ptr() as *const _, pos) };

    pos = 0;
    q_dir_diag_write_bytes(&mut buf, &mut pos, b"weave: q-dir 786eb chunk [rax]=");
    let at_rax = if rax != 0 {
        q_dir_diag_pread_u64(rax as usize)
            .map(|v| v)
            .unwrap_or(0xffff_ffff_ffff_ffff)
    } else {
        0
    };
    q_dir_diag_write_hex(&mut buf, &mut pos, at_rax, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" [rax+4]=");
    let at_rax4 = if rax != 0 {
        q_dir_diag_pread_u32((rax as usize).wrapping_add(4))
            .map(u64::from)
            .unwrap_or(0xffff_ffff)
    } else {
        0
    };
    q_dir_diag_write_hex(&mut buf, &mut pos, at_rax4, 8);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" [rax+8]=");
    let at_rax8 = if rax != 0 {
        q_dir_diag_pread_u32((rax as usize).wrapping_add(8))
            .map(u64::from)
            .unwrap_or(0xffff_ffff)
    } else {
        0
    };
    q_dir_diag_write_hex(&mut buf, &mut pos, at_rax8, 8);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" (fault deref)\n");
    unsafe { libc::write(2, buf.as_ptr() as *const _, pos) };

    pos = 0;
    q_dir_diag_write_bytes(&mut buf, &mut pos, b"weave: q-dir 786eb chunk [rdi]=");
    let at_rdi = if rdi != 0 {
        q_dir_diag_pread_u64(rdi as usize).unwrap_or(0xffff_ffff_ffff_ffff)
    } else {
        0
    };
    q_dir_diag_write_hex(&mut buf, &mut pos, at_rdi, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" [rdi+4]=");
    let at_rdi4 = if rdi != 0 {
        q_dir_diag_pread_u32((rdi as usize).wrapping_add(4))
            .map(u64::from)
            .unwrap_or(0xffff_ffff)
    } else {
        0
    };
    q_dir_diag_write_hex(&mut buf, &mut pos, at_rdi4, 8);
    q_dir_diag_write_byte(&mut buf, &mut pos, b'\n');
    unsafe { libc::write(2, buf.as_ptr() as *const _, pos) };

    log_q_dir_78698_caller_id(pe_base, pe_size, rbp, rsp);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn log_q_dir_7880d_diag(pe_base: usize, pe_size: usize, ctx: *const libc::ucontext_t) {
    const COUNTER_RVAS: [(usize, &[u8]); 3] = [
        (0x152fb0, b"0x152fb0"),
        (0x152fbc, b"0x152fbc"),
        (0x146e70, b"0x146e70"),
    ];
    let gregs = unsafe { (*ctx).uc_mcontext.gregs };
    let rax = gregs[libc::REG_RAX as usize] as u64;
    let rbx = gregs[libc::REG_RBX as usize] as u64;
    let rcx = gregs[libc::REG_RCX as usize] as u64;
    let rdx = gregs[libc::REG_RDX as usize] as u64;
    let rsi = gregs[libc::REG_RSI as usize] as u64;
    let rdi = gregs[libc::REG_RDI as usize] as u64;
    let rbp = gregs[libc::REG_RBP as usize] as u64;
    let mut buf = [0u8; 512];
    let mut pos = 0usize;
    // Counters + regs first — never deref guest pointers in the handler (re-fault risk).
    q_dir_diag_write_bytes(&mut buf, &mut pos, b"weave: q-dir 7880d counters");
    for (rva, label) in COUNTER_RVAS {
        q_dir_diag_write_bytes(&mut buf, &mut pos, b" ");
        q_dir_diag_write_bytes(&mut buf, &mut pos, label);
        q_dir_diag_write_bytes(&mut buf, &mut pos, b"=");
        let cur = q_dir_diag_pread_u64(pe_base + rva).unwrap_or(0xffff_ffff_ffff_ffff);
        q_dir_diag_write_hex(&mut buf, &mut pos, cur, 16);
    }
    q_dir_diag_write_byte(&mut buf, &mut pos, b'\n');
    unsafe { libc::write(2, buf.as_ptr() as *const _, pos) };

    pos = 0;
    q_dir_diag_write_bytes(&mut buf, &mut pos, b"weave: q-dir 7880d regs rax=");
    q_dir_diag_write_hex(&mut buf, &mut pos, rax, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" rbx=");
    q_dir_diag_write_hex(&mut buf, &mut pos, rbx, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" rcx=");
    q_dir_diag_write_hex(&mut buf, &mut pos, rcx, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" rdx=");
    q_dir_diag_write_hex(&mut buf, &mut pos, rdx, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" rsi=");
    q_dir_diag_write_hex(&mut buf, &mut pos, rsi, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" rdi=");
    q_dir_diag_write_hex(&mut buf, &mut pos, rdi, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" rbp=");
    q_dir_diag_write_hex(&mut buf, &mut pos, rbp, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" [rdi+4]=");
    let chunk_ptr = if rdi != 0 {
        q_dir_diag_pread_u32((rdi as usize).wrapping_add(4))
            .map(u64::from)
            .unwrap_or(0xffff_ffff)
    } else {
        0
    };
    q_dir_diag_write_hex(&mut buf, &mut pos, chunk_ptr, 16);
    q_dir_diag_write_byte(&mut buf, &mut pos, b'\n');
    unsafe { libc::write(2, buf.as_ptr() as *const _, pos) };

    // Q1: the chunk header words [rdi] and [rdi+8] — guarded by rdi!=0 like [rdi+4] above.
    pos = 0;
    q_dir_diag_write_bytes(&mut buf, &mut pos, b"weave: q-dir 7880d chunk [rdi]=");
    let chunk0 = if rdi != 0 {
        q_dir_diag_pread_u64(rdi as usize).unwrap_or(0xffff_ffff_ffff_ffff)
    } else {
        0
    };
    q_dir_diag_write_hex(&mut buf, &mut pos, chunk0, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" [rdi+8]=");
    let chunk8 = if rdi != 0 {
        q_dir_diag_pread_u64((rdi as usize).wrapping_add(8)).unwrap_or(0xffff_ffff_ffff_ffff)
    } else {
        0
    };
    q_dir_diag_write_hex(&mut buf, &mut pos, chunk8, 16);
    q_dir_diag_write_byte(&mut buf, &mut pos, b'\n');
    unsafe { libc::write(2, buf.as_ptr() as *const _, pos) };

    // Q4: freelist/pool-slot tables — pe_base + rva via pread, fall back to 0xffff.. on unmapped.
    pos = 0;
    q_dir_diag_write_bytes(&mut buf, &mut pos, b"weave: q-dir 7880d freelist 0x1531e0=");
    let fl_1531e0 = q_dir_diag_pread_u64(pe_base + 0x1531e0).unwrap_or(0xffff_ffff_ffff_ffff);
    q_dir_diag_write_hex(&mut buf, &mut pos, fl_1531e0, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" 0x153d70=");
    let fl_153d70 = q_dir_diag_pread_u32(pe_base + 0x153d70)
        .map(u64::from)
        .unwrap_or(0xffff_ffff);
    q_dir_diag_write_hex(&mut buf, &mut pos, fl_153d70, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" 0x153d74=");
    let fl_153d74 = q_dir_diag_pread_u32(pe_base + 0x153d74)
        .map(u64::from)
        .unwrap_or(0xffff_ffff);
    q_dir_diag_write_hex(&mut buf, &mut pos, fl_153d74, 16);
    q_dir_diag_write_byte(&mut buf, &mut pos, b'\n');
    unsafe { libc::write(2, buf.as_ptr() as *const _, pos) };

    let rsp = gregs[libc::REG_RSP as usize] as u64;
    let mut buf2 = [0u8; 128];
    let mut pos2 = 0usize;
    q_dir_diag_write_bytes(&mut buf2, &mut pos2, b"weave: q-dir 78698 at-crash esi=");
    q_dir_diag_write_hex(&mut buf2, &mut pos2, rsi, 16);
    q_dir_diag_write_bytes(&mut buf2, &mut pos2, b" (78698 1st-arg; heavy if >=2)\n");
    unsafe { libc::write(2, buf2.as_ptr() as *const _, pos2) };

    log_q_dir_78698_caller_id(pe_base, pe_size, rbp, rsp);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn q_dir_diag_nibble(n: u64) -> u8 {
    if n < 10 {
        b'0' + n as u8
    } else {
        b'a' + n as u8 - 10
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn q_dir_diag_write_byte(buf: &mut [u8], pos: &mut usize, b: u8) {
    if *pos < buf.len() {
        buf[*pos] = b;
        *pos += 1;
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn q_dir_diag_write_bytes(buf: &mut [u8], pos: &mut usize, s: &[u8]) {
    for &b in s {
        q_dir_diag_write_byte(buf, pos, b);
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn q_dir_diag_write_hex(buf: &mut [u8], pos: &mut usize, v: u64, width: u32) {
    q_dir_diag_write_bytes(buf, pos, b"0x");
    for sh in (0..width).rev() {
        let n = (v >> (sh * 4)) & 0xf;
        q_dir_diag_write_byte(buf, pos, q_dir_diag_nibble(n));
    }
}

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

// ── TRACE-D: entry-hook implementation ───────────────────────────────────────
//
// INT3-based hooks that fire during normal PE execution (not at fault time).
// Strategy: write 0xCC over the first byte of each target RVA; the SIGTRAP
// handler reads register state and pool-object fields via direct ptr::read,
// restores the original byte, and rewinds RIP by 1 so the original instruction
// re-executes on handler return.
//
// Hook points:
//   RVA 0x78698 — `sub_78698` entry.  rcx/rdi at entry = path-count, NOT the
//                 pool ptr.  The pool ptr (rdi at the crash site) is loaded
//                 inside the heavy path; hook at callsite 0x787d4 for the ptr.
//   RVA 0x787d4 — callsite `call 0x7795c` inside sub_78698 heavy path.  rdi
//                 here IS the pool object pointer that crashes at 0x7880d.
//                 Logs [rdi+0..32] and esi (path count).
//   RVA 0x7795c — pool-init helper (VA 0x47795c = base 0x400000 + RVA 0x7795c).
//                 Logs rcx/rdx/r8 at entry; plants return-site INT3.
//
// TRACE-D Run 1 finding (CI 26721114209): rdi at 0x78698 entry = 0xa (path
// count passed in rcx, not a pointer).  ptr::read on 0xa → SIGSEGV → exit 134.
// Fix: hook at 0x787d4 (callsite) where rdi IS the pool ptr, not at 0x78698
// entry.  Also corrected helper RVA: 0x47795c is the 32-bit VA; RVA = 0x7795c.

/// RVA of the `call sub_pool_helper` callsite inside `sub_78698` heavy path.
/// rdi at this point holds the pool object pointer (same rdi seen at the 0x7880d crash).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const Q_DIR_CALLSITE_787D4_RVA: u32 = 0x787d4;

/// RVA of the pool-init helper.  The TRACE-B disasm gives the 32-bit VA as
/// 0x47795c; with PE base 0x400000 the RVA is 0x47795c - 0x400000 = 0x7795c.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const Q_DIR_POOL_HELPER_RVA: u32 = 0x7795c;

/// Write a single byte to an executable page, briefly making it writable.
/// Returns the original byte, or 0xFF on failure.
///
/// # Safety
/// `addr` must point to a mapped page.  Caller is responsible for only
/// patching pages that belong to the guest PE.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn trace_d_write_byte(addr: usize, byte: u8) -> u8 {
    const PAGE_SIZE: usize = 4096;
    let page = addr & !(PAGE_SIZE - 1);
    // Make page writable.
    let rc = unsafe {
        libc::mprotect(
            page as *mut libc::c_void,
            PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )
    };
    if rc != 0 {
        return 0xFF;
    }
    let ptr = addr as *mut u8;
    let orig = unsafe { ptr.read_volatile() };
    unsafe { ptr.write_volatile(byte) };
    // Restore read+exec.
    unsafe {
        libc::mprotect(
            page as *mut libc::c_void,
            PAGE_SIZE,
            libc::PROT_READ | libc::PROT_EXEC,
        )
    };
    orig
}

/// Install INT3 breakpoints at 0x787d4 (callsite) and 0x7795c (helper entry)
/// for Q-Dir only (identified by PE size 0x1f3000).
/// Called from `seh::install` after PE metadata is stored.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn q_dir_trace_d_install_hooks(pe_base: usize, pe_size: usize) {
    const Q_DIR_SIZE_FINGERPRINT: usize = 0x1f3000;
    if pe_size != Q_DIR_SIZE_FINGERPRINT {
        return;
    }
    // Hook the callsite (0x787d4) where rdi IS the pool object pointer, NOT
    // 0x78698 (function entry) where rdi is still whatever the caller left.
    // Run 1 confirmed: rdi at 0x78698 entry = 0xa (path count in rcx).
    unsafe {
        let orig_a = trace_d_write_byte(pe_base + Q_DIR_CALLSITE_787D4_RVA as usize, 0xCC);
        Q_DIR_TRACE_D_ORIG_78698.store(orig_a, Ordering::Relaxed);

        let orig_b = trace_d_write_byte(pe_base + Q_DIR_POOL_HELPER_RVA as usize, 0xCC);
        Q_DIR_TRACE_D_ORIG_47795C.store(orig_b, Ordering::Relaxed);
    }
    let mut buf = [0u8; 160];
    let mut pos = 0usize;
    q_dir_diag_write_bytes(
        &mut buf,
        &mut pos,
        b"weave: trace-d hooks installed pe_base=",
    );
    q_dir_diag_write_hex(&mut buf, &mut pos, pe_base as u64, 16);
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" orig_787d4=");
    q_dir_diag_write_hex(
        &mut buf,
        &mut pos,
        Q_DIR_TRACE_D_ORIG_78698.load(Ordering::Relaxed) as u64,
        2,
    );
    q_dir_diag_write_bytes(&mut buf, &mut pos, b" orig_7795c=");
    q_dir_diag_write_hex(
        &mut buf,
        &mut pos,
        Q_DIR_TRACE_D_ORIG_47795C.load(Ordering::Relaxed) as u64,
        2,
    );
    q_dir_diag_write_byte(&mut buf, &mut pos, b'\n');
    unsafe { libc::write(2, buf.as_ptr() as *const _, pos) };
}

/// SIGTRAP dispatch for TRACE-D breakpoints.  Returns `true` if the trap was
/// one of our INT3 hooks and execution should resume; `false` otherwise (let
/// the normal fatal-fault path handle it).
///
/// `bp_rip` = address of the INT3 byte = (hardware RIP - 1).
/// `uctx`   = mutable ucontext; we rewind REG_RIP to `bp_rip` so the restored
///            instruction re-executes after the signal handler returns.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn q_dir_trace_d_on_sigtrap(
    pe_base: usize,
    pe_size: usize,
    bp_rip: usize,
    uctx: *mut libc::ucontext_t,
) -> bool {
    if pe_base == 0 || bp_rip < pe_base || bp_rip >= pe_base + pe_size {
        return false;
    }
    let rva = (bp_rip - pe_base) as u32;

    // ── (a) 0x787d4 — `call sub_pool_helper` callsite in sub_78698 heavy path ──
    // rdi at this point IS the pool object pointer (same rdi seen at the 0x7880d
    // crash site).  Run 1 confirmed: rdi at 0x78698 entry = 0xa (not a ptr);
    // the pool ptr is loaded inside the heavy path before this call.
    if rva == Q_DIR_CALLSITE_787D4_RVA {
        // One-shot: restore the INT3 immediately so subsequent calls run
        // unpatched.  We only need one sample to answer Q1/Q2/Q3.
        let orig = Q_DIR_TRACE_D_ORIG_78698.load(Ordering::Relaxed);
        unsafe { trace_d_write_byte(bp_rip, orig) };

        // Rewind RIP so the restored instruction executes on return.
        unsafe { (*uctx).uc_mcontext.gregs[libc::REG_RIP as usize] = bp_rip as i64 };

        // Only log the first time (guard against re-entry during restoration).
        if Q_DIR_TRACE_D_ENTRY_FIRED
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            let gregs = unsafe { (*uctx).uc_mcontext.gregs };
            let rdi = gregs[libc::REG_RDI as usize] as u64;
            let rsi = gregs[libc::REG_RSI as usize] as u64; // esi = path count
            let rcx = gregs[libc::REG_RCX as usize] as u64;

            // Log rdi (pool ptr), esi (path count in rsi), rcx.
            let mut buf = [0u8; 256];
            let mut pos = 0usize;
            q_dir_diag_write_bytes(&mut buf, &mut pos, b"weave: trace-d 787d4 callsite rdi=");
            q_dir_diag_write_hex(&mut buf, &mut pos, rdi, 16);
            q_dir_diag_write_bytes(&mut buf, &mut pos, b" esi(path-count)=");
            q_dir_diag_write_hex(&mut buf, &mut pos, rsi & 0xffff_ffff, 8);
            q_dir_diag_write_bytes(&mut buf, &mut pos, b" rcx=");
            q_dir_diag_write_hex(&mut buf, &mut pos, rcx, 16);
            q_dir_diag_write_byte(&mut buf, &mut pos, b'\n');
            unsafe { libc::write(2, buf.as_ptr() as *const _, pos) };

            // Read [rdi+0..32] via direct ptr::read_volatile.
            // Guard: rdi must look like a heap address (above 0x10000 and below
            // the PE image range).  Run 1 showed rdi can be 0xa at function
            // entry — we now hook at the callsite where rdi IS the pool ptr
            // (TRACE-C saw rdi ≈ 0x7f5f753a2004 at the crash site).
            // Additional guard: rdi must not overlap the PE image range.
            let in_pe =
                rdi >= pe_base as u64 && rdi < (pe_base as u64).wrapping_add(pe_size as u64);
            if rdi > 0x1_0000 && !in_pe {
                // Read 4 × u64 (32 bytes) from the pool object.
                let p = rdi as *const u64;
                // SAFETY: rdi is expected to be inside the guest's VirtualAlloc
                // range (confirmed by TRACE-C at address 0x7f5f75…).  At the
                // callsite the pool backing store is already allocated; the
                // question is whether the fields are initialized.  If rdi is
                // somehow garbage despite our guard, the worst outcome is a
                // secondary SIGSEGV caught by the existing crash reporter.
                let f0 = unsafe { p.read_volatile() };
                let f1 = unsafe { p.add(1).read_volatile() };
                let f2 = unsafe { p.add(2).read_volatile() };
                let f3 = unsafe { p.add(3).read_volatile() };

                let mut buf2 = [0u8; 256];
                let mut pos2 = 0usize;
                q_dir_diag_write_bytes(&mut buf2, &mut pos2, b"weave: trace-d 787d4 pool [rdi+0]=");
                q_dir_diag_write_hex(&mut buf2, &mut pos2, f0, 16);
                q_dir_diag_write_bytes(&mut buf2, &mut pos2, b" [rdi+8]=");
                q_dir_diag_write_hex(&mut buf2, &mut pos2, f1, 16);
                q_dir_diag_write_bytes(&mut buf2, &mut pos2, b" [rdi+16]=");
                q_dir_diag_write_hex(&mut buf2, &mut pos2, f2, 16);
                q_dir_diag_write_bytes(&mut buf2, &mut pos2, b" [rdi+24]=");
                q_dir_diag_write_hex(&mut buf2, &mut pos2, f3, 16);
                q_dir_diag_write_byte(&mut buf2, &mut pos2, b'\n');
                unsafe { libc::write(2, buf2.as_ptr() as *const _, pos2) };

                // Also log [rdi+4] as u32 — the field TRACE-C identified as
                // the garbage rax source at the 0x7880d crash.
                let p32 = rdi as *const u32;
                let f4_hi = unsafe { p32.add(1).read_volatile() }; // [rdi+4]
                let mut buf3 = [0u8; 128];
                let mut pos3 = 0usize;
                q_dir_diag_write_bytes(&mut buf3, &mut pos3, b"weave: trace-d 787d4 [rdi+4](u32)=");
                q_dir_diag_write_hex(&mut buf3, &mut pos3, f4_hi as u64, 8);
                q_dir_diag_write_byte(&mut buf3, &mut pos3, b'\n');
                unsafe { libc::write(2, buf3.as_ptr() as *const _, pos3) };
            } else {
                // rdi failed the guard — log it for diagnosis.
                let mut buf_g = [0u8; 128];
                let mut pos_g = 0usize;
                q_dir_diag_write_bytes(
                    &mut buf_g,
                    &mut pos_g,
                    b"weave: trace-d 787d4 rdi-guard-fail rdi=",
                );
                q_dir_diag_write_hex(&mut buf_g, &mut pos_g, rdi, 16);
                q_dir_diag_write_byte(&mut buf_g, &mut pos_g, b'\n');
                unsafe { libc::write(2, buf_g.as_ptr() as *const _, pos_g) };
            }
        }
        return true;
    }

    // ── (b) 0x7795c — pool-init helper entry ──────────────────────────────
    // (VA 0x47795c = base 0x400000 + RVA 0x7795c — corrected from Run 1 where
    // 0x47795c was mistakenly used as RVA instead of VA.)
    if rva == Q_DIR_POOL_HELPER_RVA {
        let orig = Q_DIR_TRACE_D_ORIG_47795C.load(Ordering::Relaxed);
        unsafe { trace_d_write_byte(bp_rip, orig) };
        unsafe { (*uctx).uc_mcontext.gregs[libc::REG_RIP as usize] = bp_rip as i64 };

        if Q_DIR_TRACE_D_HELPER_FIRED
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            let gregs = unsafe { (*uctx).uc_mcontext.gregs };
            let rcx = gregs[libc::REG_RCX as usize] as u64;
            let rdx = gregs[libc::REG_RDX as usize] as u64;
            let r8 = gregs[libc::REG_R8 as usize] as u64;
            let rsp = gregs[libc::REG_RSP as usize] as u64;

            let mut buf = [0u8; 256];
            let mut pos = 0usize;
            q_dir_diag_write_bytes(&mut buf, &mut pos, b"weave: trace-d 7795c entry rcx=");
            q_dir_diag_write_hex(&mut buf, &mut pos, rcx, 16);
            q_dir_diag_write_bytes(&mut buf, &mut pos, b" rdx=");
            q_dir_diag_write_hex(&mut buf, &mut pos, rdx, 16);
            q_dir_diag_write_bytes(&mut buf, &mut pos, b" r8=");
            q_dir_diag_write_hex(&mut buf, &mut pos, r8, 16);
            q_dir_diag_write_byte(&mut buf, &mut pos, b'\n');
            unsafe { libc::write(2, buf.as_ptr() as *const _, pos) };

            // Plant a return INT3 at [rsp] (the return address from the caller).
            // SAFETY: rsp is the guest stack pointer; [rsp] is the return addr
            // placed there by the `call` instruction at the callsite.
            if rsp != 0 {
                let ret_va = unsafe { (rsp as *const u64).read_volatile() };
                if ret_va >= pe_base as u64 && ret_va < (pe_base as u64) + (pe_size as u64) {
                    let ret_orig = unsafe { trace_d_write_byte(ret_va as usize, 0xCC) };
                    Q_DIR_TRACE_D_HELPER_RET_VA.store(ret_va, Ordering::Relaxed);
                    Q_DIR_TRACE_D_ORIG_RET.store(ret_orig, Ordering::Relaxed);

                    let mut buf2 = [0u8; 128];
                    let mut pos2 = 0usize;
                    q_dir_diag_write_bytes(
                        &mut buf2,
                        &mut pos2,
                        b"weave: trace-d 7795c return-bp planted at=",
                    );
                    q_dir_diag_write_hex(&mut buf2, &mut pos2, ret_va, 16);
                    q_dir_diag_write_byte(&mut buf2, &mut pos2, b'\n');
                    unsafe { libc::write(2, buf2.as_ptr() as *const _, pos2) };
                }
            }
        }
        return true;
    }

    // ── (c) dynamic return-site INT3 (planted by helper-entry hook) ───────
    let ret_va = Q_DIR_TRACE_D_HELPER_RET_VA.load(Ordering::Relaxed);
    if ret_va != 0 && bp_rip == ret_va as usize {
        let orig = Q_DIR_TRACE_D_ORIG_RET.load(Ordering::Relaxed);
        unsafe { trace_d_write_byte(bp_rip, orig) };
        unsafe { (*uctx).uc_mcontext.gregs[libc::REG_RIP as usize] = bp_rip as i64 };
        // Clear so subsequent calls don't hit a stale ret_va.
        Q_DIR_TRACE_D_HELPER_RET_VA.store(0, Ordering::Relaxed);

        if Q_DIR_TRACE_D_RETURN_FIRED
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            let rax = unsafe { (*uctx).uc_mcontext.gregs[libc::REG_RAX as usize] as u64 };
            let ret_rva = (bp_rip - pe_base) as u32;
            let mut buf = [0u8; 128];
            let mut pos = 0usize;
            q_dir_diag_write_bytes(&mut buf, &mut pos, b"weave: trace-d 7795c return rax=");
            q_dir_diag_write_hex(&mut buf, &mut pos, rax, 16);
            q_dir_diag_write_bytes(&mut buf, &mut pos, b" ret_rva=");
            q_dir_diag_write_hex(&mut buf, &mut pos, ret_rva as u64, 8);
            q_dir_diag_write_byte(&mut buf, &mut pos, b'\n');
            unsafe { libc::write(2, buf.as_ptr() as *const _, pos) };
        }
        return true;
    }

    false
}
