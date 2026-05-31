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

// ── Global PE metadata for async-signal-safe access ──────────────────────────
//
// Signal handlers cannot safely access complex data structures (locks, heap,
// etc.), so we cache only what we need as plain atomics.

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
    unsafe {
        libc::write(2, b"weave: sh got rip\n".as_ptr() as *const _, 18);
    }

    let base = PE_BASE.load(Ordering::Relaxed);
    let size = PE_SIZE.load(Ordering::Relaxed);

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
        // E3-M5b generic Q-Dir truncated-pointer fixup: Q-Dir's pool allocator
        // stores 64-bit pointers in DWORD fields.  When a fault_addr is in the
        // 32-bit range [0x10000, 0x8000_0000) it is almost certainly a truncated
        // 64-bit pointer.  Map the page at that address (MAP_FIXED_NOREPLACE,
        // zero-filled) and resume.  Also attempt to map the descriptor page at
        // (uint32_t)rdi when rdi is a high address.  Covers all RVAs in the
        // pool init chain, not just 0x7880d.  Fail #52.
        #[cfg(target_arch = "x86_64")]
        if sig == libc::SIGSEGV {
            let uctx_mut = ctx as *mut libc::ucontext_t;
            if q_dir_fixup_7880d_pool_ptr(base, size, uctx_mut) {
                return; // page(s) mapped; resume PE execution
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

/// Q-Dir E3-M5b generic truncated-pointer fixup.
///
/// Q-Dir's pool allocator stores 64-bit pointers in DWORD fields.  At any
/// SIGSEGV where the fault address is in [0x10000, 0x8000_0000) this is
/// almost certainly a truncated 64-bit pointer.  Map the faulting page using
/// MAP_FIXED_NOREPLACE (zero-filled) and resume.  Also attempt to map a copy
/// of the rdi pool descriptor if rdi is a high address — covers the call-chain
/// of truncation faults through sub_78698 and related functions.
///
/// Returns true if the signal handler should return (resuming PE execution).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn q_dir_fixup_7880d_pool_ptr(pe_base: usize, pe_size: usize, uctx: *mut libc::ucontext_t) -> bool {
    if pe_size != 0x1f3_000 {
        return false;
    }
    // Read the fault address from the signal context (si_addr equivalent via gregs).
    // On x86-64 Linux, CR2 (the page-fault linear address) is available in
    // uc_mcontext.gregs but not as a named constant — use the raw fault_addr
    // from siginfo instead via the calling context.  We derive it from rax since
    // for the 0x7880d case rax = fault_addr.  For the general case we use the
    // fault address already extracted by the caller (passed via the outer `fault_addr`
    // variable).  To access it here we re-derive from the saved gregs or just
    // use the page of rax.
    let regs = unsafe { &(*uctx).uc_mcontext.gregs };
    // Use REG_CR2 (index 22 on x86-64 Linux) for the fault linear address.
    // Index 18 is CSGSFS (segment registers), NOT CR2 — that was a bug.
    #[allow(clippy::cast_sign_loss)]
    let fault_addr = regs[libc::REG_CR2 as usize] as usize;

    // Only handle faults in the suspicious truncated-pointer range (any 32-bit
    // address above null: [0x10000, 0x1_0000_0000)).  Truncated 64-bit pointers
    // can land anywhere in the 32-bit address space, not just the bottom 2 GB.
    if fault_addr < 0x1_0000 || fault_addr >= 0x1_0000_0000 {
        return false;
    }

    const PAGE: usize = 0x1000;
    const MAP_FIXED_NOREPLACE: i32 = 0x100_000;

    // Map the faulting page (zero-filled).
    let fault_page = fault_addr & !(PAGE - 1);
    let fault_map = unsafe {
        libc::mmap(
            fault_page as *mut libc::c_void,
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if fault_map == libc::MAP_FAILED {
        // Page already mapped — the fault has a different cause; don't resume.
        return false;
    }

    // Seed [fault_addr + 8] = pe_base so that pool code reading [slot+8] as a
    // table-base pointer gets a valid non-null address (image_base) rather than 0.
    // TRACE-B analysis: the byte at image_base = 'M' (0x4D) is used as a BSS table
    // index; BSS is zero, so the function returns 0 harmlessly.  Without this seed,
    // [slot+8] = 0 and the deref of [0] causes a null fault at 0x784ba.  Fail #56.
    let in_page_off = fault_addr & (PAGE - 1);
    if in_page_off + 8 + 4 <= PAGE {
        unsafe { *((fault_page + in_page_off + 8) as *mut u32) = pe_base as u32 };
    }

    // Also attempt to map the rdi descriptor page if rdi is high, so that
    // code reading [truncated_rdi + offset] sees valid data.
    let rdi = regs[libc::REG_RDI as usize] as usize;
    if rdi >= 0x8000_0000 && !(rdi >= pe_base && rdi < pe_base + pe_size) {
        let rdi32 = rdi as u32 as usize;
        let desc_page = rdi32 & !(PAGE - 1);
        let desc_offset = rdi32 & (PAGE - 1);
        if desc_page != fault_page {
            let desc_map = unsafe {
                libc::mmap(
                    desc_page as *mut libc::c_void,
                    PAGE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                    -1,
                    0,
                )
            };
            if desc_map != libc::MAP_FAILED {
                let copy_len = (PAGE - desc_offset).min(0x200);
                unsafe {
                    libc::memcpy(
                        (desc_page + desc_offset) as *mut libc::c_void,
                        rdi as *const libc::c_void,
                        copy_len,
                    )
                };
            }
        }
    }

    let msg = b"weave: q-dir pool-fixup: mapped truncated-ptr page, resuming\n";
    unsafe { libc::write(2, msg.as_ptr() as *const _, msg.len()) };
    true
}
