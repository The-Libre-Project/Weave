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
use std::sync::atomic::{AtomicUsize, Ordering};

// ── Global PE metadata for async-signal-safe access ──────────────────────────
//
// Signal handlers cannot safely access complex data structures (locks, heap,
// etc.), so we cache only what we need as plain atomics.

static PE_BASE: AtomicUsize = AtomicUsize::new(0);
static PE_SIZE: AtomicUsize = AtomicUsize::new(0);
static PDATA_RVA: AtomicUsize = AtomicUsize::new(0);
static PDATA_SIZE: AtomicUsize = AtomicUsize::new(0);

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
        eprintln!("weave: exception handlers installed");
    }
}

// ── Signal handler installation ───────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn install_one(sig: libc::c_int) {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_flags = libc::SA_SIGINFO;
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
    let uctx = ctx as *const libc::ucontext_t;
    let rip = unsafe { (*uctx).uc_mcontext.gregs[libc::REG_RIP as usize] as usize };

    let base = PE_BASE.load(Ordering::Relaxed);
    let size = PE_SIZE.load(Ordering::Relaxed);

    if base != 0 && rip >= base && rip < base + size {
        // Fault in PE code — produce a crash report and exit.
        let rva = (rip - base) as u32;
        let fault_addr = unsafe { (*info).si_addr() } as usize;
        let win_code = signal_to_exception_code(sig);
        let func_range = find_runtime_function(base, rva);

        print_crash_report(sig, win_code, rip, rva, fault_addr, func_range, uctx);
        unsafe { libc::exit(win_code as i32) };
    } else {
        // Fault in Weave's own Rust code — restore the default handler and
        // re-raise so Rust's panic/abort handler takes over.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }
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

    // Dump 16 bytes before RIP and 16 bytes at RIP so we can identify both the
    // crashing instruction and the call/instruction that loaded the bad address.
    let pre_bytes = {
        let mut buf = [0u8; 16];
        let pre_rip = rip.saturating_sub(16);
        for (i, b) in buf.iter_mut().enumerate() {
            *b = unsafe { *(pre_rip as *const u8).add(i) };
        }
        buf
    };
    let pre_hex = pre_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let insn_bytes = {
        let mut buf = [0u8; 16];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = unsafe { *(rip as *const u8).add(i) };
        }
        buf
    };
    let insn_hex = insn_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");

    // Read 16 bytes at the fault address via /proc/self/mem (safe — doesn't
    // re-raise SIGSEGV even if the page is unmapped or read-only).
    let fault_bytes_hex = {
        let path = b"/proc/self/mem\0";
        let fd = unsafe { libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDONLY) };
        let mut hex = String::from("(unreadable)");
        if fd >= 0 {
            let mut buf = [0u8; 16];
            let n = unsafe {
                libc::pread(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    16,
                    fault_addr as i64,
                )
            };
            unsafe { libc::close(fd) };
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

    let msg = format!(
        "\nweave: CRASH — {sig_name} in PE code\n\
         weave:   exception = {win_code:#010x}  ({})\n\
         weave:   RIP       = {rip:#018x}  (PE rva {rva:#010x})\n\
         weave:   pre-insn  = [{pre_hex}]\n\
         weave:   insn      = [{insn_hex}]\n\
         weave:   fault     = {fault_addr:#018x}  [{fault_bytes_hex}]\n\
         weave:   region    = {fault_region}\n\
         weave:   function  = {func_line}\n\
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
