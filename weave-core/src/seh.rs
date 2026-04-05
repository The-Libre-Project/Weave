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

pub(crate) static PE_BASE: AtomicUsize = AtomicUsize::new(0);
pub(crate) static PE_SIZE: AtomicUsize = AtomicUsize::new(0);
pub(crate) static PDATA_RVA: AtomicUsize = AtomicUsize::new(0);
pub(crate) static PDATA_SIZE: AtomicUsize = AtomicUsize::new(0);

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

/// Return the base address at which the guest PE is mapped.
///
/// Returns 0 if called before [`install`].
pub fn pe_base() -> usize {
    PE_BASE.load(Ordering::Relaxed)
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

    // Read 8 bytes at fault address safely via /proc/self/mem.
    let fault_preview = {
        let path = b"/proc/self/mem\0";
        let fd = unsafe { libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDONLY) };
        let mut hex = [b'?'; 23]; // "?? ?? ?? ?? ?? ?? ?? ??"
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
            unsafe { libc::close(fd) };
            if n > 0 {
                // Format as hex without std::fmt (async-signal-safe enough for abort path)
                let _ = n; // silence unused
                hex = *b"?? ?? ?? ?? ?? ?? ?? ??";
                let nibble = |v: u8| if v < 10 { b'0' + v } else { b'a' + v - 10 };
                for (i, &byte) in buf[..n as usize].iter().enumerate() {
                    if i * 3 + 1 < hex.len() {
                        hex[i * 3] = nibble(byte >> 4);
                        hex[i * 3 + 1] = nibble(byte & 0xf);
                    }
                }
            }
        }
        hex
    };

    let sig_name: &[u8] = match sig {
        libc::SIGSEGV => b"SIGSEGV",
        libc::SIGFPE => b"SIGFPE",
        libc::SIGILL => b"SIGILL",
        libc::SIGBUS => b"SIGBUS",
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
    let stack_prev = read_u64_at(rsp - 8); // [RSP-8] — ret addr if ret crashed

    // Build message using only stack buffers (no heap) for signal safety.
    let mut msg = [0u8; 768];
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
            if found {
                push!(b"\nweave:   RIP maps  = ");
                for &b in &found_line[..found_line.iter().position(|&x| x == 0).unwrap_or(256)] {
                    if pos < msg.len() - 1 {
                        msg[pos] = b;
                        pos += 1;
                    }
                }
            }
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
