//! x64 Structured Exception Handling — dispatch and unwind.
//!
//! Implements the core Windows x64 exception dispatch mechanism:
//!
//!   1. **Search phase** — walk the stack via `.pdata`, calling each frame's
//!      language-specific handler (e.g. `__CxxFrameHandler4`) to find one that
//!      can handle the exception.
//!
//!   2. **Unwind phase** — walk the stack again from the bottom to the handler's
//!      frame, calling each intermediate frame's unwind handler (for `finally`
//!      blocks), then transfer control to the catch block.
//!
//! The implementation parses UNWIND_INFO structures embedded in the PE to
//! reverse each function's prolog and recover the caller's register state.

use std::sync::atomic::Ordering;

// ── Windows x64 CONTEXT ──────────────────────────────────────────────────────
//
// Must match the Windows SDK layout exactly (1232 bytes, 16-byte aligned)
// because PE-compiled handlers read and write fields by offset.

/// Windows x64 CONTEXT structure — full register state.
#[repr(C, align(16))]
pub struct Context {
    pub p1_home: u64,       // +0x000
    pub p2_home: u64,       // +0x008
    pub p3_home: u64,       // +0x010
    pub p4_home: u64,       // +0x018
    pub p5_home: u64,       // +0x020
    pub p6_home: u64,       // +0x028
    pub context_flags: u32, // +0x030
    pub mx_csr: u32,        // +0x034
    pub seg_cs: u16,        // +0x038
    pub seg_ds: u16,        // +0x03a
    pub seg_es: u16,        // +0x03c
    pub seg_fs: u16,        // +0x03e
    pub seg_gs: u16,        // +0x040
    pub seg_ss: u16,        // +0x042
    pub eflags: u32,        // +0x044
    pub dr0: u64,           // +0x048
    pub dr1: u64,           // +0x050
    pub dr2: u64,           // +0x058
    pub dr3: u64,           // +0x060
    pub dr6: u64,           // +0x068
    pub dr7: u64,           // +0x070
    pub rax: u64,           // +0x078
    pub rcx: u64,           // +0x080
    pub rdx: u64,           // +0x088
    pub rbx: u64,           // +0x090
    pub rsp: u64,           // +0x098
    pub rbp: u64,           // +0x0a0
    pub rsi: u64,           // +0x0a8
    pub rdi: u64,           // +0x0b0
    pub r8: u64,            // +0x0b8
    pub r9: u64,            // +0x0c0
    pub r10: u64,           // +0x0c8
    pub r11: u64,           // +0x0d0
    pub r12: u64,           // +0x0d8
    pub r13: u64,           // +0x0e0
    pub r14: u64,           // +0x0e8
    pub r15: u64,           // +0x0f0
    pub rip: u64,           // +0x0f8
    // XMM_SAVE_AREA32 (FXSAVE format, 512 bytes)
    pub flt_save: [u8; 512],          // +0x100 .. +0x300
    pub vector_register: [u128; 26],  // +0x300 .. +0x4a0
    pub vector_control: u64,          // +0x4a0
    pub debug_control: u64,           // +0x4a8
    pub last_branch_to_rip: u64,      // +0x4b0
    pub last_branch_from_rip: u64,    // +0x4b8
    pub last_exception_to_rip: u64,   // +0x4c0
    pub last_exception_from_rip: u64, // +0x4c8
}
// Static assert: sizeof(Context) == 1232
const _: () = assert!(std::mem::size_of::<Context>() == 1232);

impl Default for Context {
    fn default() -> Self {
        // Safety: all-zero is a valid Context
        unsafe { std::mem::zeroed() }
    }
}

// ── EXCEPTION_RECORD ─────────────────────────────────────────────────────────

pub const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;
pub const EXCEPTION_NONCONTINUABLE: u32 = 1;
pub const EXCEPTION_UNWINDING: u32 = 2;
pub const EXCEPTION_TARGET_UNWIND: u32 = 0x20;

/// Windows EXCEPTION_RECORD (x64 layout).
#[repr(C)]
pub struct ExceptionRecord {
    pub exception_code: u32,                                        // +0x00
    pub exception_flags: u32,                                       // +0x04
    pub exception_record: *mut ExceptionRecord,                     // +0x08
    pub exception_address: *mut u8,                                 // +0x10
    pub number_parameters: u32,                                     // +0x18
    _pad: u32,                                                      // +0x1c (alignment)
    pub exception_information: [u64; EXCEPTION_MAXIMUM_PARAMETERS], // +0x20
}
const _: () = assert!(std::mem::size_of::<ExceptionRecord>() == 152);

impl Default for ExceptionRecord {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

// ── RUNTIME_FUNCTION ─────────────────────────────────────────────────────────

/// Windows x64 RUNTIME_FUNCTION — one 12-byte entry per function in `.pdata`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RuntimeFunction {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_info_address: u32,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Everything below requires x86_64 (extern "win64" ABI, inline asm, etc.).
// On other targets the public items are simply absent — the stub crates that
// reference them are also cfg-gated to x86_64 builds.
// ═══════════════════════════════════════════════════════════════════════════════
#[cfg(target_arch = "x86_64")]
mod x64 {
    use super::*;

    // ── DISPATCHER_CONTEXT ───────────────────────────────────────────────────────

    /// Exception handler function pointer type.
    pub type ExceptionHandlerFn = unsafe extern "win64" fn(
        *mut ExceptionRecord,   // ExceptionRecord
        u64,                    // EstablisherFrame
        *mut Context,           // ContextRecord
        *mut DispatcherContext, // DispatcherContext
    ) -> i32;

    /// Windows x64 DISPATCHER_CONTEXT.
    #[repr(C)]
    pub struct DispatcherContext {
        pub control_pc: u64,                              // +0x00
        pub image_base: u64,                              // +0x08
        pub function_entry: *const RuntimeFunction,       // +0x10
        pub establisher_frame: u64,                       // +0x18
        pub target_ip: u64,                               // +0x20
        pub context_record: *mut Context,                 // +0x28
        pub language_handler: Option<ExceptionHandlerFn>, // +0x30
        pub handler_data: *const u8,                      // +0x38
        pub history_table: u64,                           // +0x40 (unused, set to 0)
        pub scope_index: u32,                             // +0x48
        pub control_pc_is_unwound: u32,                   // +0x4c
        pub non_volatile_registers: *const u8,            // +0x50
    }

    // ── Handler return codes ─────────────────────────────────────────────────────

    pub const EXCEPTION_CONTINUE_EXECUTION: i32 = 0;
    #[allow(dead_code)]
    pub const EXCEPTION_CONTINUE_SEARCH: i32 = 1;

    // ── UNWIND_INFO structures ───────────────────────────────────────────────────

    const UNW_FLAG_EHANDLER: u8 = 1;
    const UNW_FLAG_UHANDLER: u8 = 2;
    const UNW_FLAG_CHAININFO: u8 = 4;

    // Unwind operation codes
    const UWOP_PUSH_NONVOL: u8 = 0;
    const UWOP_ALLOC_LARGE: u8 = 1;
    const UWOP_ALLOC_SMALL: u8 = 2;
    const UWOP_SET_FPREG: u8 = 3;
    const UWOP_SAVE_NONVOL: u8 = 4;
    const UWOP_SAVE_NONVOL_FAR: u8 = 5;
    const UWOP_SAVE_XMM128: u8 = 8;
    const UWOP_SAVE_XMM128_FAR: u8 = 9;
    const UWOP_PUSH_MACHFRAME: u8 = 10;

    /// Register number → get/set helpers for Context.
    fn ctx_get_reg(ctx: &Context, reg: u8) -> u64 {
        match reg {
            0 => ctx.rax,
            1 => ctx.rcx,
            2 => ctx.rdx,
            3 => ctx.rbx,
            4 => ctx.rsp,
            5 => ctx.rbp,
            6 => ctx.rsi,
            7 => ctx.rdi,
            8 => ctx.r8,
            9 => ctx.r9,
            10 => ctx.r10,
            11 => ctx.r11,
            12 => ctx.r12,
            13 => ctx.r13,
            14 => ctx.r14,
            15 => ctx.r15,
            _ => 0,
        }
    }

    fn ctx_set_reg(ctx: &mut Context, reg: u8, val: u64) {
        match reg {
            0 => ctx.rax = val,
            1 => ctx.rcx = val,
            2 => ctx.rdx = val,
            3 => ctx.rbx = val,
            4 => ctx.rsp = val,
            5 => ctx.rbp = val,
            6 => ctx.rsi = val,
            7 => ctx.rdi = val,
            8 => ctx.r8 = val,
            9 => ctx.r9 = val,
            10 => ctx.r10 = val,
            11 => ctx.r11 = val,
            12 => ctx.r12 = val,
            13 => ctx.r13 = val,
            14 => ctx.r14 = val,
            15 => ctx.r15 = val,
            _ => {}
        }
    }

    /// Read a u64 from a pointer (unaligned-safe).
    unsafe fn read_u64(p: *const u8) -> u64 {
        (p as *const u64).read_unaligned()
    }

    /// Read a u32 from a pointer (unaligned-safe).
    unsafe fn read_u32(p: *const u8) -> u32 {
        (p as *const u32).read_unaligned()
    }

    /// Read a u16 from a pointer (unaligned-safe).
    unsafe fn read_u16(p: *const u8) -> u16 {
        (p as *const u16).read_unaligned()
    }

    // ── RtlLookupFunctionEntry ───────────────────────────────────────────────────

    /// Binary-search the `.pdata` exception table for the function containing `rva`.
    pub fn lookup_function_entry(
        image_base: usize,
        control_pc: u64,
    ) -> Option<*const RuntimeFunction> {
        let pdata_rva = crate::seh::PDATA_RVA.load(Ordering::Relaxed);
        let pdata_size = crate::seh::PDATA_SIZE.load(Ordering::Relaxed);
        if pdata_rva == 0 || pdata_size < 12 {
            return None;
        }

        let rva = (control_pc as usize).wrapping_sub(image_base) as u32;
        let table = (image_base + pdata_rva) as *const RuntimeFunction;
        let count = pdata_size / 12;

        // Binary search — .pdata is sorted by BeginAddress.
        let mut lo = 0usize;
        let mut hi = count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let entry = unsafe { &*table.add(mid) };
            if rva < entry.begin_address {
                hi = mid;
            } else if rva >= entry.end_address {
                lo = mid + 1;
            } else {
                return Some(unsafe { table.add(mid) });
            }
        }
        None
    }

    // ── RtlVirtualUnwind ─────────────────────────────────────────────────────────

    /// Result of virtual unwinding one frame.
    pub struct UnwindResult {
        pub handler: Option<ExceptionHandlerFn>,
        pub handler_data: *const u8,
        pub establisher_frame: u64,
    }

    /// Virtually unwind one stack frame using the UNWIND_INFO in the PE.
    ///
    /// Updates `ctx` to represent the caller's register state.
    /// Returns the exception handler (if any) and its data pointer.
    ///
    /// # Safety
    /// `image_base` must be the mapped PE base, `func` must point to a valid
    /// RUNTIME_FUNCTION entry, and `ctx` must contain the current frame's state.
    pub unsafe fn virtual_unwind(
        image_base: usize,
        _control_pc: u64,
        func: *const RuntimeFunction,
        ctx: &mut Context,
    ) -> UnwindResult {
        let rf = unsafe { &*func };
        let unwind_rva = rf.unwind_info_address;

        // Handle chained unwind info — follow the chain.
        let mut info_ptr = (image_base + unwind_rva as usize) as *const u8;

        loop {
            let version_flags = unsafe { *info_ptr };
            let _version = version_flags & 0x07;
            let flags = (version_flags >> 3) & 0x1f;
            let _size_of_prolog = unsafe { *info_ptr.add(1) };
            let count_of_codes = unsafe { *info_ptr.add(2) } as usize;
            let frame_reg_and_offset = unsafe { *info_ptr.add(3) };
            let frame_register = frame_reg_and_offset & 0x0f;
            let frame_offset = ((frame_reg_and_offset >> 4) & 0x0f) as u64 * 16;

            let codes_base = info_ptr.add(4);

            // Apply unwind codes to reverse the prolog.
            // We process all codes (assuming we're in the function body, not prolog).
            let mut i = 0usize;
            while i < count_of_codes {
                let code_ptr = unsafe { codes_base.add(i * 2) };
                let _code_offset = unsafe { *code_ptr };
                let op_and_info = unsafe { *code_ptr.add(1) };
                let unwind_op = op_and_info & 0x0f;
                let op_info = (op_and_info >> 4) & 0x0f;

                match unwind_op {
                    UWOP_PUSH_NONVOL => {
                        // Pop register from stack
                        let val = unsafe { read_u64(ctx.rsp as *const u8) };
                        ctx_set_reg(ctx, op_info, val);
                        ctx.rsp += 8;
                        i += 1;
                    }
                    UWOP_ALLOC_LARGE => {
                        if op_info == 0 {
                            // Next slot is size / 8 as u16
                            let slots = unsafe { read_u16(codes_base.add((i + 1) * 2)) } as u64;
                            ctx.rsp += slots * 8;
                            i += 2;
                        } else {
                            // Next two slots are raw size as u32
                            let size = unsafe { read_u32(codes_base.add((i + 1) * 2)) } as u64;
                            ctx.rsp += size;
                            i += 3;
                        }
                    }
                    UWOP_ALLOC_SMALL => {
                        ctx.rsp += (op_info as u64) * 8 + 8;
                        i += 1;
                    }
                    UWOP_SET_FPREG => {
                        // RSP = frame_register - frame_offset
                        ctx.rsp = ctx_get_reg(ctx, frame_register).wrapping_sub(frame_offset);
                        i += 1;
                    }
                    UWOP_SAVE_NONVOL => {
                        let offset = unsafe { read_u16(codes_base.add((i + 1) * 2)) } as u64 * 8;
                        let val = unsafe { read_u64((ctx.rsp + offset) as *const u8) };
                        ctx_set_reg(ctx, op_info, val);
                        i += 2;
                    }
                    UWOP_SAVE_NONVOL_FAR => {
                        let offset = unsafe { read_u32(codes_base.add((i + 1) * 2)) } as u64;
                        let val = unsafe { read_u64((ctx.rsp + offset) as *const u8) };
                        ctx_set_reg(ctx, op_info, val);
                        i += 3;
                    }
                    UWOP_SAVE_XMM128 => {
                        // Skip — we don't track XMM state for exception dispatch
                        i += 2;
                    }
                    UWOP_SAVE_XMM128_FAR => {
                        i += 3;
                    }
                    UWOP_PUSH_MACHFRAME => {
                        // Machine frame pushed by interrupt/exception.
                        // op_info 0: [RIP, CS, EFLAGS, RSP, SS]
                        // op_info 1: [ErrorCode, RIP, CS, EFLAGS, RSP, SS]
                        if op_info == 1 {
                            ctx.rsp += 8; // skip error code
                        }
                        ctx.rip = unsafe { read_u64(ctx.rsp as *const u8) };
                        ctx.rsp += 24; // skip RIP, CS, EFLAGS
                        ctx.rsp = unsafe { read_u64(ctx.rsp as *const u8) };
                        // Don't pop RIP again below
                        let establisher_frame = if frame_register != 0 {
                            ctx_get_reg(ctx, frame_register)
                        } else {
                            ctx.rsp
                        };
                        return UnwindResult {
                            handler: None,
                            handler_data: std::ptr::null(),
                            establisher_frame,
                        };
                    }
                    _ => {
                        // Unknown opcode — skip 1 slot
                        i += 1;
                    }
                }
            }

            // After processing codes, check for chained info
            if flags & UNW_FLAG_CHAININFO != 0 {
                // Chained RUNTIME_FUNCTION follows the codes (aligned to u32)
                let after_codes = unsafe { codes_base.add(count_of_codes * 2) };
                let aligned = ((after_codes as usize + 3) & !3) as *const u8;
                let chained_rf = aligned as *const RuntimeFunction;
                let chained = unsafe { &*chained_rf };
                info_ptr = (image_base + chained.unwind_info_address as usize) as *const u8;
                continue; // process chained unwind info
            }

            // Pop return address into RIP
            ctx.rip = unsafe { read_u64(ctx.rsp as *const u8) };
            ctx.rsp += 8;

            // Establisher frame = RSP after unwind (before popping return address),
            // or frame register value if one was set.
            let establisher_frame = if frame_register != 0 {
                ctx_get_reg(ctx, frame_register)
            } else {
                ctx.rsp
            };

            // Extract handler if present
            let handler;
            let handler_data;
            if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
                let after_codes = unsafe { codes_base.add(count_of_codes * 2) };
                let aligned = ((after_codes as usize + 3) & !3) as *const u8;
                let handler_rva = unsafe { read_u32(aligned) } as usize;
                let handler_addr = image_base + handler_rva;
                handler =
                    Some(unsafe { std::mem::transmute::<usize, ExceptionHandlerFn>(handler_addr) });
                handler_data = unsafe { aligned.add(4) }; // language-specific data follows
            } else {
                handler = None;
                handler_data = std::ptr::null();
            }

            return UnwindResult {
                handler,
                handler_data,
                establisher_frame,
            };
        }
    }

    // ── dispatch_exception (search phase) ────────────────────────────────────────

    /// Walk the stack and find a handler for the exception.
    ///
    /// Returns `Some((frame_rsp, target_ip, handler_idx))` if a handler was found,
    /// or `None` if no handler matched (unhandled exception).
    ///
    /// # Safety
    /// `exc_record` and `ctx` must be valid. The Context must represent the state
    /// at the throw site.
    pub unsafe fn dispatch_exception(exc_record: &mut ExceptionRecord, ctx: &mut Context) -> bool {
        let image_base = crate::seh::PE_BASE.load(Ordering::Relaxed);
        if image_base == 0 {
            return false;
        }

        // Save original context for the unwind phase
        let mut dispatch_ctx: Context = Default::default();
        // Copy the context
        unsafe {
            std::ptr::copy_nonoverlapping(
                ctx as *const Context,
                &mut dispatch_ctx as *mut Context,
                1,
            );
        }

        // Walk up to 256 frames to prevent infinite loops
        for _frame_idx in 0..256 {
            let control_pc = dispatch_ctx.rip;

            // Check if we're still in PE code
            let pe_size = crate::seh::PE_SIZE.load(Ordering::Relaxed);
            let pc_usize = control_pc as usize;
            if pc_usize < image_base || pc_usize >= image_base + pe_size {
                // Left PE code — no handler found
                eprintln!(
                    "weave: SEH dispatch: frame left PE at {control_pc:#x} (base={image_base:#x})"
                );
                return false;
            }

            let func = match lookup_function_entry(image_base, control_pc) {
                Some(f) => f,
                None => {
                    // Leaf function (no .pdata entry): RSP points to return address
                    dispatch_ctx.rip = unsafe { read_u64(dispatch_ctx.rsp as *const u8) };
                    dispatch_ctx.rsp += 8;
                    continue;
                }
            };

            let rva = (control_pc as usize - image_base) as u32;
            let mut frame_ctx = Default::default();
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &dispatch_ctx as *const Context,
                    &mut frame_ctx as *mut Context,
                    1,
                );
            }

            let result = unsafe { virtual_unwind(image_base, control_pc, func, &mut dispatch_ctx) };

            if let Some(handler) = result.handler {
                // Build DISPATCHER_CONTEXT for the handler
                let mut dc = DispatcherContext {
                    control_pc,
                    image_base: image_base as u64,
                    function_entry: func,
                    establisher_frame: result.establisher_frame,
                    target_ip: 0,
                    context_record: ctx, // original context at throw site
                    language_handler: Some(handler),
                    handler_data: result.handler_data,
                    history_table: 0,
                    scope_index: 0,
                    control_pc_is_unwound: 0,
                    non_volatile_registers: std::ptr::null(),
                };

                // Log exc_record parameters for diagnosis
                eprintln!(
                "weave: SEH search: calling handler at {:#x} for frame rva={rva:#x} (establisher={:#x})",
                handler as usize, result.establisher_frame
            );
                eprintln!(
                    "weave: SEH search:  exc_code={:#x} exc_flags={:#x} n_params={}",
                    exc_record.exception_code,
                    exc_record.exception_flags,
                    exc_record.number_parameters
                );
                if exc_record.number_parameters >= 4 {
                    eprintln!(
                        "weave: SEH search:  params[0]={:#x} [1]={:#x} [2]={:#x} [3]={:#x}",
                        exc_record.exception_information[0],
                        exc_record.exception_information[1],
                        exc_record.exception_information[2],
                        exc_record.exception_information[3],
                    );
                }
                eprintln!(
                    "weave: SEH search:  handler_data={:#x} ctx.rip={:#x} ctx.rsp={:#x}",
                    result.handler_data as usize,
                    ctx.rip,
                    ctx.rsp // ctx is throw-site context
                );
                // Read first 4 bytes at handler_data (should be FuncInfo RVA)
                if !result.handler_data.is_null() {
                    let funcinfo_rva = unsafe { read_u32(result.handler_data) };
                    let funcinfo_abs = image_base + funcinfo_rva as usize;
                    eprintln!(
                    "weave: SEH search:  handler_data[0..4]={funcinfo_rva:#x} → funcinfo_abs={funcinfo_abs:#x}"
                );
                }

                // Call the language-specific handler in search mode
                let disposition =
                    unsafe { handler(exc_record, result.establisher_frame, ctx, &mut dc) };

                eprintln!(
                    "weave: SEH search: handler disposition={disposition} target_ip={:#x}",
                    dc.target_ip
                );

                match disposition {
                    // ExceptionContinueSearch (1) — not handled, keep walking
                    1 => {}
                    // ExceptionContinueExecution (0) — exception resolved, resume
                    0 => {
                        return true;
                    }
                    _ => {
                        // ExceptionNestedException (2), ExceptionCollidedUnwind (3), etc.
                        eprintln!("weave: SEH search: unexpected disposition {disposition}");
                    }
                }
            }
            // No handler or handler said continue search — keep walking
        }

        eprintln!("weave: SEH dispatch: exhausted 256 frames without finding handler");
        false
    }

    // ── RtlUnwindEx (unwind phase) ───────────────────────────────────────────────

    /// Unwind the stack to `target_frame` and transfer control to `target_ip`.
    ///
    /// This walks from the current frame up to the target, calling each
    /// intermediate frame's unwind handler (UNW_FLAG_UHANDLER), then jumps
    /// to the catch block.
    ///
    /// # Safety
    /// All pointers must be valid. Does not return.
    pub unsafe fn unwind_ex(
        target_frame: u64,
        target_ip: u64,
        exc_record: *mut ExceptionRecord,
        return_value: u64,
        original_ctx: *mut Context,
    ) -> ! {
        let image_base = crate::seh::PE_BASE.load(Ordering::Relaxed);

        // Build an unwind-phase EXCEPTION_RECORD
        let exc = unsafe { &mut *exc_record };
        exc.exception_flags |= EXCEPTION_UNWINDING;

        // Capture current context for stack walking
        let mut walk_ctx: Context = Default::default();
        unsafe {
            std::ptr::copy_nonoverlapping(
                original_ctx as *const Context,
                &mut walk_ctx as *mut Context,
                1,
            );
        }

        // Walk frames calling unwind handlers until we reach the target
        for _ in 0..256 {
            let control_pc = walk_ctx.rip;
            let pc_usize = control_pc as usize;
            let pe_size = crate::seh::PE_SIZE.load(Ordering::Relaxed);

            if pc_usize < image_base || pc_usize >= image_base + pe_size {
                break;
            }

            let func = match lookup_function_entry(image_base, control_pc) {
                Some(f) => f,
                None => {
                    // Leaf function — pop return address
                    walk_ctx.rip = unsafe { read_u64(walk_ctx.rsp as *const u8) };
                    walk_ctx.rsp += 8;
                    continue;
                }
            };

            // Save the catching frame's live state BEFORE virtual_unwind consumes it.
            //
            // virtual_unwind reverses the frame's prolog: it restores nonvolatile
            // registers by reading the saved copies from the stack.  After the call,
            // walk_ctx holds the CALLER's register values, not this frame's live values.
            //
            // For the catching frame we need the LIVE values (set by code inside
            // the catching function between its prolog and the throw), so we capture
            // everything before calling virtual_unwind.
            let pre_rsp = walk_ctx.rsp;
            let pre_rbx = walk_ctx.rbx;
            let pre_rbp = walk_ctx.rbp;
            let pre_rsi = walk_ctx.rsi;
            let pre_rdi = walk_ctx.rdi;
            let pre_r12 = walk_ctx.r12;
            let pre_r13 = walk_ctx.r13;
            let pre_r14 = walk_ctx.r14;
            let pre_r15 = walk_ctx.r15;

            let result = unsafe { virtual_unwind(image_base, control_pc, func, &mut walk_ctx) };

            // Check if we've reached the target frame
            if result.establisher_frame == target_frame {
                // We're at the target — restore the catching frame's live register state.
                let final_ctx = unsafe { &mut *original_ctx };
                final_ctx.rbx = pre_rbx;
                final_ctx.rbp = pre_rbp;
                final_ctx.rsi = pre_rsi;
                final_ctx.rdi = pre_rdi;
                final_ctx.r12 = pre_r12;
                final_ctx.r13 = pre_r13;
                final_ctx.r14 = pre_r14;
                final_ctx.r15 = pre_r15;
                // RSP = inside-function RSP of the catching frame.
                final_ctx.rsp = pre_rsp;
                final_ctx.rip = target_ip;
                final_ctx.rax = return_value;

                eprintln!(
                "weave: SEH unwind: reached target frame={target_frame:#x} ip={target_ip:#x} rsp={pre_rsp:#x}"
            );

                // Transfer control to the catch block
                jump_to_context(final_ctx);
            }

            // Call unwind handler for intermediate frames (finally blocks)
            if let Some(handler) = result.handler {
                let mut dc = DispatcherContext {
                    control_pc,
                    image_base: image_base as u64,
                    function_entry: func,
                    establisher_frame: result.establisher_frame,
                    target_ip,
                    context_record: original_ctx,
                    language_handler: Some(handler),
                    handler_data: result.handler_data,
                    history_table: 0,
                    scope_index: 0,
                    control_pc_is_unwound: 1,
                    non_volatile_registers: std::ptr::null(),
                };

                // Set unwind + target flags for the target frame
                let saved_flags = exc.exception_flags;
                if result.establisher_frame == target_frame {
                    exc.exception_flags |= EXCEPTION_TARGET_UNWIND;
                }

                unsafe {
                    handler(exc_record, result.establisher_frame, original_ctx, &mut dc);
                }

                exc.exception_flags = saved_flags | EXCEPTION_UNWINDING;
            }
        }

        // If we couldn't reach the target, fatal error
        eprintln!("weave: SEH unwind: FAILED to reach target frame={target_frame:#x}");
        unsafe { libc::exit(1) }
    }

    // ── Context jump (transfer control) ──────────────────────────────────────────

    /// Transfer control to the context's RIP with the context's register state.
    ///
    /// This is equivalent to Windows' `RtlRestoreContext` — it loads registers from
    /// the Context and jumps to RIP. Does not return.
    unsafe fn jump_to_context(ctx: &Context) -> ! {
        // We need to restore: RBX, RBP, RSI, RDI, R12-R15, RSP, RIP, RAX
        // (nonvolatile registers + the return value in RAX + control flow)
        unsafe {
            std::arch::asm!(
                // Load nonvolatile registers from Context
                "mov rbx, [rdi + 0x90]",  // rbx
                "mov rbp, [rdi + 0xa0]",  // rbp
                "mov rsi, [rdi + 0xa8]",  // rsi
                "mov r12, [rdi + 0xd8]",  // r12
                "mov r13, [rdi + 0xe0]",  // r13
                "mov r14, [rdi + 0xe8]",  // r14
                "mov r15, [rdi + 0xf0]",  // r15
                "mov rax, [rdi + 0x78]",  // rax (return value / exception object)
                "mov rcx, [rdi + 0x80]",  // rcx
                "mov rdx, [rdi + 0x88]",  // rdx
                // Load target RSP and RIP
                "mov rsp, [rdi + 0x98]",  // rsp
                "mov r11, [rdi + 0xf8]",  // rip → r11 (temp)
                // Restore rdi last (it's our pointer)
                "mov rdi, [rdi + 0xb0]",  // rdi
                // Jump to target
                "jmp r11",
                in("rdi") ctx as *const Context,
                options(noreturn)
            );
        }
    }

    // ── RaiseException (entry point) ─────────────────────────────────────────────

    /// Raise a Windows exception and dispatch it through the SEH chain.
    ///
    /// This is the implementation behind kernel32!RaiseException.
    ///
    /// # Safety
    /// `arguments` must point to `num_args` valid u64 values (or be null if
    /// num_args is 0).
    pub unsafe fn raise_exception(
        exception_code: u32,
        exception_flags: u32,
        num_args: u32,
        arguments: *const u64,
    ) {
        let mut exc_record = ExceptionRecord {
            exception_code,
            exception_flags,
            exception_record: std::ptr::null_mut(),
            exception_address: std::ptr::null_mut(),
            number_parameters: num_args.min(EXCEPTION_MAXIMUM_PARAMETERS as u32),
            ..Default::default()
        };
        for i in 0..exc_record.number_parameters as usize {
            exc_record.exception_information[i] = unsafe { *arguments.add(i) };
        }

        // Capture caller context by scanning the stack for the first return
        // address that lands inside the PE image.
        //
        // We cannot reliably use RBP-based frame walking here because:
        //   1. This function is called through multiple Rust wrapper frames
        //      (extern "win64" in kernel32 → this fn), so [rbp+8] gives a
        //      Rust-internal address, not the PE caller.
        //   2. Rust debug builds may not emit frame-pointer prologs for every
        //      function, making [rbp+8] undefined.
        //
        // Instead: read current RSP and scan upward for the first word that
        // falls within [PE_BASE, PE_BASE+PE_SIZE).  That word is the return
        // address from the PE code that ultimately triggered the exception, and
        // the RSP at that call site is (scan_addr + 8).
        let mut ctx = Context::default();

        let pe_base = crate::seh::PE_BASE.load(Ordering::Relaxed) as u64;
        let pe_size = crate::seh::PE_SIZE.load(Ordering::Relaxed) as u64;

        let mut cur_rsp: u64;
        unsafe {
            std::arch::asm!("mov {}, rsp", out(reg) cur_rsp, options(nomem, nostack));
        }

        // Capture current nonvolatile registers (these are valid for the throw site).
        let rbx_val: u64;
        let rbp_val: u64;
        let rdi_val: u64;
        let rsi_val: u64;
        let r12_val: u64;
        let r13_val: u64;
        let r14_val: u64;
        let r15_val: u64;
        unsafe {
            std::arch::asm!("mov {}, rbx", out(reg) rbx_val, options(nomem, nostack));
            std::arch::asm!("mov {}, rbp", out(reg) rbp_val, options(nomem, nostack));
            std::arch::asm!("mov {}, rdi", out(reg) rdi_val, options(nomem, nostack));
            std::arch::asm!("mov {}, rsi", out(reg) rsi_val, options(nomem, nostack));
            std::arch::asm!("mov {}, r12", out(reg) r12_val, options(nomem, nostack));
            std::arch::asm!("mov {}, r13", out(reg) r13_val, options(nomem, nostack));
            std::arch::asm!("mov {}, r14", out(reg) r14_val, options(nomem, nostack));
            std::arch::asm!("mov {}, r15", out(reg) r15_val, options(nomem, nostack));
        }

        // Scan the stack for the first PE return address.
        //
        // We require the candidate to be within a function covered by .pdata, to
        // distinguish real code return addresses from PE data pointers (e.g. the
        // image_base and ThrowInfo arguments stored in stack frames above us).
        let mut caller_rip: u64 = 0;
        let mut caller_rsp: u64 = 0;
        // Align to 8 bytes before scanning.
        cur_rsp &= !7u64;
        eprintln!(
            "weave: raise_exception scan start: cur_rsp={cur_rsp:#x} pe=[{pe_base:#x},{:#x})",
            pe_base + pe_size
        );
        // Hard limit: only scan 64 KB upward to avoid reading unmapped guard pages.
        let scan_limit = cur_rsp.saturating_add(64 * 1024);
        for i in 0..512usize {
            let addr = cur_rsp + (i * 8) as u64;
            if addr >= scan_limit {
                break;
            }
            let candidate = unsafe { *(addr as *const u64) };
            if pe_base > 0 && candidate > pe_base && candidate < pe_base + pe_size {
                // Only accept if this is within a function that has .pdata coverage.
                // This rejects PE data values (image_base, ThrowInfo pointers, etc.)
                // which happen to lie in the PE address range but aren't code addresses.
                if lookup_function_entry(pe_base as usize, candidate).is_some() {
                    caller_rip = candidate;
                    caller_rsp = addr + 8;
                    break;
                }
            }
        }

        if caller_rip == 0 {
            // Fallback: no PE address found on stack — exception has no PE origin.
            eprintln!(
            "weave: RaiseException code={exception_code:#x} — no PE return address found on stack"
        );
            unsafe { libc::abort() };
        }

        ctx.rip = caller_rip;
        ctx.rsp = caller_rsp;
        ctx.rbx = rbx_val;
        ctx.rbp = rbp_val;
        ctx.rdi = rdi_val;
        ctx.rsi = rsi_val;
        ctx.r12 = r12_val;
        ctx.r13 = r13_val;
        ctx.r14 = r14_val;
        ctx.r15 = r15_val;
        ctx.context_flags = 0x10001f; // CONTEXT_ALL

        exc_record.exception_address = caller_rip as *mut u8;

        eprintln!(
        "weave: RaiseException code={exception_code:#x} flags={exception_flags:#x} at rip={caller_rip:#x}"
    );

        let handled = unsafe { dispatch_exception(&mut exc_record, &mut ctx) };
        if !handled {
            eprintln!("weave: unhandled exception {exception_code:#x} — aborting");
            unsafe { libc::abort() };
        }
    }

    // ── Exported stubs for kernel32/ntdll imports ────────────────────────────────
    /// Kernel32/ntdll RtlUnwindEx export — called by PE code (e.g. MSVC CRT's
    /// `__CxxFrameHandler`) to unwind to a catch block.
    ///
    /// # Safety
    /// All pointer arguments must be valid.
    pub unsafe extern "win64" fn rtl_unwind_ex_export(
        target_frame: *mut u8,
        target_ip: *mut u8,
        exception_record: *mut ExceptionRecord,
        return_value: u64,
        context_record: *mut Context,
        _history_table: u64,
    ) {
        eprintln!(
        "weave: RtlUnwindEx called: target_frame={:#x} target_ip={:#x} return_value={return_value:#x}",
        target_frame as usize, target_ip as usize
    );

        unsafe {
            unwind_ex(
                target_frame as u64,
                target_ip as u64,
                exception_record,
                return_value,
                context_record,
            );
        }
    }

    /// Kernel32/ntdll RtlVirtualUnwind export.
    ///
    /// # Safety
    /// All pointer arguments must be valid.
    pub unsafe extern "win64" fn rtl_virtual_unwind_export(
        handler_type: u32,
        image_base: u64,
        control_pc: u64,
        function_entry: *const RuntimeFunction,
        context_record: *mut Context,
        handler_data: *mut *const u8,
        establisher_frame: *mut u64,
        _context_pointers: *mut u8,
    ) -> usize {
        let _ = handler_type;
        let ctx = unsafe { &mut *context_record };
        let result =
            unsafe { virtual_unwind(image_base as usize, control_pc, function_entry, ctx) };

        if !handler_data.is_null() {
            unsafe { *handler_data = result.handler_data };
        }
        if !establisher_frame.is_null() {
            unsafe { *establisher_frame = result.establisher_frame };
        }

        match result.handler {
            Some(h) => h as usize,
            None => 0,
        }
    }

    /// Kernel32/ntdll RtlLookupFunctionEntry export.
    ///
    /// # Safety
    /// `image_base_out` must be a valid writable pointer.
    pub unsafe extern "win64" fn rtl_lookup_function_entry_export(
        control_pc: u64,
        image_base_out: *mut u64,
        _history_table: u64,
    ) -> *const RuntimeFunction {
        let image_base = crate::seh::PE_BASE.load(Ordering::Relaxed);
        if !image_base_out.is_null() {
            unsafe { *image_base_out = image_base as u64 };
        }
        match lookup_function_entry(image_base, control_pc) {
            Some(ptr) => ptr,
            None => std::ptr::null(),
        }
    }

    /// Kernel32!RtlCaptureContext export.
    ///
    /// # Safety
    /// `context_record` must point to a writable Context-sized buffer.
    pub unsafe extern "win64" fn rtl_capture_context_export(context_record: *mut Context) {
        // Minimal capture — just zero it and set flags.
        // Full capture would require inline asm to read all registers, but most
        // callers only need RSP/RIP/nonvol which are set by the calling code.
        if !context_record.is_null() {
            let ctx = unsafe { &mut *context_record };
            *ctx = Context::default();
            ctx.context_flags = 0x10001f; // CONTEXT_ALL
        }
    }

    // ── MSVC C++ frame handler ───────────────────────────────────────────────────

    /// Real implementation of MSVC `__CxxFrameHandler3` / `__CxxFrameHandler4`.
    ///
    /// In search mode: parses FuncInfo, finds a matching catch handler (catch-all
    /// only for now), calls the funclet to get the continuation address, then calls
    /// `unwind_ex` to unwind the stack and jump to the continuation.
    ///
    /// In unwind mode: returns ExceptionContinueSearch (1) — we handle finally
    /// blocks implicitly through unwind_ex.
    ///
    /// # Safety
    /// All pointer arguments must be valid Windows x64 SEH structures.
    pub unsafe extern "win64" fn cxx_frame_handler(
        exc_record: *mut ExceptionRecord,
        establisher_frame: u64,
        ctx: *mut Context,
        dc: *mut DispatcherContext,
    ) -> i32 {
        let exc = unsafe { &*exc_record };
        let dc_ref = unsafe { &*dc };

        // Unwind phase: no-op (finally blocks run via unwind_ex's handler calls).
        if exc.exception_flags & EXCEPTION_UNWINDING != 0 {
            return 1; // ExceptionContinueSearch
        }

        // Only handle C++ exceptions.
        const CXX_EXCEPTION_CODE: u32 = 0xE06D7363;
        if exc.exception_code != CXX_EXCEPTION_CODE {
            return 1;
        }

        let image_base = dc_ref.image_base as usize;
        let handler_data = dc_ref.handler_data;
        if handler_data.is_null() {
            return 1;
        }

        // handler_data is a pointer to a u32 FuncInfo RVA.
        let funcinfo_rva = unsafe { read_u32(handler_data) } as usize;
        let fi = (image_base + funcinfo_rva) as *const u8;

        // Validate FuncInfo magic.
        let magic = unsafe { read_u32(fi) };
        if magic != 0x19930520 && magic != 0x19930521 && magic != 0x19930522 {
            eprintln!("weave: CxxFrameHandler: unexpected FuncInfo magic {magic:#x}");
            return 1;
        }

        // FuncInfo layout (x64, image-relative RVA format, magic:29+bbtFlags:3 packed):
        //  +0x00  magic:29 + bbtFlags:3  (u32) ← single word, NOT two separate fields
        //  +0x04  maxState    (i32)
        //  +0x08  dispUnwindMap (u32) — RVA
        //  +0x0c  nTryBlocks  (u32)
        //  +0x10  dispTryBlockMap (u32) — RVA to TryBlockMapEntry[]
        //  +0x14  nIPMapEntries (u32)
        //  +0x18  dispIPtoStateMap (u32) — RVA to IpToStateMapEntry[]
        //  +0x1c  pESTypeList (u32) — RVA
        //  +0x20  EHFlags (u32)

        // Print raw FuncInfo bytes the first few times to verify the layout.
        {
            use std::sync::atomic::{AtomicUsize, Ordering as AO};
            static DUMP_COUNT: AtomicUsize = AtomicUsize::new(0);
            let n = DUMP_COUNT.fetch_add(1, AO::Relaxed);
            if n < 3 {
                let w: [u32; 8] = unsafe {
                    [
                        read_u32(fi),
                        read_u32(fi.add(4)),
                        read_u32(fi.add(8)),
                        read_u32(fi.add(12)),
                        read_u32(fi.add(16)),
                        read_u32(fi.add(20)),
                        read_u32(fi.add(24)),
                        read_u32(fi.add(28)),
                    ]
                };
                eprintln!(
                "weave: FuncInfo[{n}] @ {:#x}: {:08x} {:08x} {:08x} {:08x}  {:08x} {:08x} {:08x} {:08x}",
                fi as usize, w[0],w[1],w[2],w[3], w[4],w[5],w[6],w[7]
            );
            }
        }

        let n_try_blocks = unsafe { read_u32(fi.add(0x0c)) } as usize;
        let disp_try_block = unsafe { read_u32(fi.add(0x10)) } as usize;
        let n_ip_entries = unsafe { read_u32(fi.add(0x14)) } as usize;
        let disp_ip_to_state = unsafe { read_u32(fi.add(0x18)) } as usize;

        let pe_size = crate::seh::PE_SIZE.load(Ordering::Relaxed);
        // Sanity check counts to avoid spinning on corrupt data.
        if n_try_blocks > 64
            || n_ip_entries > 1024
            || disp_try_block >= pe_size
            || disp_ip_to_state >= pe_size
        {
            eprintln!(
            "weave: CxxFrameHandler: implausible FuncInfo fields \
             n_try={n_try_blocks} n_ip={n_ip_entries} tb_rva={disp_try_block:#x} ip_rva={disp_ip_to_state:#x} pe_size={pe_size:#x}"
        );
            return 1;
        }

        // Determine current EH state from the IP-to-state map.
        // Entries are sorted by IP RVA ascending; we want the last one ≤ control_pc_rva.
        let control_pc_rva = (dc_ref.control_pc as usize).wrapping_sub(image_base) as u32;
        let ip_map = (image_base + disp_ip_to_state) as *const u8;
        let mut eh_state: i32 = -1;
        for i in 0..n_ip_entries {
            let e = unsafe { ip_map.add(i * 8) };
            let ip_rva = unsafe { read_u32(e) };
            let state = unsafe { read_u32(e.add(4)) } as i32;
            if control_pc_rva >= ip_rva {
                eh_state = state;
            } else {
                break;
            }
        }

        eprintln!(
            "weave: CxxFrameHandler: control_pc_rva={control_pc_rva:#x} \
         eh_state={eh_state} funcinfo={:#x} establisher={establisher_frame:#x}",
            fi as usize,
        );

        // Walk TryBlockMap for a try range that covers eh_state.
        // TryBlockMapEntry (x64, 20 bytes):
        //   +0x00  tryLow          (i32)
        //   +0x04  tryHigh         (i32)
        //   +0x08  catchHigh       (i32)
        //   +0x0c  nCatches        (i32)
        //   +0x10  dispHandlerArray (u32) — RVA to HandlerType[]
        let try_map = (image_base + disp_try_block) as *const u8;

        for i in 0..n_try_blocks {
            let tb = unsafe { try_map.add(i * 20) };
            let try_low = unsafe { read_u32(tb) } as i32;
            let try_high = unsafe { read_u32(tb.add(4)) } as i32;
            let n_catches = unsafe { read_u32(tb.add(12)) } as usize;
            let disp_h = unsafe { read_u32(tb.add(16)) } as usize;

            if eh_state < try_low || eh_state > try_high {
                continue;
            }

            // Bounds-check before touching the handler array.
            if n_catches > 64 || disp_h == 0 || disp_h >= pe_size {
                eprintln!(
                    "weave: CxxFrameHandler: skip bad try block [{try_low},{try_high}] \
                 n_catches={n_catches} disp_h={disp_h:#x}"
                );
                continue;
            }

            eprintln!(
                "weave: CxxFrameHandler: try block [{try_low},{try_high}] matches \
             eh_state={eh_state}, {n_catches} catch(es)"
            );

            // HandlerType (x64, 20 bytes):
            //   +0x00  adjectives       (u32)
            //   +0x04  dispType         (u32) — RVA to type_info; 0 = catch-all
            //   +0x08  dispCatchObj     (u32) — frame-relative offset for caught object
            //   +0x0c  dispOfHandler    (u32) — RVA to catch funclet
            //   +0x10  dispFrame        (u32)
            let h_arr = (image_base + disp_h) as *const u8;

            for j in 0..n_catches {
                let h = unsafe { h_arr.add(j * 20) };
                let disp_type = unsafe { read_u32(h.add(4)) };
                let disp_catch_obj = unsafe { read_u32(h.add(8)) } as u64;
                let handler_rva = unsafe { read_u32(h.add(12)) } as usize;

                // Typed catch (disp_type != 0): match against the thrown type's hierarchy.
                // catch-all (disp_type == 0) always matches.
                if disp_type != 0 {
                    let matched = 'match_typed: {
                        // Exception parameters: [magic, thrown_obj, throw_info_va, image_base]
                        if exc.number_parameters < 3 {
                            break 'match_typed false;
                        }
                        let throw_info_va = exc.exception_information[2] as usize;
                        let throw_image_base = if exc.number_parameters >= 4 {
                            exc.exception_information[3] as usize
                        } else {
                            image_base
                        };

                        const CANONICAL_LIMIT: usize = 0x0000_8000_0000_0000;
                        if throw_info_va == 0 || throw_info_va >= CANONICAL_LIMIT {
                            break 'match_typed false;
                        }

                        let ti = throw_info_va as *const u8;
                        // ThrowInfo +0x0c = pCatchableTypeArray (u32 RVA from throw_image_base)
                        let cta_rva = unsafe { read_u32(ti.add(0x0c)) } as usize;
                        if cta_rva == 0 || cta_rva >= pe_size {
                            break 'match_typed false;
                        }

                        let cta = (throw_image_base + cta_rva) as *const u8;
                        let n_ct = unsafe { read_u32(cta) } as usize;

                        let mut found = false;
                        'types: for k in 0..n_ct.min(64) {
                            // CatchableTypeArray: u32 count, then u32 RVA entries
                            let ct_rva = unsafe { read_u32(cta.add(4 + k * 4)) } as usize;
                            if ct_rva == 0 || ct_rva >= pe_size {
                                continue;
                            }
                            let ct = (throw_image_base + ct_rva) as *const u8;
                            // CatchableType +0x04 = pType (u32 RVA → TypeDescriptor)
                            let thrown_td_rva = unsafe { read_u32(ct.add(4)) } as usize;

                            // Primary check: same TypeDescriptor RVA (same PE image)
                            if thrown_td_rva == disp_type as usize {
                                eprintln!(
                                "weave: CxxFrameHandler: typed match j={j} via RVA {disp_type:#x}"
                            );
                                found = true;
                                break 'types;
                            }

                            // Fallback: compare decorated type names (cross-module or ASLR)
                            if thrown_td_rva != 0
                                && thrown_td_rva < pe_size
                                && (disp_type as usize) < pe_size
                            {
                                // TypeDescriptor layout: +0x00 vtable (u64), +0x08 spare (u64),
                                // +0x10 decorated name (char[], null-terminated)
                                let thrown_name =
                                    (throw_image_base + thrown_td_rva + 0x10) as *const u8;
                                let handler_name =
                                    (image_base + disp_type as usize + 0x10) as *const u8;
                                let mut same = true;
                                for c in 0..256usize {
                                    let a = unsafe { *thrown_name.add(c) };
                                    let b = unsafe { *handler_name.add(c) };
                                    if a != b {
                                        same = false;
                                        break;
                                    }
                                    if a == 0 {
                                        break; // both null-terminated at same position
                                    }
                                }
                                if same {
                                    eprintln!(
                                        "weave: CxxFrameHandler: typed match j={j} via name \
                                     thrown_td={thrown_td_rva:#x} handler_td={disp_type:#x}"
                                    );
                                    found = true;
                                    break 'types;
                                }
                            }
                        }
                        found
                    };

                    if !matched {
                        eprintln!(
                        "weave: CxxFrameHandler: no match typed catch j={j} type_rva={disp_type:#x}"
                    );
                        continue;
                    }
                }

                let handler_va = image_base + handler_rva;

                // Exception object pointer: for _CxxThrowException, params[1] = thrown ptr.
                let exc_obj: u64 = if exc.number_parameters >= 2 {
                    exc.exception_information[1]
                } else {
                    0
                };

                // For typed catches, write the thrown exception object pointer into the
                // catching frame at the HandlerType.dispCatchObj frame-relative offset.
                // The catch funclet reads the object from [frame + dispCatchObj] via rbp.
                // For catch-all (dispCatchObj==0) there is nothing to store.
                if disp_type != 0 && disp_catch_obj != 0 {
                    let slot = (establisher_frame + disp_catch_obj) as *mut u64;
                    unsafe { slot.write_unaligned(exc_obj) };
                    eprintln!(
                        "weave: CxxFrameHandler: wrote exc_obj={exc_obj:#x} to \
                     frame[{disp_catch_obj:#x}]={:#x}",
                        slot as usize
                    );
                }

                let catch_kind = if disp_type == 0 { "catch-all" } else { "typed" };
                eprintln!(
                    "weave: CxxFrameHandler: calling {catch_kind} funclet j={j} at {handler_va:#x}"
                );

                // Call the catch funclet using the Win64 calling convention.
                // rcx = exception object (or address of caught obj slot),
                // rdx = establisher_frame (the catching function's frame pointer).
                // Returns: rax = continuation address (where to resume in the outer function).
                let handler_fn: unsafe extern "win64" fn(u64, u64) -> u64 =
                    unsafe { std::mem::transmute(handler_va) };
                let continuation = unsafe { handler_fn(exc_obj, establisher_frame) };

                eprintln!("weave: CxxFrameHandler: continuation={continuation:#x}");

                if continuation == 0 {
                    eprintln!("weave: CxxFrameHandler: null continuation — aborting");
                    unsafe { libc::abort() };
                }

                // Unwind the stack from the throw site to the catching frame,
                // calling any intermediate unwind handlers (finally blocks).
                // Then jump_to_context will transfer control to `continuation`
                // with the catching frame's register state.
                unsafe {
                    unwind_ex(establisher_frame, continuation, exc_record, 0, ctx);
                }
                // unwind_ex never returns.
            }
        }

        // No matching catch handler in this frame.
        1 // ExceptionContinueSearch
    }
} // mod x64

#[cfg(target_arch = "x86_64")]
pub use x64::*;
