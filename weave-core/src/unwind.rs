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
        // SAFETY: Context is #[repr(C, align(16))] with only integer and byte-array
        // fields. All-zero is a valid bit pattern for every field — no enums, no
        // references, no NonZero types. The Windows SDK treats a zeroed CONTEXT as
        // "uninitialized" which is the correct starting state before capture.
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
        // SAFETY: ExceptionRecord is #[repr(C)] with only integer and raw-pointer
        // fields. All-zero is a valid bit pattern — null pointers and zero integers
        // are legal starting values. Callers fill in exception_code and other fields
        // before use, so this serves purely as a zero-initialized blank slate.
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
        // SAFETY: Callers guarantee `p` points into either (a) the thread's committed
        // stack (RSP is always within the stack's committed region per OS invariant on
        // every call), or (b) a mapped PE section validated against PE_BASE+PE_SIZE.
        // read_unaligned avoids UB from misalignment — stack slots and unwind data
        // fields are not guaranteed 8-byte aligned.
        (p as *const u64).read_unaligned()
    }

    /// Read a u64 from any address via `/proc/self/mem`, returning `None` on
    /// unmapped pages instead of faulting.  Used in stack-scan fallback where
    /// the pointer may point to an address outside the committed stack range.
    ///
    /// Returns `Some(val)` if exactly 8 bytes were read; `None` on any error
    /// (unmapped page, EFAULT, short read, etc.).
    #[cfg(target_os = "linux")]
    unsafe fn read_u64_safe(addr: u64) -> Option<u64> {
        let mem_path = b"/proc/self/mem\0";
        let fd = libc::open(mem_path.as_ptr() as *const libc::c_char, libc::O_RDONLY);
        if fd < 0 {
            return None;
        }
        let mut val: u64 = 0;
        let n = libc::pread(
            fd,
            &mut val as *mut u64 as *mut libc::c_void,
            8,
            addr as i64,
        );
        libc::close(fd);
        if n == 8 {
            Some(val)
        } else {
            None
        }
    }

    /// Non-Linux fallback: direct read (no `/proc/self/mem` available, but
    /// stack scan faults are Linux-specific anyway).
    #[cfg(not(target_os = "linux"))]
    unsafe fn read_u64_safe(addr: u64) -> Option<u64> {
        let p = addr as *const u8;
        if p.is_null() {
            None
        } else {
            Some(read_u64(p))
        }
    }

    /// Read a u32 from a pointer (unaligned-safe).
    unsafe fn read_u32(p: *const u8) -> u32 {
        // SAFETY: `p` points into a mapped PE section (UNWIND_INFO, FuncInfo, or
        // TryBlockMap — all validated by the caller). UNWIND_CODE entries after
        // variable-length arrays have no guaranteed 4-byte alignment, so
        // read_unaligned is required to avoid UB.
        (p as *const u32).read_unaligned()
    }

    /// Read a u16 from a pointer (unaligned-safe).
    unsafe fn read_u16(p: *const u8) -> u16 {
        // SAFETY: `p` points into the UNWIND_CODE array in a mapped PE section.
        // UNWIND_CODE entries are 2 bytes each; callers compute `codes_base.add(i * 2)`
        // which is naturally 2-byte aligned relative to the codes_base address, but
        // codes_base itself may not be 2-byte aligned in the file, so read_unaligned
        // is used defensively.
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
            // SAFETY: `table` points to the start of the .pdata section (image_base +
            // pdata_rva, both validated non-zero above). `mid` is in [0, count) where
            // count = pdata_size / 12 and each RuntimeFunction is exactly 12 bytes
            // (#[repr(C)] with three u32 fields). The .pdata section is mapped read-only
            // by the PE loader and lives for the process lifetime.
            let entry = unsafe { &*table.add(mid) };
            if rva < entry.begin_address {
                hi = mid;
            } else if rva >= entry.end_address {
                lo = mid + 1;
            } else {
                // SAFETY: Same as above — `mid` is a valid index within the .pdata array.
                // Returning a raw pointer is safe because the caller holds no mutable
                // reference to this region and the PE mapping outlives any stack frame.
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
    /// Wine ref: dlls/ntdll/unwind.c — RtlVirtualUnwind2 (x86_64 version, line 2035)
    ///
    /// Key behavioral details from Wine:
    /// - `frame` (EstablisherFrame) is initialized to `context->Rsp` BEFORE any unwind
    ///   processing, and only updated by UWOP_SET_FPREG.
    /// - If `info->frame_reg` is set, `frame` is recomputed as
    ///   `get_int_reg(context, frame_reg) - frame_offset * 16` at the START of each
    ///   unwind info block (before processing codes).
    /// - UWOP_SAVE_NONVOL reads from `frame + offset`, NOT `context->Rsp + offset`.
    /// - Return address is popped AFTER all unwind codes (including chains).
    pub unsafe fn virtual_unwind(
        image_base: usize,
        _control_pc: u64,
        func: *const RuntimeFunction,
        ctx: &mut Context,
    ) -> UnwindResult {
        // SAFETY: `func` is a pointer into the .pdata section returned by
        // lookup_function_entry, which validated that the index is within the
        // PDATA_SIZE-bounded array. The PE mapping is read-only and lives for
        // the process lifetime, so the reference is valid for the duration of
        // this call.
        let rf = unsafe { &*func };
        let unwind_rva = rf.unwind_info_address;

        // Wine ref: `frame = *frame_ret = context->Rsp;` — initialized once before
        // any unwind processing. This is the EstablisherFrame.
        let mut frame: u64 = ctx.rsp;

        let mut info_ptr = (image_base + unwind_rva as usize) as *const u8;

        loop {
            // SAFETY: `info_ptr` = image_base + unwind_info_address (or a chained
            // successor). unwind_info_address is an RVA taken from a validated
            // .pdata entry. The first 4 bytes of UNWIND_INFO are always present for
            // any well-formed PE (version+flags u8, prolog_size u8, count_of_codes u8,
            // frame_reg_and_offset u8). The PE loader maps the whole image so any
            // in-bounds RVA is readable.
            let version_flags = unsafe { *info_ptr };
            let _version = version_flags & 0x07;
            let flags = (version_flags >> 3) & 0x1f;
            let _size_of_prolog = unsafe { *info_ptr.add(1) };
            let count_of_codes = unsafe { *info_ptr.add(2) } as usize;
            let frame_reg_and_offset = unsafe { *info_ptr.add(3) };
            let frame_register = frame_reg_and_offset & 0x0f;
            let frame_offset = (frame_reg_and_offset >> 4) & 0x0f;

            let codes_base = info_ptr.add(4);

            // Wine ref: if (info->frame_reg)
            //     frame = get_int_reg(context, info->frame_reg) - info->frame_offset * 16;
            if frame_register != 0 {
                frame = ctx_get_reg(ctx, frame_register).wrapping_sub((frame_offset as u64) * 16);
            }

            // Apply unwind codes to reverse the prolog.
            let mut i = 0usize;
            while i < count_of_codes {
                // SAFETY: `codes_base` = info_ptr + 4, within the .xdata section.
                // `i` is bounded by `count_of_codes` which was read from the
                // UNWIND_INFO header. Each UNWIND_CODE is 2 bytes; the total array
                // is count_of_codes * 2 bytes, guaranteed to fit in the mapped PE.
                // We do not validate count_of_codes against the section size here —
                // a corrupt PE could cause an out-of-bounds read; this is a known
                // limitation accepted in exchange for implementation simplicity.
                let code_ptr = unsafe { codes_base.add(i * 2) };
                let _code_offset = unsafe { *code_ptr };
                let op_and_info = unsafe { *code_ptr.add(1) };
                let unwind_op = op_and_info & 0x0f;
                let op_info = (op_and_info >> 4) & 0x0f;

                match unwind_op {
                    UWOP_PUSH_NONVOL => {
                        // SAFETY: UWOP_PUSH_NONVOL reverses a `push reg` prolog instruction.
                        // The Windows x64 ABI guarantees RSP is 8-byte aligned at any call
                        // boundary, and the UNWIND_INFO correctly accounts for every push
                        // in the prolog. ctx.rsp here points to the saved register value
                        // within the calling function's stack frame — part of the thread's
                        // committed stack, always readable.
                        let val = unsafe { read_u64(ctx.rsp as *const u8) };
                        ctx_set_reg(ctx, op_info, val);
                        ctx.rsp += 8;
                        i += 1;
                    }
                    UWOP_ALLOC_LARGE => {
                        if op_info == 0 {
                            // SAFETY: UWOP_ALLOC_LARGE with op_info==0 uses one extra
                            // UNWIND_CODE slot (i+1) holding the allocation size in 8-byte
                            // slots as a u16. `i+1 < count_of_codes` is guaranteed by the
                            // PE linker: a well-formed UNWIND_INFO never places a multi-slot
                            // code at the last slot. The read targets the .xdata section,
                            // same mapping invariant as the codes_base read above.
                            let slots = unsafe { read_u16(codes_base.add((i + 1) * 2)) } as u64;
                            ctx.rsp += slots * 8;
                            i += 2;
                        } else {
                            // SAFETY: op_info==1 uses two extra slots holding the raw byte
                            // count as a u32. Same mapping invariant as op_info==0 case.
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
                        // Wine ref: case UWOP_SET_FPREG:
                        //   context->Rsp = *frame_ret = frame;
                        // Restores RSP from the frame value and updates EstablisherFrame.
                        ctx.rsp = frame;
                        i += 1;
                    }
                    UWOP_SAVE_NONVOL => {
                        // Wine ref: off = frame + *(USHORT *)&info->opcodes[i+1] * 8;
                        // Reads relative to `frame`, NOT ctx.rsp.
                        let offset = unsafe { read_u16(codes_base.add((i + 1) * 2)) } as u64 * 8;
                        // SAFETY: UWOP_SAVE_NONVOL reverses a `mov [frame+N], reg` prolog
                        // instruction. `frame` is either the initial RSP value (which the
                        // OS guarantees points into the thread's committed stack) or the
                        // FP-register value from UWOP_SET_FPREG. `offset` is a scaled u16
                        // (max 65535*8 = ~512 KB), well within the stack's committed region
                        // for any normal thread stack. The save slot is part of the
                        // function's own frame, guaranteed present by the prolog.
                        let val = unsafe { read_u64((frame + offset) as *const u8) };
                        ctx_set_reg(ctx, op_info, val);
                        i += 2;
                    }
                    UWOP_SAVE_NONVOL_FAR => {
                        // Wine ref: off = frame + *(DWORD *)&info->opcodes[i+1];
                        let offset = unsafe { read_u32(codes_base.add((i + 1) * 2)) } as u64;
                        // SAFETY: Same as UWOP_SAVE_NONVOL but with a u32 offset (up to ~4 GB
                        // relative). In practice MSVC-generated code uses values within the
                        // thread stack's committed region. The address `frame + offset` must
                        // point to a valid save slot within this function's stack frame, as
                        // mandated by the Windows x64 ABI prolog/epilog contract.
                        let val = unsafe { read_u64((frame + offset) as *const u8) };
                        ctx_set_reg(ctx, op_info, val);
                        i += 3;
                    }
                    UWOP_SAVE_XMM128 => {
                        i += 2;
                    }
                    UWOP_SAVE_XMM128_FAR => {
                        i += 3;
                    }
                    UWOP_PUSH_MACHFRAME => {
                        if op_info == 1 {
                            ctx.rsp += 8; // skip error code pushed by hardware for some faults
                        }
                        // SAFETY: UWOP_PUSH_MACHFRAME reverses a hardware-pushed interrupt
                        // frame on the stack. The layout at RSP is (per Intel/AMD SDM and
                        // Windows kernel ABI): [RIP, CS, RFLAGS, RSP, SS] — 5 u64 slots.
                        // ctx.rsp points to this frame within the kernel-provided signal
                        // stack or a hardware exception frame, both committed and readable.
                        // We read RIP at rsp+0 and the saved RSP at rsp+24 (after skipping
                        // CS and RFLAGS).
                        ctx.rip = unsafe { read_u64(ctx.rsp as *const u8) };
                        ctx.rsp += 24;
                        ctx.rsp = unsafe { read_u64(ctx.rsp as *const u8) };
                        return UnwindResult {
                            handler: None,
                            handler_data: std::ptr::null(),
                            establisher_frame: frame,
                        };
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            // After processing codes, check for chained info
            if flags & UNW_FLAG_CHAININFO != 0 {
                // SAFETY: The Windows x64 ABI specifies that when UNW_FLAG_CHAININFO is
                // set, a RUNTIME_FUNCTION record immediately follows the UNWIND_CODE array
                // at the next 4-byte-aligned address. `after_codes` = codes_base +
                // count_of_codes*2 points one byte past the last UNWIND_CODE. The 4-byte
                // alignment rounds up to the next aligned address within the .xdata
                // section. The chained RUNTIME_FUNCTION (12 bytes) is within the mapped PE.
                let after_codes = unsafe { codes_base.add(count_of_codes * 2) };
                let aligned = ((after_codes as usize + 3) & !3) as *const u8;
                let chained_rf = aligned as *const RuntimeFunction;
                // SAFETY: `chained_rf` points to the chained RUNTIME_FUNCTION embedded at
                // the 4-byte-aligned address immediately after the UNWIND_CODE array —
                // mandated layout when UNW_FLAG_CHAININFO is set. The PE mapping covers
                // this region. We read only 12 bytes (three u32 fields of RuntimeFunction).
                let chained = unsafe { &*chained_rf };
                info_ptr = (image_base + chained.unwind_info_address as usize) as *const u8;
                continue;
            }

            // Pop return address — Wine does this AFTER all codes and chains.
            // SAFETY: After reversing all prolog operations, ctx.rsp points to the
            // return address slot on the caller's stack frame. The Windows x64 ABI
            // guarantees that at the moment of the CALL instruction RSP is 8-byte
            // aligned and the 8 bytes at RSP are the return address. The stack is
            // committed and readable throughout unwinding.
            ctx.rip = unsafe { read_u64(ctx.rsp as *const u8) };
            ctx.rsp += 8;

            // Extract handler if present
            let handler;
            let handler_data;
            if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
                // SAFETY: When EHANDLER or UHANDLER is set, the Windows x64 ABI places a
                // 4-byte handler RVA immediately after the UNWIND_CODE array at the next
                // 4-byte-aligned address. `aligned` is computed the same way as the
                // CHAININFO case — it is within the mapped PE .xdata section.
                let after_codes = unsafe { codes_base.add(count_of_codes * 2) };
                let aligned = ((after_codes as usize + 3) & !3) as *const u8;
                let handler_rva = unsafe { read_u32(aligned) } as usize;
                let handler_addr = image_base + handler_rva;
                // SAFETY: `handler_addr` is computed as `image_base + handler_rva`, where
                // `handler_rva` is the 32-bit RVA stored in the UNWIND_INFO exception-handler
                // slot (4 bytes immediately after the unwind codes, as specified by the
                // Microsoft x64 ABI).  The PE loader has already mapped the image into an
                // executable region, so `handler_addr` is a valid instruction address for a
                // function whose signature is `ExceptionHandlerFn` (four Win64-ABI arguments:
                // ExceptionRecord*, EstablisherFrame u64, ContextRecord*, DispatcherContext*,
                // returning i32).  Converting a `usize` VA to this fn-pointer type is the
                // standard pattern for invoking PE-resident exception handlers.
                handler =
                    Some(unsafe { std::mem::transmute::<usize, ExceptionHandlerFn>(handler_addr) });
                // SAFETY: `aligned.add(4)` points 4 bytes past the handler RVA, to the
                // start of the handler-data block (e.g. FuncInfo RVA for CxxFrameHandler).
                // This pointer is passed back to the caller as handler_data and will only
                // be dereferenced by the PE handler itself, which knows the layout.
                handler_data = unsafe { aligned.add(4) };
            } else {
                handler = None;
                handler_data = std::ptr::null();
            }

            return UnwindResult {
                handler,
                handler_data,
                establisher_frame: frame,
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
        // SAFETY: Both src (`ctx`) and dst (`dispatch_ctx`) are live &mut Context
        // references with #[repr(C, align(16))] layout and sizeof = 1232 bytes.
        // copy_nonoverlapping with count=1 copies exactly sizeof(Context) bytes.
        // The pointers cannot overlap because `ctx` is a caller-provided &mut and
        // `dispatch_ctx` is a local variable on this frame.
        unsafe {
            std::ptr::copy_nonoverlapping(
                ctx as *const Context,
                &mut dispatch_ctx as *mut Context,
                1,
            );
        }

        // Walk up to 256 frames to prevent infinite loops.
        //
        // scan_fallback_rsp tracks the RSP just before each call to virtual_unwind.
        // When virtual_unwind produces a non-PE RIP (e.g. UWOP_SET_FPREG uses
        // ctx.rbp which holds Weave's frame pointer rather than the PE caller's),
        // we recover by re-scanning upward from scan_fallback_rsp to find the next
        // genuine PE return address, skipping Weave stub frames.
        let mut scan_fallback_rsp: u64 = dispatch_ctx.rsp;
        for _frame_idx in 0..256 {
            let control_pc = dispatch_ctx.rip;

            // Check if we're still in PE code
            let pe_size = crate::seh::PE_SIZE.load(Ordering::Relaxed);
            let pc_usize = control_pc as usize;
            if pc_usize < image_base || pc_usize >= image_base + pe_size {
                // RIP left PE space.  Two causes:
                //   (a) virtual_unwind computed a wrong RSP via UWOP_SET_FPREG using
                //       Weave's own RBP instead of the PE caller's, then read a
                //       non-PE value as the next return address.
                //   (b) The legitimate call stack passes through a Weave stub frame.
                //
                // Recovery: scan upward from scan_fallback_rsp (RSP before the last
                // virtual_unwind) to find the next PE return address on the stack.
                let scan_limit = scan_fallback_rsp.saturating_add(64 * 1024);
                let mut found = false;
                let mut scan_ptr = scan_fallback_rsp;
                while scan_ptr < scan_limit {
                    // SAFETY: `scan_ptr` starts at scan_fallback_rsp (the RSP value
                    // before the last virtual_unwind call, which was either ctx.rsp
                    // at dispatch entry or dispatch_ctx.rsp after a previous unwind).
                    // Both are within the thread's committed stack. scan_limit caps the
                    // scan at 64 KB above scan_fallback_rsp — the Linux default thread
                    // stack is at least 512 KB, so this scan stays within committed
                    // pages. We advance in 8-byte steps matching the x64 ABI stack
                    // alignment invariant (RSP is always 8-byte aligned at call sites).
                    let candidate = match unsafe { read_u64_safe(scan_ptr) } {
                        Some(v) => v,
                        None => {
                            scan_ptr += 8;
                            continue;
                        }
                    };
                    if candidate > image_base as u64
                        && candidate < (image_base + pe_size) as u64
                        && lookup_function_entry(image_base, candidate).is_some()
                    {
                        dispatch_ctx.rip = candidate;
                        dispatch_ctx.rsp = scan_ptr + 8;
                        scan_fallback_rsp = scan_ptr + 8;
                        found = true;
                        break;
                    }
                    scan_ptr += 8;
                }
                if !found {
                    return false;
                }
                continue;
            }

            let func = match lookup_function_entry(image_base, control_pc) {
                Some(f) => f,
                None => {
                    // Leaf function (no .pdata entry): RSP points to return address
                    // SAFETY: A leaf function has no prolog and makes no stack allocation,
                    // so RSP at the point of the call still points to the return address.
                    // dispatch_ctx.rsp was validated to be within the PE range or derived
                    // from a prior unwind step; the return address slot is within the
                    // thread's committed stack.
                    dispatch_ctx.rip = unsafe { read_u64(dispatch_ctx.rsp as *const u8) };
                    dispatch_ctx.rsp += 8;
                    scan_fallback_rsp = dispatch_ctx.rsp;
                    continue;
                }
            };

            let _rva = (control_pc as usize - image_base) as u32;
            let mut frame_ctx = Default::default();
            // SAFETY: Both `dispatch_ctx` (local, initialized above) and `frame_ctx`
            // (local, just zeroed by Default) are valid, non-overlapping Context objects.
            // copy_nonoverlapping with count=1 copies sizeof(Context)=1232 bytes.
            // This snapshots dispatch_ctx before virtual_unwind mutates it, so we can
            // pass the pre-unwind state to the handler as the "context at this frame".
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &dispatch_ctx as *const Context,
                    &mut frame_ctx as *mut Context,
                    1,
                );
            }

            // Save RSP before virtual_unwind; used for re-scan if unwind goes off-track.
            scan_fallback_rsp = dispatch_ctx.rsp;
            // SAFETY: `func` is a valid .pdata pointer from lookup_function_entry.
            // `dispatch_ctx` has been validated to be within PE space (control_pc check
            // above). virtual_unwind's safety contract requires a valid RuntimeFunction
            // pointer, valid image_base, and a mutable Context — all satisfied here.
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

                // Call the language-specific handler in search mode
                // SAFETY: `handler` is an `ExceptionHandlerFn` obtained from the PE's
                // UNWIND_INFO via the transmute in virtual_unwind — it is a PE-compiled
                // function using `extern "win64"`. The Windows x64 ABI contract for
                // language-specific handlers (per MSDN RtlVirtualUnwind docs) requires
                // exactly these four arguments: (ExceptionRecord*, EstablisherFrame u64,
                // ContextRecord*, DispatcherContext*). All pointers are valid: exc_record
                // is the caller's &mut ExceptionRecord, establisher_frame is the RSP-
                // derived frame value, ctx is the original throw-site Context, and dc is
                // the DispatcherContext just initialized above.
                let disposition =
                    unsafe { handler(exc_record, result.establisher_frame, ctx, &mut dc) };

                match disposition {
                    // ExceptionContinueSearch (1) — not handled, keep walking
                    1 => {}
                    // ExceptionContinueExecution (0) — exception resolved, resume
                    0 => {
                        return true;
                    }
                    _ => {
                        // ExceptionNestedException (2), ExceptionCollidedUnwind (3), etc.
                    }
                }
            }
            // No handler or handler said continue search — keep walking
        }

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
        // SAFETY: `exc_record` is a valid *mut ExceptionRecord per the function's
        // safety contract (caller is cxx_frame_handler or rtl_unwind_ex_export,
        // both of which receive it from the PE's own exception dispatch machinery).
        let exc = unsafe { &mut *exc_record };
        exc.exception_flags |= EXCEPTION_UNWINDING;

        // Capture current context for stack walking
        let mut walk_ctx: Context = Default::default();
        // SAFETY: `original_ctx` is a valid *mut Context (same safety contract).
        // walk_ctx is a local, zeroed Context on this frame. count=1 copies exactly
        // sizeof(Context) bytes. No aliasing: original_ctx comes from the caller's
        // dispatch chain and walk_ctx is a fresh local.
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
                    // SAFETY: Leaf function in PE code: no prolog, so RSP still points to
                    // the return address pushed by the CALL instruction. walk_ctx.rsp
                    // was inherited from original_ctx (throw-site RSP) and advanced by
                    // each virtual_unwind call, always remaining within the committed stack.
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

            // SAFETY: `func` is a valid .pdata pointer, walk_ctx is within PE space
            // (checked above). See dispatch_exception for full virtual_unwind contract.
            let result = unsafe { virtual_unwind(image_base, control_pc, func, &mut walk_ctx) };

            // Check if we've reached the target frame
            if result.establisher_frame == target_frame {
                // We're at the target — restore the catching frame's live register state.
                // SAFETY: `original_ctx` is a valid *mut Context per the function's
                // safety contract. We write only the nonvolatile registers and RSP/RIP/RAX
                // fields, then pass the pointer to jump_to_context which reads from it
                // via inline asm. The Context remains valid for the lifetime of this call
                // (we haven't returned yet).
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

                // SAFETY: Calling unwind handler during unwind phase. Same ABI contract
                // as the search-phase call in dispatch_exception: extern "win64" function
                // pointer from PE code, four arguments per the Windows EXCEPTION_ROUTINE
                // prototype. During unwind phase (EXCEPTION_UNWINDING set) the handler is
                // expected to run finally blocks and return ExceptionContinueSearch — it
                // must not modify exc_record->ExceptionFlags in an incompatible way.
                // original_ctx is valid (caller's contract); dc is freshly initialized above.
                unsafe {
                    handler(exc_record, result.establisher_frame, original_ctx, &mut dc);
                }

                exc.exception_flags = saved_flags | EXCEPTION_UNWINDING;
            }
        }

        // If we couldn't reach the target, fatal error
        eprintln!("weave: SEH unwind failed to reach target frame={target_frame:#x}");
        // SAFETY: libc::exit is safe to call at any time and terminates the process.
        // This is an unrecoverable state — the unwind machinery failed to find the
        // target frame, indicating a corrupt or mismatched stack.
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
        //
        // SAFETY: This inline asm performs a non-returning register-restore + jmp,
        // equivalent to Windows RtlRestoreContext. The contract:
        //
        // 1. Field offsets: the hard-coded hex offsets are the byte offsets within the
        //    Windows x64 CONTEXT structure (verified against the static_assert on
        //    sizeof=1232 and the #[repr(C, align(16))] layout above). Specifically:
        //    rax=+0x78, rcx=+0x80, rdx=+0x88, rbx=+0x90, rsp=+0x98, rbp=+0xa0,
        //    rsi=+0xa8, rdi=+0xb0, r11=+0xd0, r12=+0xd8, ..., r15=+0xf0, rip=+0xf8.
        //
        // 2. RDI carries `ctx` into the asm block as input ("rdi" constraint). The asm
        //    reads all other registers from ctx before finally overwriting RDI from
        //    ctx.rdi at offset +0xb0. This ordering is required because RDI is the
        //    pointer — it must be consumed last.
        //
        // 3. RSP is loaded from ctx.rsp (+0x98) and then immediately used by `jmp r11`.
        //    ctx.rsp was set by unwind_ex to the catching frame's inside-function RSP
        //    (pre_rsp), which the Windows x64 ABI guarantees is 16-byte aligned at the
        //    point of the `call` into the catch funclet. The target stack is committed.
        //
        // 4. `jmp r11` transfers control to ctx.rip (the catch funclet continuation
        //    address returned by the catch funclet). This is equivalent to a longjmp
        //    into the catching function's frame.
        //
        // 5. `options(noreturn)` is correct — control never returns to this Rust frame.
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
            // SAFETY: `arguments` points to `num_args` valid u64 values (function
            // safety contract). `i < number_parameters ≤ min(num_args, 15)`.
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
        // SAFETY: `mov {}, rsp` reads the stack pointer register directly. RSP is
        // always defined and valid on x86_64 (it points to the current stack frame).
        // `options(nomem, nostack)` tells LLVM the asm does not access memory or
        // modify the stack, preventing the compiler from spilling/reloading around it.
        // We only need RSP to begin the stack scan; no memory is written.
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
        // SAFETY: Each `mov {}, reg` reads a single general-purpose register into a
        // local variable. Reading registers is always safe; `nomem, nostack` prevents
        // LLVM from inserting memory operations between the reads that could clobber
        // the values. These captures are "best-effort" — they approximate the nonvolatile
        // register state at the PE throw site, since those registers are callee-saved
        // and won't have been modified by Weave's internal call frames between the
        // throw and here (Weave saves/restores them per the System V AMD64 ABI).
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
            // SAFETY: `addr` starts at cur_rsp (the actual RSP captured from the
            // hardware register above, 8-byte aligned) and advances in 8-byte steps.
            // The 64 KB limit prevents reading past the stack's committed region —
            // Linux stacks grow down and are at least 64 KB committed by default, with
            // a guard page below. The scan stays within the upper (already committed)
            // portion of the stack and will not hit the guard page.
            let candidate = unsafe { *(addr as *const u64) };
            if pe_base > 0 && candidate > pe_base && candidate < pe_base + pe_size {
                let has_pdata = lookup_function_entry(pe_base as usize, candidate).is_some();
                // Only accept if this is within a function that has .pdata coverage.
                // This rejects PE data values (image_base, ThrowInfo pointers, etc.)
                // which happen to lie in the PE address range but aren't code addresses.
                if has_pdata {
                    caller_rip = candidate;
                    caller_rsp = addr + 8;
                    break;
                }
            }
        }

        if caller_rip == 0 {
            eprintln!("weave: RaiseException {exception_code:#x} — no PE return address on stack");
            // SAFETY: abort() is always safe to call and terminates the process immediately.
            // No PE return address was found — this is an unrecoverable situation.
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

        // For MSVC C++ exceptions (0xe06d7363): params are [magic, obj_ptr, throwinfo_rva, imgbase]
        // params[2] is the ThrowInfo RVA relative to params[3] (the image base).
        // Logging the RVA helps identify the exception type in the PE.
        if exception_code == 0xe06d7363 && exc_record.number_parameters >= 4 {
            let p = &exc_record.exception_information;
            let throwinfo_rva = p[2].wrapping_sub(p[3]);
            eprintln!(
                "weave: C++ throw at rip={caller_rip:#x}: obj={:#x} throwinfo_rva={throwinfo_rva:#x}",
                p[1]
            );
        } else {
            eprintln!("weave: RaiseException: code={exception_code:#x} at rip={caller_rip:#x}");
        }

        // SAFETY: exc_record is fully initialized above; ctx has rip/rsp set from the
        // stack scan and nonvolatile registers captured from hardware. Both are valid
        // for the duration of this call. dispatch_exception's contract is satisfied.
        let handled = unsafe { dispatch_exception(&mut exc_record, &mut ctx) };
        if !handled {
            eprintln!("weave: unhandled exception {exception_code:#x}");
            // SAFETY: abort() terminates the process; no cleanup needed for unhandled exceptions.
            unsafe { libc::abort() };
        }
    }

    /// Raise a Windows exception with an EXACT throw-site context.
    ///
    /// Unlike `raise_exception` (which scans the stack to guess the throw site),
    /// this function takes the RIP and RSP captured by the naked
    /// `ucrt_cxx_throw_exception` trampoline before any prolog ran. This avoids
    /// the false-positive problem that occurs when PE addresses stored in Weave's
    /// own stack frames are mistaken for the actual return address.
    ///
    /// `throw_rip` — return address from the NPP `call _CxxThrowException` instruction.
    /// `throw_rsp` — NPP's RSP at the point of the CALL (= RSP+8 at naked-fn entry).
    ///
    /// # Safety
    /// `arguments` must point to `num_args` valid u64 values. `throw_rip` and
    /// `throw_rsp` must be valid values captured by the naked trampoline.
    pub unsafe fn raise_exception_at(
        exception_code: u32,
        exception_flags: u32,
        num_args: u32,
        arguments: *const u64,
        throw_rip: u64,
        throw_rsp: u64,
    ) {
        let mut exc_record = ExceptionRecord {
            exception_code,
            exception_flags,
            exception_record: std::ptr::null_mut(),
            exception_address: throw_rip as *mut u8,
            number_parameters: num_args.min(EXCEPTION_MAXIMUM_PARAMETERS as u32),
            ..Default::default()
        };
        for i in 0..exc_record.number_parameters as usize {
            // SAFETY: `arguments` points to `num_args` valid u64 values (function
            // safety contract). `i < number_parameters ≤ min(num_args, 15)`.
            exc_record.exception_information[i] = unsafe { *arguments.add(i) };
        }

        let mut ctx = Context {
            rip: throw_rip,
            rsp: throw_rsp,
            ..Context::default()
        };

        // Capture Weave's current non-volatile registers as a best-effort
        // approximation. virtual_unwind reads saved registers from the stack
        // (not from ctx), so these values only matter for UWOP_SET_FPREG
        // (which we skip) and the establisher-frame computation.
        let rbx_val: u64;
        let rbp_val: u64;
        let rdi_val: u64;
        let rsi_val: u64;
        let r12_val: u64;
        let r13_val: u64;
        let r14_val: u64;
        let r15_val: u64;
        // SAFETY: Same contract as the equivalent block in raise_exception — reading
        // callee-saved registers via inline asm. throw_rip/throw_rsp were captured
        // by the naked trampoline BEFORE any prolog, so the nonvolatile registers
        // still hold the PE caller's values (they haven't been clobbered by a prolog).
        // This makes the register captures more accurate than in raise_exception.
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
        ctx.rbx = rbx_val;
        ctx.rbp = rbp_val;
        ctx.rdi = rdi_val;
        ctx.rsi = rsi_val;
        ctx.r12 = r12_val;
        ctx.r13 = r13_val;
        ctx.r14 = r14_val;
        ctx.r15 = r15_val;
        ctx.context_flags = 0x10001f; // CONTEXT_ALL

        // SAFETY: exc_record and ctx are fully initialized above. dispatch_exception's
        // contract: exc_record is a valid ExceptionRecord, ctx represents the throw-site
        // register state (rip/rsp exact from the naked trampoline, nonvolatiles captured).
        // Log the thrown type name for C++ exceptions before dispatch.
        if exception_code == 0xE06D7363 && exc_record.number_parameters >= 3 {
            let ti_ptr = exc_record.exception_information[2] as usize;
            let ib = if exc_record.number_parameters >= 4 {
                exc_record.exception_information[3] as usize
            } else {
                crate::seh::PE_BASE.load(Ordering::Relaxed)
            };
            let pe_sz = crate::seh::PE_SIZE.load(Ordering::Relaxed);
            if ti_ptr != 0 && ib != 0 {
                unsafe {
                    let cta_rva = read_u32((ti_ptr as *const u8).add(0x0c)) as usize;
                    if cta_rva != 0 && cta_rva < pe_sz {
                        let cta = (ib + cta_rva) as *const u8;
                        let n_ct = read_u32(cta) as usize;
                        if n_ct > 0 {
                            let ct_rva = read_u32(cta.add(4)) as usize;
                            if ct_rva != 0 && ct_rva < pe_sz {
                                let ct = (ib + ct_rva) as *const u8;
                                let td_rva = read_u32(ct.add(4)) as usize;
                                if td_rva != 0 && td_rva < pe_sz {
                                    let td = (ib + td_rva) as *const u8;
                                    let name_ptr = td.add(0x10) as *const i8;
                                    if !name_ptr.is_null() {
                                        if let Ok(s) = core::ffi::CStr::from_ptr(name_ptr).to_str()
                                        {
                                            eprintln!(
                                                "weave: C++ exception type='{s}' at rip={:#x}",
                                                throw_rip
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let handled = unsafe { dispatch_exception(&mut exc_record, &mut ctx) };
        if !handled {
            eprintln!("weave: unhandled exception {exception_code:#x}");
            // Try the registered UnhandledExceptionFilter before aborting.
            let uef = crate::seh::UEF_HANDLER.load(Ordering::Relaxed);
            if uef != 0 {
                eprintln!("weave: calling UnhandledExceptionFilter handler");
                // Build a minimal EXCEPTION_POINTERS-like struct on the stack:
                // [0] = &exc_record, [1] = &ctx (as ExceptionRecord* and ContextRecord*)
                let pointers: [*mut std::ffi::c_void; 2] = [
                    &mut exc_record as *mut _ as *mut std::ffi::c_void,
                    &mut ctx as *mut _ as *mut std::ffi::c_void,
                ];
                let f: unsafe extern "win64" fn(*mut u8) -> i32 =
                    unsafe { std::mem::transmute(uef) };
                let result = unsafe { f(pointers.as_ptr() as *mut u8) };
                eprintln!("weave: UnhandledExceptionFilter returned {result}");
            }
            // SAFETY: abort() terminates the process; no cleanup needed for unhandled exceptions.
            unsafe { libc::abort() };
        }
    }

    // ── Hardware exception dispatch (SIGSEGV → SEH) ────────────────────────────

    /// Dispatch a hardware exception (e.g. SIGSEGV → STATUS_ACCESS_VIOLATION)
    /// through the SEH mechanism. Called from the signal handler.
    ///
    /// Returns `true` if a handler was found and the ucontext was updated
    /// (the signal handler should return normally to resume at the new RIP).
    /// Returns `false` if no handler was found (caller should fall through to
    /// the crash report).
    ///
    /// Wine ref: dlls/ntdll/signal_x86_64.c — setup_exception / call_vectored_handlers
    /// On Windows, the kernel delivers hardware exceptions through
    /// KiUserExceptionDispatcher which calls RtlDispatchException. We do the
    /// same from the Linux signal handler.
    ///
    /// # Safety
    /// `uctx` must be a valid ucontext_t from a signal handler.
    #[cfg(target_os = "linux")]
    pub unsafe fn dispatch_hardware_exception(
        exception_code: u32,
        fault_addr: usize,
        uctx: *mut libc::ucontext_t,
    ) -> bool {
        // SAFETY: `uctx` is a valid *mut libc::ucontext_t provided by the Linux kernel
        // signal delivery machinery (SA_SIGINFO signal handler third argument). The
        // kernel fills in uc_mcontext.gregs with the interrupted thread's full register
        // state before calling the signal handler, and the struct is valid for the
        // lifetime of the signal handler call. We take a mutable reference so we can
        // write back a modified RIP if a handler resumes execution (ContinueExecution).
        let gregs = unsafe { &mut (*uctx).uc_mcontext.gregs };

        // Build EXCEPTION_RECORD
        let mut exc_record = ExceptionRecord {
            exception_code,
            exception_flags: 0, // continuable
            exception_record: std::ptr::null_mut(),
            exception_address: gregs[libc::REG_RIP as usize] as *mut u8,
            number_parameters: 2,
            ..Default::default()
        };
        // STATUS_ACCESS_VIOLATION has 2 params: [0]=read(0)/write(1), [1]=fault address
        exc_record.exception_information[0] = 0; // read (we don't distinguish read/write here)
        exc_record.exception_information[1] = fault_addr as u64;

        // Build Context from ucontext
        let mut ctx = Context {
            rax: gregs[libc::REG_RAX as usize] as u64,
            rcx: gregs[libc::REG_RCX as usize] as u64,
            rdx: gregs[libc::REG_RDX as usize] as u64,
            rbx: gregs[libc::REG_RBX as usize] as u64,
            rsp: gregs[libc::REG_RSP as usize] as u64,
            rbp: gregs[libc::REG_RBP as usize] as u64,
            rsi: gregs[libc::REG_RSI as usize] as u64,
            rdi: gregs[libc::REG_RDI as usize] as u64,
            r8: gregs[libc::REG_R8 as usize] as u64,
            r9: gregs[libc::REG_R9 as usize] as u64,
            r10: gregs[libc::REG_R10 as usize] as u64,
            r11: gregs[libc::REG_R11 as usize] as u64,
            r12: gregs[libc::REG_R12 as usize] as u64,
            r13: gregs[libc::REG_R13 as usize] as u64,
            r14: gregs[libc::REG_R14 as usize] as u64,
            r15: gregs[libc::REG_R15 as usize] as u64,
            rip: gregs[libc::REG_RIP as usize] as u64,
            context_flags: 0x10001f, // CONTEXT_ALL
            ..Context::default()
        };

        // SAFETY: exc_record is initialized above with the hardware exception parameters.
        // ctx is built directly from the kernel-provided gregs array — it exactly
        // represents the faulting thread's register state. dispatch_exception's contract:
        // both must be valid for the duration of the call. The faulting thread is
        // suspended in the signal handler, so the stack it describes is stable.
        let handled = unsafe { dispatch_exception(&mut exc_record, &mut ctx) };
        if handled {
            // dispatch_exception + unwind_ex already transferred control
            // (unwind_ex does a longjmp-like context switch). If we get here,
            // it means the handler returned ExceptionContinueExecution (0),
            // which means "resume at the modified context." Update ucontext.
            //
            // Note: in practice, for ACCESS_VIOLATION this path is rare —
            // most handlers will unwind. But we handle it for completeness.
            gregs[libc::REG_RAX as usize] = ctx.rax as i64;
            gregs[libc::REG_RCX as usize] = ctx.rcx as i64;
            gregs[libc::REG_RDX as usize] = ctx.rdx as i64;
            gregs[libc::REG_RBX as usize] = ctx.rbx as i64;
            gregs[libc::REG_RSP as usize] = ctx.rsp as i64;
            gregs[libc::REG_RBP as usize] = ctx.rbp as i64;
            gregs[libc::REG_RSI as usize] = ctx.rsi as i64;
            gregs[libc::REG_RDI as usize] = ctx.rdi as i64;
            gregs[libc::REG_R8 as usize] = ctx.r8 as i64;
            gregs[libc::REG_R9 as usize] = ctx.r9 as i64;
            gregs[libc::REG_R10 as usize] = ctx.r10 as i64;
            gregs[libc::REG_R11 as usize] = ctx.r11 as i64;
            gregs[libc::REG_R12 as usize] = ctx.r12 as i64;
            gregs[libc::REG_R13 as usize] = ctx.r13 as i64;
            gregs[libc::REG_R14 as usize] = ctx.r14 as i64;
            gregs[libc::REG_R15 as usize] = ctx.r15 as i64;
            gregs[libc::REG_RIP as usize] = ctx.rip as i64;
            true
        } else {
            false
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
        let (exc_code, exc_addr) = if exception_record.is_null() {
            (0u32, 0usize)
        } else {
            // SAFETY: Non-null exception_record pointer validated just above; caller's
            // safety contract (all pointers must be valid). The ExceptionRecord is owned
            // by the PE's exception dispatch machinery and lives for the unwind duration.
            let r = unsafe { &*exception_record };
            (r.exception_code, r.exception_address as usize)
        };
        eprintln!(
            "weave: RtlUnwindEx: target_frame={:#x} target_ip={:#x} exc_code={exc_code:#x} exc_addr={exc_addr:#x}",
            target_frame as usize, target_ip as usize
        );

        // SAFETY: Called from PE code via the Win64 ABI (this function is exported as
        // RtlUnwindEx). target_frame is the EstablisherFrame of the catching frame —
        // a valid stack address. target_ip is the continuation address returned by the
        // catch funclet. exception_record and context_record are the original pointers
        // from the search phase. unwind_ex's contract is satisfied by the export's
        // own safety contract (all pointer arguments must be valid).
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
        eprintln!("weave/unwind: RtlVirtualUnwind ip=0x{control_pc:x} base=0x{image_base:x} type={handler_type}");
        let _ = handler_type;
        // SAFETY: `context_record` is non-null per caller's safety contract (exported as
        // RtlVirtualUnwind; callers are PE-compiled CRT or user code). The Context must
        // represent the frame to unwind. virtual_unwind modifies it in-place.
        let ctx = unsafe { &mut *context_record };
        // SAFETY: function_entry is a valid *const RuntimeFunction per caller's contract.
        // image_base and control_pc are consistent values passed by the PE CRT.
        let result =
            unsafe { virtual_unwind(image_base as usize, control_pc, function_entry, ctx) };

        if !handler_data.is_null() {
            // SAFETY: handler_data is a non-null writable pointer per caller's contract.
            unsafe { *handler_data = result.handler_data };
        }
        if !establisher_frame.is_null() {
            // SAFETY: establisher_frame is a non-null writable pointer per caller's contract.
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
            // SAFETY: `image_base_out` is non-null and writable per the function's
            // safety contract (exported as RtlLookupFunctionEntry; PE CRT passes a
            // valid u64-aligned stack variable to receive the image base).
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
            // SAFETY: `context_record` is non-null and points to a writable Context-
            // sized buffer per the function's safety contract (exported as
            // RtlCaptureContext; PE code passes a stack-allocated Context).
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
        // SAFETY: exc_record and dc are provided by the Weave dispatch loop
        // (dispatch_exception calls handler(exc_record, ..., ctx, &mut dc)). Both
        // pointers are non-null and valid — exc_record is the throw-site ExceptionRecord,
        // dc is the DispatcherContext built on the dispatch loop's stack frame.
        let exc = unsafe { &*exc_record };
        let dc_ref = unsafe { &*dc };
        let mut matched_first = false;

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
        // SAFETY: handler_data is non-null (checked above) and points to the handler-data
        // block immediately after the handler RVA in .xdata — specifically, a u32 RVA
        // to the FuncInfo structure. This pointer was produced by virtual_unwind's
        // `aligned.add(4)` and is within the mapped PE section.
        let funcinfo_rva = unsafe { read_u32(handler_data) } as usize;
        let fi = (image_base + funcinfo_rva) as *const u8;

        // Validate FuncInfo magic.
        // SAFETY: `fi` = image_base + funcinfo_rva points into the PE's .rdata section.
        // funcinfo_rva was just read from the validated handler-data block. A valid PE
        // places FuncInfo within the image bounds; we check the magic word immediately
        // after to detect corrupt data.
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
                // SAFETY: `fi` is a validated FuncInfo pointer (magic checked above).
                // Reading 8 consecutive u32 values (32 bytes) covers the full FuncInfo
                // fixed header, which is always ≥ 0x24 bytes for x64 image-relative
                // format. The PE mapping makes all in-bounds addresses readable.
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

        // SAFETY: `fi` points to a valid FuncInfo structure in the PE (magic validated
        // above). The FuncInfo layout is documented by the MSVC EH ABI: a fixed header
        // of at least 0x24 bytes for x64 image-relative format. The offsets 0x0c, 0x10,
        // 0x14, 0x18 are within the fixed header. The PE mapping guarantees these
        // bytes are readable.
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
        // ip_map points to the IpToStateMapEntry array in the PE image.
        // disp_ip_to_state was bounds-checked against pe_size above.
        let ip_map = (image_base + disp_ip_to_state) as *const u8;
        let mut eh_state: i32 = -1;
        for i in 0..n_ip_entries {
            // SAFETY: `ip_map` points to the IpToStateMap array validated above.
            // Each entry is 8 bytes (u32 ip_rva + u32 state). `i < n_ip_entries ≤ 1024`
            // (sanity-checked above). The array is within the PE mapping. read_u32 is
            // unaligned-safe, handling any alignment the linker chose for the array.
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
            // SAFETY: `try_map` = image_base + disp_try_block, validated against pe_size
            // above. Each TryBlockMapEntry is 20 bytes; `i < n_try_blocks ≤ 64`
            // (sanity-checked). Fields at offsets 0, 4, 12, 16 are within the 20-byte
            // entry. The PE mapping covers this region.
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
                // SAFETY: `h_arr` = image_base + disp_h; disp_h was bounds-checked
                // against pe_size above. Each HandlerType is 20 bytes; `j < n_catches ≤ 64`.
                // Fields at offsets 4, 8, 12 are within the entry. PE mapping covers this.
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
                        // SAFETY: throw_info_va was validated to be non-zero and below the
                        // canonical address limit (0x8000_0000_0000), placing it in user
                        // space. This is the VA stored in exception_information[2] by
                        // _CxxThrowException — it points to the ThrowInfo struct in the PE's
                        // .rdata section. Offset 0x0c is within the fixed ThrowInfo header
                        // (which is ≥ 0x10 bytes per the MSVC EH ABI). The PE mapping makes
                        // all in-bounds RVAs readable.
                        let cta_rva = unsafe { read_u32(ti.add(0x0c)) } as usize;
                        if cta_rva == 0 || cta_rva >= pe_size {
                            break 'match_typed false;
                        }

                        let cta = (throw_image_base + cta_rva) as *const u8;
                        // SAFETY: cta_rva was bounds-checked against pe_size above.
                        // `cta` = throw_image_base + cta_rva points to the
                        // CatchableTypeArray in .rdata. The first u32 is the element count.
                        let n_ct = unsafe { read_u32(cta) } as usize;

                        let mut found = false;
                        'types: for k in 0..n_ct.min(64) {
                            // CatchableTypeArray: u32 count, then u32 RVA entries
                            // SAFETY: `cta.add(4 + k * 4)` accesses the k-th RVA entry
                            // after the count word. k is capped at 63. The array is in the
                            // PE's .rdata section; the PE mapping makes it readable.
                            let ct_rva = unsafe { read_u32(cta.add(4 + k * 4)) } as usize;
                            if ct_rva == 0 || ct_rva >= pe_size {
                                continue;
                            }
                            let ct = (throw_image_base + ct_rva) as *const u8;
                            // CatchableType +0x04 = pType (u32 RVA → TypeDescriptor)
                            // SAFETY: ct = throw_image_base + ct_rva; ct_rva was bounds-
                            // checked against pe_size. CatchableType offset 0x04 is within
                            // the fixed header (≥ 0x08 bytes per the MSVC EH ABI).
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
                                // SAFETY: Both thrown_td_rva and disp_type are <pe_size
                                // (checked by the enclosing if). The TypeDescriptor name
                                // starts at offset 0x10 within the struct. We scan up to
                                // 256 bytes looking for a null terminator — MSVC decorated
                                // names (mangled C++ type names) are always null-terminated
                                // and well within 256 bytes. Both pointers are in mapped PE
                                // .rdata sections and are readable.
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
                    // SAFETY: `slot` = establisher_frame + disp_catch_obj is a frame-
                    // relative offset into the catching function's stack frame. establisher_frame
                    // is the RSP value at the entry of the catching function (computed by
                    // virtual_unwind from the .pdata entry). disp_catch_obj is the offset to
                    // the local variable slot where the caught object should be copied, as
                    // encoded in the HandlerType by the MSVC compiler. The catching function's
                    // entire frame is committed stack memory, so the write is safe. We use
                    // write_unaligned to handle any alignment the compiler chose for the slot.
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
                // SAFETY: `handler_va` is the virtual address of a C++ catch funclet embedded
                // in the PE image, extracted from the FuncInfo4 HandlerType table at the index
                // selected by the type-match loop above.  The Microsoft C++ ABI specifies that
                // catch funclets take (rcx=exception_object_ptr, rdx=establisher_frame) and
                // return the continuation RIP in rax — matching the `fn(u64, u64) -> u64`
                // signature declared here with `extern "win64"`.  The address has been verified
                // to be non-zero by the surrounding `if handler_va != 0` guard, and it lies
                // within the loaded image because it was decoded from a PE-relative offset.
                let handler_fn: unsafe extern "win64" fn(u64, u64) -> u64 =
                    unsafe { std::mem::transmute(handler_va) };
                // SAFETY: handler_fn is a valid Win64 function pointer materialized
                // above. exc_obj and establisher_frame are valid u64 values. The funclet
                // runs within the catching function's stack frame (establisher_frame is
                // its RSP), which is committed and writable.
                let continuation = unsafe { handler_fn(exc_obj, establisher_frame) };

                eprintln!("weave: CxxFrameHandler: continuation={continuation:#x}");

                if continuation == 0 {
                    eprintln!("weave: CxxFrameHandler: null continuation — aborting");
                    // SAFETY: abort() is always safe; null continuation is a fatal
                    // state indicating a corrupt PE or a compiler-generated funclet
                    // that violated the EH ABI contract.
                    unsafe { libc::abort() };
                }

                // Unwind the stack from the throw site to the catching frame,
                // calling any intermediate unwind handlers (finally blocks).
                // Then jump_to_context will transfer control to `continuation`
                // with the catching frame's register state.
                // SAFETY: establisher_frame is the validated target frame (RSP of the
                // catching function). continuation is a non-zero VA in the PE returned
                // by the catch funclet. exc_record and ctx are valid (checked at
                // function entry). unwind_ex's contract is satisfied.
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
