//! WINSPOOL.DRV stubs for Weave — printer spooler API.
//!
//! SumatraPDF and other apps import WINSPOOL.DRV to enumerate printers and
//! open print dialogs. Weave has no printer spooler, so all functions return
//! "no printer available" sentinels without touching any system state.
//!
//! All stubs are Phase A: they return the correct failure sentinel but perform
//! no real work. A future milestone can wire up CUPS integration.
//!
//! Wine ref source: dlls/winspool.drv/info.c

// Wine ref: dlls/winspool.drv/info.c — OpenPrinterW allocates an opened_printer_t entry
// keyed by printer name; returns FALSE + ERROR_INVALID_PRINTER_NAME when the named
// printer is not found in the registry. Since Weave has no printer registry, FALSE is
// always the correct return with a non-null phPrinter left unchanged (not written).
/// OpenPrinterW — open a connection to a printer or print server.
///
/// Returns FALSE (no printer available). `ph_printer` is not written.
///
/// # Safety
/// `pp_printer_name` and `p_default` are ignored. `ph_printer` must be
/// null or a valid writable pointer to a usize.
// stub: Phase A — no spooler; always returns FALSE (ERROR_INVALID_PRINTER_NAME).
pub unsafe extern "win64" fn open_printer_w(
    _pp_printer_name: *const u16,
    _ph_printer: *mut usize,
    _p_default: *const u8,
) -> i32 {
    // ERROR_INVALID_PRINTER_NAME = 1801 (0x709)
    weave_common::set_last_error(0x709);
    0 // FALSE
}

// Wine ref: dlls/winspool.drv/info.c — ClosePrinter validates the handle via get_opened_printer;
// returns TRUE on success, FALSE + ERROR_INVALID_HANDLE if the handle is not found.
// Since we never issue valid handles, returning TRUE is the correct "already closed" sentinel
// (matches Wine's documented "if handle is null, return FALSE" — we treat unknown handle as closed).
/// ClosePrinter — close a connection to a printer or print server.
///
/// Returns TRUE (handle already invalid/closed; no resource to free).
///
/// # Safety
/// `h_printer` is ignored.
// stub: Phase A — no handle table; returns TRUE (no-op close).
pub unsafe extern "win64" fn close_printer(_h_printer: usize) -> i32 {
    1 // TRUE — nothing to close
}

// Wine ref: dlls/winspool.drv/info.c — WINSPOOL_EnumPrintersW initialises *lpdwReturned=0
// and *lpdwNeeded=0 before any registry walk; returns FALSE + ERROR_INSUFFICIENT_BUFFER
// when cbBuf < needed. When no printers exist, it returns TRUE with *lpdwReturned=0
// and *lpdwNeeded=0 (empty enum). Weave always has zero printers, so TRUE + zeros is correct.
/// EnumPrintersW — enumerate available printers.
///
/// Always returns FALSE with `*pcb_needed = 0` and `*pc_returned = 0` (no printers).
///
/// # Safety
/// `p_printer_enum`, `pcb_needed`, and `pc_returned` must be null or valid
/// writable pointers for their respective types.
// stub: Phase A — no spooler; zero printers enumerated, returns FALSE.
pub unsafe extern "win64" fn enum_printers_w(
    _flags: u32,
    _name: *const u16,
    _level: u32,
    _p_printer_enum: *mut u8,
    _cb_buf: u32,
    pcb_needed: *mut u32,
    pc_returned: *mut u32,
) -> i32 {
    // Write 0 to output counts before returning so callers that check them
    // before the return value don't see garbage.
    if let Some(pcb_needed) = weave_common::validators::validate_lpdword(pcb_needed as usize) {
        // SAFETY: pcb_needed validated by weave_common::validators::validate_lpdword (null + alignment).
        // (a) null-checked; (b) caller stack; (c) call duration; (d) none — Phase A.
        unsafe { *pcb_needed = 0 };
    }
    if let Some(pc_returned) = weave_common::validators::validate_lpdword(pc_returned as usize) {
        // SAFETY: pc_returned validated by weave_common::validators::validate_lpdword (null + alignment).
        // (a) null-checked; (b) caller stack; (c) call duration; (d) none — Phase A.
        unsafe { *pc_returned = 0 };
    }
    // ERROR_INSUFFICIENT_BUFFER is the Wine sentinel when cbBuf < needed.
    // With needed=0 and returned=0, returning FALSE + no error is also valid.
    // Use FALSE here — callers that check for TRUE to proceed with zero printers
    // will still read pc_returned=0 and skip enumeration.
    weave_common::set_last_error(0); // ERROR_SUCCESS — no printers is not an error
    0 // FALSE — empty enum; pc_returned=0 signals no printers
}

// Wine ref: dlls/winspool.drv/info.c — GetPrinterW looks up the printer by handle,
// reads the registry, fills pPrinter; returns FALSE + ERROR_INSUFFICIENT_BUFFER if
// cbBuf < needed. Since Weave issues no valid handles, FALSE is always correct.
/// GetPrinterW — retrieve information about a printer.
///
/// Returns FALSE (invalid handle — no printer).
///
/// # Safety
/// Arguments are ignored.
// stub: Phase A — no handle table; always returns FALSE.
pub unsafe extern "win64" fn get_printer_w(
    _h_printer: usize,
    _level: u32,
    _p_printer: *mut u8,
    _cb_buf: u32,
    _pcb_needed: *mut u32,
) -> i32 {
    weave_common::set_last_error(6); // ERROR_INVALID_HANDLE
    0 // FALSE
}

// Wine ref: dlls/winspool.drv/info.c — DeviceCapabilitiesW (or DeviceCapabilitiesA) returns
// the number of items in the output array, or -1 on error. When the device is not found,
// returns -1. Since Weave has no devices, -1 is always correct.
/// DeviceCapabilitiesW — query the capabilities of a printer device.
///
/// Returns -1 (error — no printer device).
///
/// # Safety
/// Arguments are ignored.
// stub: Phase A — no spooler; always returns -1 (error sentinel).
pub unsafe extern "win64" fn device_capabilities_w(
    _p_device: *const u16,
    _p_port: *const u16,
    _fw_capability: u16,
    _p_output: *mut u8,
    _p_dev_mode: *const u8,
) -> i32 {
    -1 // DC_* error sentinel per Wine dlls/winspool.drv/info.c
}

// Wine ref: dlls/winspool.drv/info.c — DocumentPropertiesW opens the printer-specific
// property dialog. Returns IDOK on success, -1 on error (invalid handle / not found).
// Since Weave has no printer, -1 is the correct failure return.
/// DocumentPropertiesW — display a printer properties dialog.
///
/// Returns -1 (error — no printer device).
///
/// # Safety
/// Arguments are ignored.
// stub: Phase A — no spooler; always returns -1 (error sentinel).
pub unsafe extern "win64" fn document_properties_w(
    _hwnd: usize,
    _h_printer: usize,
    _p_device_name: *const u16,
    _p_dev_mode_output: *mut u8,
    _p_dev_mode_input: *const u8,
    _f_mode: u32,
) -> i32 {
    -1
}

// Wine ref: dlls/winspool.drv/info.c — GetDefaultPrinterW (ordinal #203) writes the
// default printer name into pszBuffer (up to *pcch_buffer chars); returns TRUE on success,
// FALSE + ERROR_FILE_NOT_FOUND when no default printer is set. Weave has no printers.
/// GetDefaultPrinterW — retrieve the name of the default printer (ordinal #203).
///
/// Returns FALSE (no default printer configured).
///
/// # Safety
/// `psz_buffer` and `pcch_buffer` are ignored.
// stub: Phase A — no spooler; always returns FALSE (ERROR_FILE_NOT_FOUND).
pub unsafe extern "win64" fn get_default_printer_w(
    _psz_buffer: *mut u16,
    _pcch_buffer: *mut u32,
) -> i32 {
    weave_common::set_last_error(2); // ERROR_FILE_NOT_FOUND — no default printer
    0 // FALSE
}

/// Resolve a WINSPOOL.DRV import to a stub function pointer.
///
/// Called from `weave_shell32::resolve` when `dll` matches "WINSPOOL.DRV"
/// (case-insensitive).
pub fn resolve(func: &str) -> Option<usize> {
    match func {
        "OpenPrinterW" => Some(open_printer_w as *const () as usize),
        "ClosePrinter" => Some(close_printer as *const () as usize),
        "EnumPrintersW" => Some(enum_printers_w as *const () as usize),
        "GetPrinterW" => Some(get_printer_w as *const () as usize),
        "DeviceCapabilitiesW" => Some(device_capabilities_w as *const () as usize),
        "DocumentPropertiesW" => Some(document_properties_w as *const () as usize),
        // Ordinal #203 = GetDefaultPrinterW (confirmed via Wine dlls/winspool.drv/*.spec).
        "GetDefaultPrinterW" | "#203" => Some(get_default_printer_w as *const () as usize),
        _ => None,
    }
}
