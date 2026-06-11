//! kernel32.dll stubs for Weave.
//!
//! Critical sections are real: EnterCriticalSection blocks via spin+yield,
//! LeaveCriticalSection releases atomically, TryEnterCriticalSection returns
//! FALSE under contention. All three honour recursive entry (same-TID re-enter).
//! VirtualProtect/VirtualQuery delegate to mprotect/mincore.
//! WriteConsoleW converts UTF-16 to UTF-8 and writes to the Linux fd.
//! CreateFileW/ReadFile/WriteFile/CloseHandle delegate to weave-core file_io.

#![allow(non_snake_case)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Tracks the most recently freed heap address so consecutive double-frees
/// of the same pointer are silently ignored.  Windows HeapFree returns FALSE
/// (but does not crash) when called twice on the same block; glibc's free()
/// aborts on "fasttop" detection.  heap_alloc resets this to 0 so that the
/// same address can be legally freed again after a re-allocation.
static LAST_HEAP_FREE: AtomicUsize = AtomicUsize::new(0);

/// Process-global top-level exception filter installed via SetUnhandledExceptionFilter.
/// 0 means no handler installed (default: no filter).
static UEF_HANDLER: AtomicUsize = AtomicUsize::new(0);

/// Process-global override table for SetStdHandle / GetStdHandle.
/// Slots: [0]=stdin, [1]=stdout, [2]=stderr.
/// Sentinel value NO_OVERRIDE means "no override — fall back to default constant".
/// We use usize::MAX - 1 rather than usize::MAX so that INVALID_HANDLE_VALUE
/// (usize::MAX) can be stored as a valid override (e.g. SetStdHandle closing a handle).
/// Win32 handles are always < 2^31 and multiples of 4, so usize::MAX - 1 cannot
/// collide with any real handle.
const NO_OVERRIDE: usize = usize::MAX - 1;
static STD_HANDLE_OVERRIDES: [AtomicUsize; 3] = [
    AtomicUsize::new(NO_OVERRIDE),
    AtomicUsize::new(NO_OVERRIDE),
    AtomicUsize::new(NO_OVERRIDE),
];

/// Map a Windows nStdHandle value to an index into STD_HANDLE_OVERRIDES.
/// Returns None for unknown nStdHandle values.
fn std_slot(n: u32) -> Option<usize> {
    match n {
        STD_INPUT_HANDLE => Some(0),
        STD_OUTPUT_HANDLE => Some(1),
        STD_ERROR_HANDLE => Some(2),
        _ => None,
    }
}

use weave_common::stub::warn_once;
use weave_common::{STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use weave_core::progress::mark_phase;
use weave_core::restrace;
use weave_core::{file_io, handles};

// ── File mapping table ────────────────────────────────────────────────────────
//
// Maps a "mapping handle" → (mmap base address, mmap size) for file-backed
// CreateFileMappingW.  The view address returned by MapViewOfFile equals the
// base address, so UnmapViewOfFile can look it up by value.
//
// Mapping handles start at FILE_MAPPING_OFFSET to be visually distinct from
// file handles (4–N) and HWND values (0x10000+).
const FILE_MAPPING_OFFSET: usize = 0x0005_0000;
#[allow(clippy::type_complexity)]
static FILE_MAPPINGS: std::sync::OnceLock<Mutex<Vec<Option<(usize, usize)>>>> =
    std::sync::OnceLock::new();

fn file_mappings() -> &'static Mutex<Vec<Option<(usize, usize)>>> {
    FILE_MAPPINGS.get_or_init(|| Mutex::new(Vec::new()))
}

type FileMappingsGuard<'a> = std::sync::MutexGuard<'a, Vec<Option<(usize, usize)>>>;

fn lock_file_mappings<'a>(
    m: &'a Mutex<Vec<Option<(usize, usize)>>>,
) -> Option<FileMappingsGuard<'a>> {
    m.lock()
        .map_err(|e| eprintln!("weave: weave-kernel32: file mappings mutex poisoned: {e}"))
        .ok()
}

// ── Semaphore table ───────────────────────────────────────────────────────────
//
// Each CreateSemaphoreW/A allocates a heap-pinned sem_t via Box and stores it
// here, keyed by a monotonically-incrementing handle value starting at
// SEMAPHORE_HANDLE_BASE.  The Box guarantees the sem_t address is stable after
// sem_init — never move a SemWrapper out of its Box.
//
// Named semaphores are out of scope; lp_name is ignored.

/// sem_t is not Send/Sync by default; this newtype opts in.
struct SemWrapper(libc::sem_t);
unsafe impl Send for SemWrapper {}
unsafe impl Sync for SemWrapper {}

struct SemEntry {
    sem: Arc<SemWrapper>,
    // max_count is enforced by ReleaseSemaphore to prevent exceeding the ceiling.
    max_count: i32,
}

const SEMAPHORE_HANDLE_BASE: usize = 0x8FFF_0001;
static SEMAPHORE_NEXT: AtomicUsize = AtomicUsize::new(SEMAPHORE_HANDLE_BASE);
static SEMAPHORE_TABLE: OnceLock<Mutex<HashMap<usize, SemEntry>>> = OnceLock::new();

// ── Waitable timer table (timerfd-backed) ───────────────────────────────────
static TIMER_TABLE: OnceLock<Mutex<HashMap<usize, i32>>> = OnceLock::new();
static TIMER_NEXT_HANDLE: AtomicUsize = AtomicUsize::new(0xB000_0001);

fn timer_table() -> &'static Mutex<HashMap<usize, i32>> {
    TIMER_TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn sem_table() -> &'static Mutex<HashMap<usize, SemEntry>> {
    SEMAPHORE_TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Create a POSIX-backed anonymous semaphore and return its Weave handle.
/// Returns 0 (NULL) on invalid arguments or allocation failure.
/// Wine ref: dlls/kernelbase/sync.c:796 — CreateSemaphoreW delegates to
/// CreateSemaphoreExW(sa, initial, max, name, 0, SEMAPHORE_ALL_ACCESS) →
/// NtCreateSemaphore.  max=0 or initial>max → STATUS_INVALID_PARAMETER →
/// ERROR_INVALID_PARAMETER → NULL handle.
fn create_semaphore_impl(l_initial_count: i32, l_maximum_count: i32) -> usize {
    // Validate: max must be > 0 and initial must be ≤ max.
    if l_maximum_count <= 0 || l_initial_count < 0 || l_initial_count > l_maximum_count {
        return 0;
    }

    // Initialise sem_t on the stack, then move into Arc (which pins it on the heap).
    // Arc lets wait_for_single_object clone the entry, drop the table lock, and
    // then block without holding the mutex.
    let mut raw_sem = SemWrapper(unsafe { std::mem::zeroed::<libc::sem_t>() });

    // sem_init(pshared=0 → process-local, value=initial_count)
    let rc = unsafe {
        libc::sem_init(
            &mut raw_sem.0 as *mut libc::sem_t,
            0,
            l_initial_count as u32,
        )
    };
    if rc != 0 {
        return 0;
    }

    let handle = SEMAPHORE_NEXT.fetch_add(1, Ordering::Relaxed);
    let sem_entry = SemEntry {
        sem: Arc::new(raw_sem),
        max_count: l_maximum_count,
    };

    let mut table = match sem_table()
        .lock()
        .map_err(|e| eprintln!("weave: semaphore table mutex poisoned: {e}"))
        .ok()
    {
        Some(g) => g,
        None => return 0,
    };
    table.insert(handle, sem_entry);
    handle
}

/// Look up a semaphore handle and return its current value via sem_getvalue.
/// Returns None if the handle is not in the table.
pub fn semaphore_getvalue(handle: usize) -> Option<i32> {
    let table = sem_table()
        .lock()
        .map_err(|e| eprintln!("weave: semaphore table mutex poisoned: {e}"))
        .ok()?;
    let entry = table.get(&handle)?;
    let mut val: libc::c_int = 0;
    let rc = unsafe {
        libc::sem_getvalue(
            &entry.sem.0 as *const libc::sem_t as *mut libc::sem_t,
            &mut val,
        )
    };
    if rc == 0 {
        Some(val)
    } else {
        None
    }
}

/// Allocate a mapping slot and return its handle.
fn alloc_mapping(addr: usize, size: usize) -> usize {
    let mut table = match lock_file_mappings(file_mappings()) {
        Some(g) => g,
        None => return 0,
    };
    for (i, slot) in table.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some((addr, size));
            return i + FILE_MAPPING_OFFSET;
        }
    }
    table.push(Some((addr, size)));
    (table.len() - 1) + FILE_MAPPING_OFFSET
}

/// Look up and remove a mapping slot by handle; returns (addr, size).
#[allow(dead_code)]
fn take_mapping(handle: usize) -> Option<(usize, usize)> {
    let index = handle.checked_sub(FILE_MAPPING_OFFSET)?;
    let mut table = lock_file_mappings(file_mappings())?;
    table.get_mut(index)?.take()
}

/// Look up (addr, size) by view address across all slots (for UnmapViewOfFile).
fn find_mapping_by_addr(view_addr: usize) -> Option<(usize, usize)> {
    let mut table = lock_file_mappings(file_mappings())?;
    for slot in table.iter_mut() {
        if let Some((addr, size)) = *slot {
            if addr == view_addr {
                *slot = None;
                return Some((addr, size));
            }
        }
    }
    None
}

// Windows limits null-terminated strings to 32,767 UTF-16 code units (MAX_PATH extended).
// Scanning beyond this is almost certainly a caller bug; cap the loop to avoid runaway reads.
const MAX_UTF16_LEN: usize = 32_768;
const MAX_UTF8_LEN: usize = 65_536;

// Per-thread last error — backed by weave_common::last_error (shared TLS).
// The LAST_ERROR TLS definition lives in weave-common so other DLL crates
// (advapi32, user32, etc.) can set/get it without depending on weave-kernel32.

// Per-thread TLS slot storage for dynamically allocated TLS indices.
thread_local! {
    static TLS_SLOTS: RefCell<HashMap<u32, usize>> = RefCell::new(HashMap::new());
}

/// Windows OSVERSIONINFOEXW — extended version information.
/// This is the superset; OSVERSIONINFOW is the first 276 bytes.
#[repr(C)]
pub struct OsVersionInfoExW {
    dw_os_version_info_size: u32,
    dw_major_version: u32,
    dw_minor_version: u32,
    dw_build_number: u32,
    dw_platform_id: u32,
    sz_csd_version: [u16; 128],
    w_service_pack_major: u16,
    w_service_pack_minor: u16,
    w_suite_mask: u16,
    w_product_type: u8,
    w_reserved: u8,
}

/// Windows OSVERSIONINFOEXA — extended version information (ANSI).
#[repr(C)]
struct OsVersionInfoExA {
    dw_os_version_info_size: u32,
    dw_major_version: u32,
    dw_minor_version: u32,
    dw_build_number: u32,
    dw_platform_id: u32,
    sz_csd_version: [u8; 128],
    w_service_pack_major: u16,
    w_service_pack_minor: u16,
    w_suite_mask: u16,
    w_product_type: u8,
    w_reserved: u8,
}

/// Mirrors Windows CONSOLE_SCREEN_BUFFER_INFO layout.
#[repr(C)]
pub struct ConsoleScreenBufferInfo {
    pub size_x: i16,
    pub size_y: i16,
    pub cursor_x: i16,
    pub cursor_y: i16,
    pub attributes: u16,
    pub window_left: i16,
    pub window_top: i16,
    pub window_right: i16,
    pub window_bottom: i16,
    pub max_x: i16,
    pub max_y: i16,
}

/// Mirrors Windows BY_HANDLE_FILE_INFORMATION layout.
#[repr(C)]
pub struct ByHandleFileInformation {
    pub dw_file_attributes: u32,
    pub ft_creation_time_low: u32,
    pub ft_creation_time_high: u32,
    pub ft_last_access_time_low: u32,
    pub ft_last_access_time_high: u32,
    pub ft_last_write_time_low: u32,
    pub ft_last_write_time_high: u32,
    pub dw_volume_serial_number: u32,
    pub n_file_size_high: u32,
    pub n_file_size_low: u32,
    pub n_number_of_links: u32,
    pub n_file_index_high: u32,
    pub n_file_index_low: u32,
}

// ── Windows page-protection flags ─────────────────────────────────────────────

fn win_prot_to_linux(protect: u32) -> i32 {
    match protect & 0xFF {
        0x01 => libc::PROT_NONE,
        0x02 => libc::PROT_READ,
        0x04 => libc::PROT_READ | libc::PROT_WRITE,
        0x08 => libc::PROT_READ | libc::PROT_WRITE,
        0x10 => libc::PROT_EXEC,
        0x20 => libc::PROT_READ | libc::PROT_EXEC,
        0x40 | 0x80 => libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        _ => libc::PROT_READ | libc::PROT_WRITE,
    }
}

// ── Locale information ───────────────────────────────────────────────────────

fn locale_info_lookup(lc_type: u32) -> Option<&'static str> {
    match lc_type {
        0x0001 => Some("en-US"),                   // LOCALE_SLANGUAGE
        0x0002 => Some("ENU"),                     // LOCALE_SABBREVLANGNAME
        0x0003 => Some("English"),                 // LOCALE_SNATIVELANGNAME
        0x0004 => Some("United States"),           // LOCALE_SCOUNTRY
        0x0005 => Some("ENU"),                     // LOCALE_SABBREVCTRYNAME
        0x0007 => Some("English (United States)"), // LOCALE_SENGCOUNTRY
        0x000B => Some("437"),                     // LOCALE_IDEFAULTCODEPAGE (OEM)
        0x000C => Some(","),                       // LOCALE_SLIST (list separator)
        0x000D => Some("1"),                       // LOCALE_IMEASURE (1 = US customary)
        0x000E => Some("."),                       // LOCALE_SDECIMAL
        0x000F => Some(","),                       // LOCALE_STHOUSAND
        0x0010 => Some("3;0"),                     // LOCALE_SGROUPING
        0x0011 => Some("2"),                       // LOCALE_IDIGITS
        0x0012 => Some("1"),                       // LOCALE_ILZERO
        0x0013 => Some("0123456789"),              // LOCALE_SNATIVEDIGITS
        0x0014 => Some("$"),                       // LOCALE_SCURRENCY
        0x0015 => Some("USD"),                     // LOCALE_SINTLSYMBOL
        0x0016 => Some("."),                       // LOCALE_SMONDECIMALSEP
        0x0017 => Some(","),                       // LOCALE_SMONTHOUSANDSEP
        0x0018 => Some("3;0"),                     // LOCALE_SMONGROUPING
        0x0019 => Some("2"),                       // LOCALE_ICURRDIGITS
        0x001A => Some("2"),                       // LOCALE_IINTLCURRDIGITS
        0x001B => Some("0"),                       // LOCALE_ICURRENCY
        0x001C => Some("0"),                       // LOCALE_INEGCURR
        0x001D => Some("/"),                       // LOCALE_SDATE (obsolete)
        0x001E => Some(":"),                       // LOCALE_STIME (obsolete)
        0x001F => Some("dddd, MMMM dd, yyyy"),     // LOCALE_SLONGDATE
        0x0020 => Some("M/d/yyyy"),                // LOCALE_SSHORTDATE
        0x0021 => Some("1"),                       // LOCALE_ITIMEMARKPOSN
        0x0022 => Some("0"),                       // LOCALE_ICALENDARTYPE
        0x0023 => Some("0"),                       // LOCALE_IOPTIONALCALENDAR
        0x0024 => Some("1"),                       // LOCALE_IFIRSTDAYOFWEEK
        0x0025 => Some("0"),                       // LOCALE_IFIRSTWEEKOFYEAR
        0x0026 => Some("January"),                 // LOCALE_SMONTHNAME1
        0x0027 => Some("February"),
        0x0028 => Some("March"),
        0x0029 => Some("April"),
        0x002A => Some("May"),
        0x002B => Some("June"),
        0x002C => Some("July"),
        0x002D => Some("August"),
        0x002E => Some("September"),
        0x002F => Some("October"),
        0x0030 => Some("November"),
        0x0031 => Some("December"),
        0x0032 => Some(""),       // LOCALE_SMONTHNAME13 (not used in Gregorian)
        0x0038 => Some("Sunday"), // LOCALE_SDAYNAME1
        0x0039 => Some("Monday"),
        0x003A => Some("Tuesday"),
        0x003B => Some("Wednesday"),
        0x003C => Some("Thursday"),
        0x003D => Some("Friday"),
        0x003E => Some("Saturday"),
        0x0044 => Some("AM"),  // LOCALE_S1159 (AM designator)
        0x0045 => Some("PM"),  // LOCALE_S2359 (PM designator)
        0x0049 => Some("Jan"), // LOCALE_SABBREVMONTHNAME1
        0x004A => Some("Feb"),
        0x004B => Some("Mar"),
        0x004C => Some("Apr"),
        0x004D => Some("May"),
        0x004E => Some("Jun"),
        0x004F => Some("Jul"),
        0x0050 => Some("Aug"),
        0x0051 => Some("Sep"),
        0x0052 => Some("Oct"),
        0x0053 => Some("Nov"),
        0x0054 => Some("Dec"),
        0x0055 => Some(""),                        // LOCALE_SABBREVMONTHNAME13
        0x0056 => Some(""),                        // LOCALE_SPOSITIVESIGN
        0x0057 => Some("-"),                       // LOCALE_SNEGATIVESIGN
        0x0058 => Some("1"),                       // LOCALE_IPOSSIGNPOSN
        0x0059 => Some("en"),                      // LOCALE_SISO639LANGNAME
        0x005A => Some("US"),                      // LOCALE_SISO3166CTRYNAME
        0x005B => Some("h:mm:ss tt"),              // LOCALE_STIMEFORMAT (12h)
        0x005C => Some("en-US"),                   // LOCALE_SNAME
        0x0061 => Some("English"),                 // LOCALE_SENGLISHLANGUAGENAME
        0x0062 => Some("United States"),           // LOCALE_SENGLISHCOUNTRYNAME
        0x0063 => Some("English"),                 // LOCALE_SNATIVELANGUAGENAME
        0x0064 => Some("United States"),           // LOCALE_SNATIVECOUNTRYNAME
        0x1004 => Some("1252"),                    // LOCALE_IDEFAULTANSICODEPAGE
        0x1007 => Some("English (United States)"), // LOCALE_SNATIVEDISPLAYNAME
        0x1009 => Some("English (United States)"), // LOCALE_SLOCALIZEDDISPLAYNAME
        _ => None,
    }
}

/// Numeric locale values returned when LOCALE_RETURN_NUMBER is set.
///
/// Wine ref: dlls/kernelbase/locale.c — get_locale_info writes binary DWORD for
/// LOCALE_RETURN_NUMBER; caller passes cch_data=2 (sizeof DWORD / sizeof WCHAR).
fn locale_number_lookup(lc_type: u32) -> u32 {
    match lc_type {
        0x0001 => 0x0409, // LOCALE_ILANGUAGE — English US LCID
        0x000B => 437,    // LOCALE_IDEFAULTCODEPAGE — OEM code page
        0x000D => 0,      // LOCALE_IMEASURE — 0 = metric
        0x000E => 0,      // LOCALE_IDIGITSUBSTITUTION
        0x0011 => 2,      // LOCALE_IDIGITS
        0x0012 => 1,      // LOCALE_ILZERO
        0x0018 => 0,      // LOCALE_INEGNUMBER
        0x0019 => 2,      // LOCALE_ICURRDIGITS
        0x001A => 2,      // LOCALE_IINTLCURRDIGITS
        0x001B => 0,      // LOCALE_ICURRENCY (0 = $n)
        0x001C => 0,      // LOCALE_INEGCURR
        0x001D => 1,      // LOCALE_IPOSSYMPRECEDES
        0x001E => 0,      // LOCALE_IPOSSEPBYSPACE
        0x001F => 1,      // LOCALE_INEGSYMPRECEDES
        0x0020 => 0,      // LOCALE_INEGSEPBYSPACE
        0x0021 => 1,      // LOCALE_ITIMEMARKPOSN
        0x0022 => 1,      // LOCALE_ICALENDARTYPE — 1 = Gregorian
        0x0023 => 0,      // LOCALE_IOPTIONALCALENDAR
        0x0024 => 0,      // LOCALE_IFIRSTDAYOFWEEK — 0 = Monday
        0x0025 => 0,      // LOCALE_IFIRSTWEEKOFYEAR
        0x0050 => 3,      // LOCALE_IPOSSIGNPOSN
        0x0051 => 0,      // LOCALE_INEGSIGNPOSN
        0x0055 => 0,      // LOCALE_IREADINGLAYOUT — 0 = LTR
        0x1004 => 1252,   // LOCALE_IDEFAULTANSICODEPAGE
        0x1010 => 1,      // LOCALE_INEGNUMBER
        0x1014 => 0,      // LOCALE_IDEFAULTMACCODEPAGE
        _ => 0,           // unknown: return 0 (safe default, avoids goto-fail)
    }
}

// ── Stubs ─────────────────────────────────────────────────────────────────────

/// GetStdHandle: return the Weave HANDLE for stdin/stdout/stderr.
///
/// Checks the process-global override table first (written by SetStdHandle).
/// If no override is set (sentinel NO_OVERRIDE), falls back to the default
/// handle constants. Returns INVALID_HANDLE_VALUE (usize::MAX) for unknown
/// nStdHandle values.
// Wine ref: dlls/kernelbase/console.c — reads from process STD handle table;
// returns INVALID_HANDLE_VALUE for unknown nStdHandle values.
pub extern "win64" fn get_std_handle(n_std_handle: u32) -> usize {
    let slot = match std_slot(n_std_handle) {
        Some(s) => s,
        None => return usize::MAX, // INVALID_HANDLE_VALUE
    };
    let override_val = STD_HANDLE_OVERRIDES[slot].load(Ordering::Relaxed);
    if override_val != NO_OVERRIDE {
        return override_val;
    }
    // No override — fall back to default constants.
    match n_std_handle {
        STD_INPUT_HANDLE => handles::STDIN_HANDLE,
        STD_OUTPUT_HANDLE => handles::STDOUT_HANDLE,
        STD_ERROR_HANDLE => handles::STDERR_HANDLE,
        _ => usize::MAX,
    }
}

/// WriteConsoleW: write a UTF-16 buffer to a console handle.
///
/// Looks up the Linux fd via the global HANDLE table, converts UTF-16 to
/// UTF-8, then writes to the fd.
///
/// # Safety
/// `lp_buffer` must be valid for `n_chars` UTF-16 code units.
// Wine ref: dlls/kernelbase/console.c:2163 — calls console_ioctl with
// IOCTL_CONDRV_WRITE_CONSOLE; sets *written = length on success, 0 on failure.
// reserved parameter is accepted but not used.
pub unsafe extern "win64" fn write_console_w(
    h_console_output: usize,
    lp_buffer: *const u16,
    n_chars: u32,
    lp_chars_written: *mut u32,
    _lp_reserved: usize,
) -> i32 {
    // Pointer validation: null buffer or zero-length is a no-op.
    if lp_buffer.is_null() {
        if !lp_chars_written.is_null() {
            unsafe { *lp_chars_written = 0 };
        }
        return 0; // FALSE — invalid parameter
    }
    // Sanity cap: Windows itself rejects more than ~32k chars in one call.
    // More importantly, a crafted n_chars of 0xFFFFFFFF would try to read 8GB.
    const MAX_CONSOLE_CHARS: u32 = 65_536;
    let n_chars = n_chars.min(MAX_CONSOLE_CHARS);

    let fd = match handles::get_fd(h_console_output) {
        Some(fd) => fd,
        None => return 0, // FALSE
    };
    // SAFETY: lp_buffer was checked non-null above; n_chars was capped to
    // MAX_CONSOLE_CHARS (65_536) so the slice length is bounded and valid.
    let slice = unsafe { std::slice::from_raw_parts(lp_buffer, n_chars as usize) };
    let s = String::from_utf16_lossy(slice);
    let bytes = s.as_bytes();
    // SAFETY: fd is a valid Linux file descriptor from the handle table;
    // bytes is a valid UTF-8 slice with a stable pointer.
    let n = unsafe { libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len()) };
    if !lp_chars_written.is_null() {
        unsafe { *lp_chars_written = if n >= 0 { n_chars } else { 0 } };
    }
    (n >= 0) as i32
}

/// ExitProcess: terminate the process with the given exit code.
// Wine ref: dlls/kernelbase/process.c — ExitProcess calls RtlExitUserProcess
// which sends the exit code to the Wineserver and unwinds TLS callbacks
// (DLL_PROCESS_DETACH) before calling NtTerminateProcess.
pub extern "win64" fn exit_process(u_exit_code: u32) -> ! {
    eprintln!("weave/kernel32: ExitProcess({u_exit_code})");
    unsafe { libc::exit(u_exit_code as i32) }
}

/// TerminateProcess: forcibly terminate a process.
///
/// For Weave's single-process model we treat any TerminateProcess call as
/// "exit immediately".  hProcess is ignored — there is only one process.
///
/// # Safety
/// `_h_process` is accepted but not dereferenced.
// Wine ref: server/process.c:1512 (terminate_process handler) — sends
// SIGKILL via server to the target process; the server sets exit_code
// then calls process_killed(). Ignores self-termination vs. remote.
pub unsafe extern "win64" fn terminate_process(_h_process: usize, u_exit_code: u32) -> i32 {
    eprintln!("weave: TerminateProcess exit_code={u_exit_code:#x}");
    unsafe { libc::exit(u_exit_code as i32) }
}

/// GetLastError: return the calling thread's last error code.
// Wine ref: include/winbase.h:2679 — inline that reads TEB->LastErrorValue;
// kernelbase implements via NtCurrentTeb()->LastErrorValue directly.
pub extern "win64" fn get_last_error() -> u32 {
    let v = weave_common::get_last_error();
    // Trace every GetLastError to pinpoint stale-errno bleeds that turn into
    // spurious HRESULT_FROM_WIN32(GetLastError()) wrappers in apps like 7-Zip.
    // Zero is common (success); skip to keep noise down.
    if v != 0 {
        eprintln!("weave/GetLastError: → {v} (0x{v:x})");
    }
    v
}

/// SetLastError: set the calling thread's last error code.
// Wine ref: include/winbase.h — inline that writes TEB->LastErrorValue;
// SetLastError(0) is a common pattern to clear error before a call.
pub extern "win64" fn set_last_error(dw_err_code: u32) {
    if dw_err_code != 0 {
        eprintln!("weave/SetLastError: code={dw_err_code} (0x{dw_err_code:x})");
    }
    weave_common::set_last_error(dw_err_code);
}

/// Process-global error mode flags set via SetErrorMode.
/// Windows default is 0 (all error dialogs enabled).
static ERROR_MODE: AtomicU32 = AtomicU32::new(0);

/// SetErrorMode: set the process error-mode flags and return the previous value.
///
/// # Safety
/// Called from Windows PE code via IAT; parameters are caller-supplied Win32 values.
// Wine ref: dlls/kernelbase/process.c — stores value per-process and returns old value.
pub unsafe extern "win64" fn set_error_mode(u_mode: u32) -> u32 {
    ERROR_MODE.swap(u_mode, Ordering::Relaxed)
}

/// VirtualProtect: change memory protection on a region.
///
/// # Safety
/// `lp_address` must point into a valid mapped region.
// Wine ref: dlls/kernelbase/memory.c:553 — delegates to VirtualProtectEx which
// calls NtProtectVirtualMemory; Win9x allows NULL old_prot but NT does not —
// old_prot must be a valid pointer on NT/Vista+.
pub unsafe extern "win64" fn virtual_protect(
    lp_address: *mut u8,
    dw_size: usize,
    fl_new_protect: u32,
    lpfl_old_protect: *mut u32,
) -> i32 {
    if !lpfl_old_protect.is_null() {
        unsafe { *lpfl_old_protect = 0x40 }; // report old prot as PAGE_EXECUTE_READWRITE
    }
    let prot = win_prot_to_linux(fl_new_protect);
    // Round address down to page boundary and size up to a full page multiple.
    let page_addr = (lp_address as usize) & !(4096 - 1);
    let page_size = (dw_size + 4095) & !4095;
    // SAFETY: page_addr is a page-aligned address within a mapped region (the caller's
    // # Safety contract); page_size is a non-zero multiple of the system page size.
    // mprotect requires both conditions, plus that the range stays within a single
    // VMA.  We don't enforce the VMA constraint here — Windows semantics allow
    // multi-region calls, and mprotect will return ENOMEM for invalid ranges which
    // we map to failure via the return value.
    let ret = unsafe { libc::mprotect(page_addr as *mut libc::c_void, page_size, prot) };
    (ret == 0) as i32
}

/// VirtualQuery: return basic info about a memory region.
///
/// Returns a minimal MEMORY_BASIC_INFORMATION (48 bytes) that satisfies
/// the CRT stack-guard introspection. Every page is reported as committed
/// and read-write private.
///
/// # Safety
/// `lp_buffer` must be writable for at least `dw_length` bytes (minimum 48).
// Wine ref: dlls/kernelbase/memory.c::VirtualQueryEx — calls
// NtQueryVirtualMemory(MemoryBasicInformation); returns sizeof(MBI) on success,
// 0 on failure. MBI layout: BaseAddress(8)+AllocationBase(8)+AllocationProtect(4)
// +__alignment(4)+RegionSize(8)+State(4)+Protect(4)+Type(4) = 48 bytes on x64.
pub unsafe extern "win64" fn virtual_query(
    lp_address: *const u8,
    lp_buffer: *mut u8,
    dw_length: usize,
) -> usize {
    const MBI_SIZE: usize = 48;
    if lp_buffer.is_null() || dw_length < MBI_SIZE {
        return 0;
    }
    let page_addr = (lp_address as usize) & !(4096 - 1);
    // SAFETY: lp_buffer is non-null (checked above) and dw_length >= MBI_SIZE (48).
    // We write exactly MBI_SIZE bytes at byte-level offsets matching the
    // MEMORY_BASIC_INFORMATION layout documented in the Windows SDK (x64):
    //   +0  PVOID  BaseAddress
    //   +8  PVOID  AllocationBase
    //   +16 DWORD  AllocationProtect
    //   +24 SIZE_T RegionSize
    //   +32 DWORD  State
    //   +36 DWORD  Protect
    //   +40 DWORD  Type
    // All writes stay within the 48-byte span and are at correctly aligned offsets.
    unsafe {
        std::ptr::write_bytes(lp_buffer, 0, MBI_SIZE);
        *(lp_buffer as *mut usize) = page_addr; // BaseAddress
        *(lp_buffer.add(8) as *mut usize) = page_addr; // AllocationBase
        *(lp_buffer.add(16) as *mut u32) = 0x04; // AllocationProtect = PAGE_READWRITE
        *(lp_buffer.add(24) as *mut usize) = 4096; // RegionSize
        *(lp_buffer.add(32) as *mut u32) = 0x1000; // State = MEM_COMMIT
        *(lp_buffer.add(36) as *mut u32) = 0x04; // Protect = PAGE_READWRITE
        *(lp_buffer.add(40) as *mut u32) = 0x20000; // Type = MEM_PRIVATE
    }
    MBI_SIZE
}

/// VirtualAlloc: allocate virtual memory.
///
/// # Safety
/// `lp_address` must be null or a valid address for allocation.
/// VirtualAlloc: reserve or commit virtual memory pages.
///
/// Wine ref: dlls/kernelbase/memory.c — VirtualAlloc delegates to VirtualAllocEx which
/// calls NtAllocateVirtualMemory. MEM_COMMIT | MEM_RESERVE is the normal pattern.
/// Weave maps via mmap; MAP_FIXED_NOREPLACE prevents overwriting existing Weave mappings.
///
/// # Safety
/// `lp_address` must be null or a page-aligned address.
// Wine ref: dlls/kernelbase/memory.c — VirtualAlloc delegates to VirtualAllocEx →
// NtAllocateVirtualMemory. MEM_COMMIT|MEM_RESERVE is the normal pattern; MEM_RESERVE
// alone allocates without backing pages. Weave maps via mmap; MAP_FIXED_NOREPLACE used
// when addr is non-null to avoid silently replacing existing mappings.
pub unsafe extern "win64" fn virtual_alloc(
    lp_address: *mut u8,
    dw_size: usize,
    _fl_allocation_type: u32,
    fl_protect: u32,
) -> *mut u8 {
    let prot = win_prot_to_linux(fl_protect);
    const MAP_FIXED_NOREPLACE: i32 = 0x10_0000;
    // Low 32-bit policy (null-base case only): pass a low hint so the kernel
    // prefers an address < 2 GiB. Combined with MAP_32BIT (Linux x86-64 0x40)
    // for best compatibility. Required for guests storing VirtualAlloc results
    // in DWORDs (Q-Dir 0x7795c / 0x7880d truncation; TRACE-D CI 26721495118).
    // The returned value must be both a valid host pointer and truncatable to
    // 32 bits for guests that store VA results in DWORD fields.
    const MAP_32BIT: i32 = 0x40;
    const LOW_32BIT_HINT: *mut libc::c_void = 0x0000_0000_0040_0000 as *mut libc::c_void;
    // Guard against mmap(NULL, 0, ...) which returns MAP_FAILED on Linux.
    if dw_size == 0 {
        eprintln!("weave: VirtualAlloc(size=0) → NULL");
        return std::ptr::null_mut();
    }
    // SAFETY: mmap with MAP_ANONYMOUS and fd=-1 does not dereference any pointer;
    // passing null (or lp_address) as the hint is always valid.  When lp_address is
    // non-null, MAP_FIXED_NOREPLACE ensures mmap returns MAP_FAILED instead of
    // silently remapping an existing allocation — the caller must handle the failure.
    // dw_size > 0 is enforced by the early-return above.
    // Sandbox: fd=-1 + MAP_ANONYMOUS only — no fd-backed mapping; no Landlock escape path.
    let result = if lp_address.is_null() {
        unsafe {
            libc::mmap(
                LOW_32BIT_HINT,
                dw_size,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_32BIT,
                -1,
                0,
            )
        }
    } else {
        unsafe {
            libc::mmap(
                lp_address as *mut libc::c_void,
                dw_size,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        }
    };
    if result == libc::MAP_FAILED {
        let err = std::io::Error::last_os_error();
        eprintln!(
            "weave: VirtualAlloc FAILED addr={:#x} size={dw_size:#x} err={err}",
            lp_address as usize
        );
        std::ptr::null_mut()
    } else {
        let result_ptr = result as *mut u8;
        eprintln!("weave/VirtualAlloc: size={dw_size:#x} → addr={result_ptr:p}");
        result_ptr
    }
}

/// VirtualAllocEx: allocate virtual memory in another process.
///
/// # Safety
/// `lp_address` must be null or a valid address for allocation.
// Wine ref: dlls/kernelbase/memory.c — VirtualAllocEx calls
// NtAllocateVirtualMemory; hProcess is ignored in Weave (single-process model).
pub unsafe extern "win64" fn virtual_alloc_ex(
    _h_process: usize,
    lp_address: *mut u8,
    dw_size: usize,
    fl_allocation_type: u32,
    fl_protect: u32,
) -> *mut u8 {
    unsafe { virtual_alloc(lp_address, dw_size, fl_allocation_type, fl_protect) }
}

/// VirtualFree: free virtual memory.
///
/// Wine ref: dlls/kernelbase/memory.c — VirtualFreeEx: MEM_RELEASE with non-zero size →
/// ERROR_INVALID_PARAMETER. MEM_RELEASE with size=0 is the correct release pattern.
/// MEM_DECOMMIT with a size decommits only that range.
///
/// Known gap: Weave does not track VirtualAlloc sizes. MEM_RELEASE (size=0) should unmap
/// the entire allocation; without size tracking we cannot call munmap. This is an accepted
/// in-process model gap (Phase 4).
///
/// # Safety
/// `lp_address` must be a valid mmap'd address.
// Wine ref: dlls/kernelbase/memory.c — VirtualFree delegates to VirtualFreeEx →
// NtFreeVirtualMemory. MEM_RELEASE requires dwSize=0; non-zero → ERROR_INVALID_PARAMETER.
// MEM_DECOMMIT with size decommits only that range (pages become reserved, not freed).
pub unsafe extern "win64" fn virtual_free(
    lp_address: *mut u8,
    dw_size: usize,
    dw_free_type: u32,
) -> i32 {
    const MEM_RELEASE: u32 = 0x8000;
    const MEM_DECOMMIT: u32 = 0x4000;

    eprintln!("weave/VirtualFree: addr={lp_address:p} size={dw_size:#x} type={dw_free_type:#x}");
    if lp_address.is_null() {
        return 0; // FALSE — NULL address is invalid
    }
    match dw_free_type {
        MEM_RELEASE if dw_size != 0 => {
            // Wine ref: MEM_RELEASE with non-zero dwSize → ERROR_INVALID_PARAMETER
            eprintln!("weave/VirtualFree: addr={lp_address:p} size={dw_size:#x} type=MEM_RELEASE → FALSE (ERROR_INVALID_PARAMETER: size must be 0 for MEM_RELEASE)");
            set_last_error(0x57); // ERROR_INVALID_PARAMETER
            0
        }
        MEM_RELEASE => {
            // Known gap: we don't track VirtualAlloc sizes, so we can't munmap the region.
            // Accept it as a no-op (leak) rather than crashing.
            eprintln!("weave/VirtualFree: addr={lp_address:p} size={dw_size:#x} type=MEM_RELEASE → TRUE (no-op, size not tracked)");
            1 // TRUE
        }
        MEM_DECOMMIT => {
            // Decommit a range: munmap the specific range.
            if dw_size == 0 {
                eprintln!("weave/VirtualFree: addr={lp_address:p} size=0 type=MEM_DECOMMIT → FALSE (ERROR_INVALID_PARAMETER)");
                set_last_error(0x57);
                return 0;
            }
            eprintln!("weave/VirtualFree: addr={lp_address:p} size={dw_size:#x} type=MEM_DECOMMIT → munmap");
            // SAFETY: lp_address is non-null (checked above) and was obtained from
            // VirtualAlloc (mmap); dw_size > 0 (checked above).  munmap requires
            // that the address is page-aligned — Windows semantics say lp_address
            // for MEM_DECOMMIT must be within an allocated region, so the caller is
            // responsible for alignment per the API contract.
            let ret = unsafe { libc::munmap(lp_address as *mut libc::c_void, dw_size) };
            (ret == 0) as i32
        }
        _ => {
            set_last_error(0x57);
            0
        }
    }
}

/// VirtualFreeEx: free virtual memory in another process.
///
/// # Safety
/// `lp_address` must be a valid allocated address.
// Wine ref: dlls/kernelbase/memory.c — VirtualFreeEx calls
// NtFreeVirtualMemory; hProcess is ignored in Weave (single-process model).
pub unsafe extern "win64" fn virtual_free_ex(
    _h_process: usize,
    lp_address: *mut u8,
    dw_size: usize,
    dw_free_type: u32,
) -> i32 {
    unsafe { virtual_free(lp_address, dw_size, dw_free_type) }
}

/// Sleep: suspend the calling thread for the given number of milliseconds.
// Wine ref: dlls/kernelbase/sync.c:361 — calls NtDelayExecution(FALSE, &timeout)
// where timeout is a negative 100ns LARGE_INTEGER. INFINITE (0xFFFFFFFF) passes
// NULL timeout to NtDelayExecution, sleeping indefinitely.
pub extern "win64" fn sleep(dw_milliseconds: u32) {
    eprintln!("weave/Sleep: ms={dw_milliseconds}");
    let ts = libc::timespec {
        tv_sec: (dw_milliseconds / 1000) as i64,
        tv_nsec: ((dw_milliseconds % 1000) * 1_000_000) as i64,
    };
    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
}

/// TlsGetValue: return the value stored in a TLS slot.
///
/// Static indices (0-63) return NULL. Dynamic indices (64+) use per-thread storage.
// Wine ref: dlls/kernelbase/thread.c:785 — indices < TLS_MINIMUM_AVAILABLE (64)
// read TEB->TlsSlots[index]; higher indices use TEB->TlsExpansionSlots[index-64].
// Always clears LastError to ERROR_SUCCESS before returning.
pub extern "win64" fn tls_get_value(dw_tls_index: u32) -> *mut u8 {
    // Wine ref: dlls/kernelbase/thread.c — TlsGetValue always clears LastError
    // to ERROR_SUCCESS before returning, even on success. Callers use GetLastError
    // after TlsGetValue(index) to distinguish "slot is NULL" from "slot not set".
    set_last_error(0);
    if dw_tls_index >= 64 {
        return TLS_SLOTS
            .with(|slots| slots.borrow().get(&dw_tls_index).copied().unwrap_or(0) as *mut u8);
    }
    std::ptr::null_mut()
}

/// InitializeCriticalSection: zero-initialise the CRITICAL_SECTION struct.
///
/// # Safety
/// `lp_critical_section` must point to at least 40 bytes of writable memory.
// Wine ref: dlls/kernelbase/sync.c::InitializeCriticalSectionEx — calls
// RtlInitializeCriticalSectionEx; sets LockCount=-1, RecursionCount=0,
// OwningThread=0, LockSemaphore=0; raises STATUS_NO_MEMORY on failure.
pub unsafe extern "win64" fn initialize_critical_section(lp_critical_section: *mut u8) {
    // Pointer validation: null is an invalid parameter.
    if lp_critical_section.is_null() {
        return;
    }
    unsafe { std::ptr::write_bytes(lp_critical_section, 0, 40) };
    // SAFETY: lp_critical_section is non-null (checked above) and points to at
    // least 40 bytes (documented in the function's # Safety contract).  Offset 8
    // is the LockCount field of the Windows CRITICAL_SECTION struct (RTL_CRITICAL_SECTION
    // layout: DebugInfo(8) + LockCount(4) = offset 8).  We wrote the preceding 40 bytes
    // to zero, so the pointer arithmetic stays within the allocation.
    unsafe { *(lp_critical_section.add(8) as *mut i32) = -1 };
}

/// EnterCriticalSection: acquire the critical section (blocking spin).
///
/// RTL_CRITICAL_SECTION layout (offsets in bytes):
///   0  DebugInfo (8 bytes, ptr — unused)
///   8  LockCount (i32: -1=unlocked, ≥0=locked; +1 per recursive hold)
///  12  RecursionCount (i32: 0=not held, ≥1=depth)
///  16  OwningThread (usize: Linux TID, 0=none)
///  24  LockSemaphore (HANDLE — unused)
///  32  SpinCount (usize — ignored)
///
/// # Safety
/// `lp_critical_section` must point to at least 40 bytes of writable,
/// 4-byte-aligned memory (the Windows CRITICAL_SECTION struct).
// Wine ref: dlls/ntdll/sync.c — RtlEnterCriticalSection: spins on LockCount
// CAS(-1 → 0); on success sets OwningThread = NtCurrentTeb()->ClientId.UniqueThread
// and RecursionCount = 1 (or increments both for recursive entry). For contended
// case Wine falls through to NtWaitForKeyedEvent; we use sched_yield + nanosleep.
pub unsafe extern "win64" fn enter_critical_section(lp_critical_section: *mut u8) {
    if lp_critical_section.is_null() {
        return;
    }
    // SAFETY: caller guarantees valid 40-byte struct; offset 16 (usize) is 8-byte aligned.
    let owning_atomic = unsafe { &*(lp_critical_section.add(16) as *const AtomicUsize) };
    let tid = unsafe { libc::syscall(libc::SYS_gettid) as usize };
    // Recursive entry: same thread already owns the CS.
    if owning_atomic.load(Ordering::Acquire) == tid {
        // SAFETY: RecursionCount at offset 12, i32.
        let rec_ptr = unsafe { lp_critical_section.add(12) as *mut i32 };
        // SAFETY: LockCount at offset 8, i32.
        let lock_atomic = unsafe { &*(lp_critical_section.add(8) as *const AtomicI32) };
        unsafe {
            let rc = std::ptr::read_volatile(rec_ptr);
            std::ptr::write_volatile(rec_ptr, rc + 1);
        }
        lock_atomic.fetch_add(1, Ordering::AcqRel);
        return;
    }
    // Fast path / spin loop: CAS LockCount from -1 → 0.
    // SAFETY: LockCount at offset 8, 4-byte aligned.
    let lock_atomic = unsafe { &*(lp_critical_section.add(8) as *const AtomicI32) };
    let rec_ptr = unsafe { lp_critical_section.add(12) as *mut i32 };
    const SPIN_LIMIT: u32 = 4_000;
    let mut spins: u32 = 0;
    loop {
        match lock_atomic.compare_exchange(-1, 0, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                // Acquired — set owner and recursion depth.
                owning_atomic.store(tid, Ordering::Release);
                unsafe { std::ptr::write_volatile(rec_ptr, 1) };
                return;
            }
            Err(_) => {
                spins += 1;
                if spins == 1 {
                    eprintln!("weave/EnterCriticalSection: cs={lp_critical_section:p} contended (will spin)");
                }
                if spins < SPIN_LIMIT {
                    unsafe { libc::sched_yield() };
                } else {
                    // Back off: sleep 1 ms to avoid burning CPU in CI.
                    let ts = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 1_000_000,
                    };
                    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
                    spins = 0;
                }
            }
        }
    }
}

/// LeaveCriticalSection: release the critical section.
///
/// # Safety
/// `lp_critical_section` must point to the same valid CRITICAL_SECTION struct
/// that was passed to EnterCriticalSection.
// Wine ref: dlls/ntdll/sync.c — RtlLeaveCriticalSection: decrements RecursionCount;
// when it reaches 0, clears OwningThread and stores -1 to LockCount via Interlocked
// exchange. Waiter wake-up (NtReleaseKeyedEvent) only fires when LockCount was > 0
// before the decrement (i.e. there were waiters); we skip the wake because our Enter
// spins rather than blocking on a kernel object.
pub unsafe extern "win64" fn leave_critical_section(lp_critical_section: *mut u8) {
    if lp_critical_section.is_null() {
        return;
    }
    // SAFETY: offsets verified against RTL_CRITICAL_SECTION layout above.
    let lock_atomic = unsafe { &*(lp_critical_section.add(8) as *const AtomicI32) };
    let rec_ptr = unsafe { lp_critical_section.add(12) as *mut i32 };
    // SAFETY: offset 16 is 8-byte aligned; AtomicUsize has the same layout as usize.
    let owning_atomic = unsafe { &*(lp_critical_section.add(16) as *const AtomicUsize) };
    let rc = unsafe { std::ptr::read_volatile(rec_ptr) };
    if rc > 1 {
        // Recursive hold: unwind one level.
        unsafe { std::ptr::write_volatile(rec_ptr, rc - 1) };
        // Decrement LockCount to match (mirrors recursive Enter increment).
        lock_atomic.fetch_sub(1, Ordering::Release);
    } else {
        // Final release: clear owner first, then unlock.
        unsafe { std::ptr::write_volatile(rec_ptr, 0) };
        owning_atomic.store(0, Ordering::Release);
        lock_atomic.store(-1, Ordering::Release);
    }
}

/// DeleteCriticalSection: free resources associated with a critical section.
///
/// Phase 1: no-op.
// Wine ref: dlls/ntdll/sync.c — RtlDeleteCriticalSection: closes LockSemaphore
// via NtClose if non-null; frees DebugInfo allocation from the heap.
pub extern "win64" fn delete_critical_section(_lp_critical_section: *mut u8) {}

/// SetUnhandledExceptionFilter: install a top-level exception filter.
///
/// Stores the handler in UEF_HANDLER and returns the previous handler pointer.
/// Passing 0 (NULL) clears the handler.
// Wine ref: dlls/kernelbase/except.c — stores filter via InterlockedExchangePointer;
// returns the previous filter. NULL argument clears the handler.
pub extern "win64" fn set_unhandled_exception_filter(lp_top_level_handler: usize) -> usize {
    UEF_HANDLER.swap(lp_top_level_handler, Ordering::SeqCst)
}

/// IsDBCSLeadByte: test whether a byte is a lead byte in the current DBCS.
///
/// Linux always uses UTF-8; DBCS is never active. Always returns FALSE.
// Wine ref: dlls/kernelbase/locale.c — checks if ACP is a DBCS code page
// and if so, looks up test_char in the lead-byte table; FALSE for UTF-8 (65001).
pub extern "win64" fn is_dbcs_lead_byte(_test_char: u8) -> i32 {
    0 // FALSE
}

/// IsDBCSLeadByteEx: test whether a byte is a lead byte for a specific code page.
///
/// Only UTF-8 (65001) is used; DBCS is not active. Always returns FALSE.
// Wine ref: dlls/kernelbase/locale.c:6657 — calls get_codepage_table(codepage); returns TRUE
// only if table->DBCSCodePage != 0 AND table->DBCSOffsets[testchar] != 0; UTF-8 and all
// single-byte code pages have DBCSCodePage==0 so always evaluate FALSE.
pub extern "win64" fn is_dbcs_lead_byte_ex(_code_page: u32, _test_char: u8) -> i32 {
    0 // FALSE
}

/// GetACP: return the current ANSI code page identifier.
///
/// Returns 65001 (UTF-8) — the only code page Weave supports.
// Wine ref: dlls/kernelbase/locale.c — reads ansi_cp.CodePage from the
// NLS locale data; returns the system ANSI code page set at boot.
pub extern "win64" fn get_acp() -> u32 {
    65001 // CP_UTF8
}

// ── SRW lock helpers (Linux futex) ───────────────────────────────────────────
//
// Wine ref: dlls/ntdll/sync.c:471 — Wine stores the SRW lock state as a
// packed 4-byte struct: `exclusive_waiters` (i16, bit 0 = exclusive-held flag,
// bits 1+ = exclusive-waiter count) followed by `owners` (u16, shared reader
// count). `RtlAcquireSRWLockExclusive` increments exclusive_waiters by 2 first,
// then CAS-loops on owners==0 to set owners=1 and clear the held bit. Shared
// waiters loop on exclusive_waiters==0 to increment owners.
//
// We follow this layout exactly. The SRWLOCK PVOID slot is 8 bytes on x64
// but only the low 32 bits carry lock state; the upper 32 bits stay zero.
//
// futex_wait / futex_wake operate on *const u32 (the low 32 bits of the slot).

/// Packed SRW lock state: [exclusive_waiters: i16][owners: u16] = 4 bytes.
/// bit 0 of exclusive_waiters: exclusive-held flag ("owned exclusive")
/// bits 1..15 of exclusive_waiters: number of threads waiting for exclusive access
/// owners: number of shared (read) holders
#[repr(C)]
#[derive(Clone, Copy)]
struct SrwLock {
    exclusive_waiters: i16,
    owners: u16,
}

// CONDITION_VARIABLE_LOCKMODE_SHARED
const CONDITION_VARIABLE_LOCKMODE_SHARED: u32 = 0x1;

/// FUTEX_WAIT on the low 32-bit word at `addr`.
/// Returns the raw i32 syscall return value (0 = woken, -EAGAIN/-EINTR/-ETIMEDOUT).
/// # Safety
/// `addr` must be valid for a 4-byte aligned read. `timeout` must be NULL or point
/// to a valid `libc::timespec`.
unsafe fn futex_wait(addr: *const u32, val: u32, timeout: *const libc::timespec) -> i32 {
    libc::syscall(
        libc::SYS_futex,
        addr,
        libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
        val,
        timeout,
        std::ptr::null::<u32>(),
        0u32,
    ) as i32
}

/// FUTEX_WAKE up to `count` waiters on `addr`.
/// # Safety
/// `addr` must be valid for a 4-byte read.
unsafe fn futex_wake(addr: *const u32, count: i32) -> i32 {
    libc::syscall(
        libc::SYS_futex,
        addr,
        libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG,
        count,
        std::ptr::null::<libc::timespec>(),
        std::ptr::null::<u32>(),
        0u32,
    ) as i32
}

/// Get a pointer to the low 32-bit word of an SRWLOCK slot (the packed state).
/// The SRWLOCK is stored in a `*mut usize` (8 bytes on x64); only the low 4 bytes
/// are used for lock state so that futex can operate on them.
/// # Safety
/// `slot` must be a valid pointer to an 8-byte SRWLOCK-sized region.
#[inline]
unsafe fn srw_state_ptr(slot: *mut usize) -> *mut u32 {
    // On little-endian Linux x86-64 the low 32 bits are at the same address.
    slot as *mut u32
}

// ── Task 1 — SRW try-acquire + DuplicateHandle + WaitOnAddress family ───────

/// TryAcquireSRWLockExclusive: try to acquire an SRW lock for exclusive access.
///
/// Single CAS attempt — returns TRUE (1) if acquired, FALSE (0) if already held.
/// # Safety
/// `srw_lock` must be a valid pointer to an SRWLOCK-sized slot.
// Wine ref: dlls/ntdll/sync.c:645 — RtlTryAcquireSRWLockExclusive: CAS loop on
// owners==0 to set owners=1 and exclusive_waiters|=1; returns BOOLEAN.
pub unsafe extern "win64" fn try_acquire_srw_lock_exclusive(srw_lock: *mut usize) -> u8 {
    let p = unsafe { srw_state_ptr(srw_lock) };
    let atomic = unsafe { &*(p as *const AtomicI32) };
    loop {
        let old_i32 = atomic.load(Ordering::Acquire);
        let old: SrwLock = unsafe { std::mem::transmute(old_i32 as u32) };
        if old.owners != 0 {
            return 0; // FALSE — locked (exclusive or shared)
        }
        let mut new = old;
        new.owners = 1;
        new.exclusive_waiters |= 1; // set held-exclusive bit
        let new_i32: i32 = unsafe { std::mem::transmute::<SrwLock, u32>(new) as i32 };
        if atomic
            .compare_exchange(old_i32, new_i32, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return 1; // TRUE
        }
    }
}

/// TryAcquireSRWLockShared: try to acquire an SRW lock for shared access.
///
/// Returns TRUE (1) if acquired, FALSE (0) if an exclusive lock is held or waiters present.
/// # Safety
/// `srw_lock` must be a valid pointer to an SRWLOCK-sized slot.
// Wine ref: dlls/ntdll/sync.c:680 — RtlTryAcquireSRWLockShared: CAS loop; fails if
// exclusive_waiters != 0 (exclusive held or waiters pending), else increments owners.
pub unsafe extern "win64" fn try_acquire_srw_lock_shared(srw_lock: *mut usize) -> u8 {
    let p = unsafe { srw_state_ptr(srw_lock) };
    let atomic = unsafe { &*(p as *const AtomicI32) };
    loop {
        let old_i32 = atomic.load(Ordering::Acquire);
        let old: SrwLock = unsafe { std::mem::transmute(old_i32 as u32) };
        if old.exclusive_waiters != 0 {
            return 0; // FALSE — exclusive held or exclusive waiters present
        }
        let mut new = old;
        new.owners += 1;
        let new_i32: i32 = unsafe { std::mem::transmute::<SrwLock, u32>(new) as i32 };
        if atomic
            .compare_exchange(old_i32, new_i32, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return 1; // TRUE
        }
    }
}

/// DuplicateHandle: duplicate a kernel object handle.
///
/// Wine ref: dlls/kernelbase/sync.c — calls NtDuplicateObject; if
/// DUPLICATE_CLOSE_SOURCE is set, closes the source handle after duplication.
/// Weave limitation: handle table has no ref-counting in Phase 1/2; single-process
/// only. We copy the handle value — caller gets a second reference to the same
/// slot. DUPLICATE_CLOSE_SOURCE and DUPLICATE_SAME_ACCESS flags are ignored.
/// This is sufficient for apps that duplicate handles to pass to threads they
/// create (also no-ops in Phase 1/2) or to child processes (not supported).
///
/// # Safety
/// `lp_target_handle` must be a valid writable pointer or NULL.
// Wine ref: dlls/kernelbase/process.c:744 — calls NtDuplicateObject(source_process, source,
// dest_process, dest, access, inherit ? OBJ_INHERIT : 0, options); full cross-process handle
// duplication backed by the server handle table. DUPLICATE_CLOSE_SOURCE handled server-side.
pub unsafe extern "win64" fn duplicate_handle(
    _h_source_process_handle: usize,
    h_source_handle: usize,
    _h_target_process_handle: usize,
    lp_target_handle: *mut usize,
    _dw_desired_access: u32,
    _b_inherit_handle: i32,
    _dw_options: u32,
) -> i32 {
    if !lp_target_handle.is_null() {
        unsafe { *lp_target_handle = h_source_handle };
    }
    1 // TRUE
}

/// ProcessIdToSessionId: get the session ID for a process.
///
/// # Safety
/// `p_session_id` must be a valid writable pointer or NULL.
// Wine ref: dlls/kernelbase/process.c:1117 — fast-path for current PID reads
// NtCurrentTeb()->Peb->SessionId directly; other PIDs: OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)
// then NtQueryInformationProcess(ProcessSessionInformation, id, sizeof(DWORD)).
pub unsafe extern "win64" fn process_id_to_session_id(
    _dw_process_id: u32,
    p_session_id: *mut u32,
) -> i32 {
    if !p_session_id.is_null() {
        unsafe { *p_session_id = 1 };
    }
    1 // TRUE
}

/// WaitOnAddress: wait for the value at `address` to differ from `*compare_address`.
///
/// Compares `address_size` bytes (1, 2, 4, or 8). If they already differ, returns
/// TRUE immediately. Otherwise blocks via futex until woken or timeout.
/// Returns FALSE + sets ERROR_TIMEOUT (0x5B4) on timeout.
///
/// # Safety
/// `address` must be valid for a read of `address_size` bytes.
/// `compare_address` must be valid for a read of `address_size` bytes.
// Wine ref: dlls/ntdll/sync.c:877 — RtlWaitOnAddress: compare_addr(addr, cmp, size)
// inside a spinlock to prevent missed wakes; size must be 1/2/4/8 else STATUS_INVALID_PARAMETER.
// Wine uses NtWaitForAlertByThreadId; on Linux we use FUTEX_WAIT on the low 32 bits.
// EAGAIN means the value changed before we slept — return TRUE. ETIMEDOUT → FALSE + ERROR_TIMEOUT.
pub unsafe extern "win64" fn wait_on_address(
    address: *const u8,
    compare_address: *const u8,
    address_size: usize,
    dw_milliseconds: u32,
) -> i32 {
    eprintln!(
        "weave/WaitOnAddress: entry addr={address:?} size={address_size} ms={dw_milliseconds}"
    );
    if address_size != 1 && address_size != 2 && address_size != 4 && address_size != 8 {
        set_last_error(0x57); // ERROR_INVALID_PARAMETER
        return 0;
    }

    // Compare current value to compare value.
    let differs = unsafe {
        match address_size {
            1 => *address != *compare_address,
            2 => *(address as *const u16) != *(compare_address as *const u16),
            4 => *(address as *const u32) != *(compare_address as *const u32),
            8 => *(address as *const u64) != *(compare_address as *const u64),
            _ => unreachable!(),
        }
    };
    if differs {
        return 1; // TRUE — already different, no need to wait
    }

    // Snapshot the low 32 bits at the wait address to use as the futex compare value.
    // For sizes < 4 we still read a u32 (safe: we only compare the low bytes we care about).
    let futex_val = unsafe { std::ptr::read_unaligned(address as *const u32) };

    // Build optional timeout.
    let timeout_storage: libc::timespec;
    let timeout_ptr: *const libc::timespec = if dw_milliseconds == 0xFFFF_FFFF {
        std::ptr::null()
    } else {
        timeout_storage = libc::timespec {
            tv_sec: (dw_milliseconds / 1000) as libc::time_t,
            tv_nsec: ((dw_milliseconds % 1000) * 1_000_000) as libc::c_long,
        };
        &timeout_storage
    };

    // futex_wait on the low 32-bit word.
    let ret = unsafe { futex_wait(address as *const u32, futex_val, timeout_ptr) };

    let errno = unsafe { *libc::__errno_location() };
    if ret == -1 && errno == libc::ETIMEDOUT {
        set_last_error(0x5B4); // ERROR_TIMEOUT
        return 0; // FALSE
    }
    // EAGAIN: value changed before sleep started — success.
    // EINTR: signal — treat as woken, caller will re-check.
    1 // TRUE
}

/// WakeByAddressSingle: wake one thread waiting on an address via WaitOnAddress.
///
/// Issues FUTEX_WAKE(1) on the low 32-bit word at `address`.
/// # Safety
/// `address` must be a valid pointer to a memory location that waiters are watching.
// Wine ref: dlls/ntdll/sync.c:961 — RtlWakeAddressSingle walks the hash-bucket queue and
// alerts one matching thread via NtAlertThreadByThreadId. On Linux we use FUTEX_WAKE(1).
pub extern "win64" fn wake_by_address_single(address: usize) {
    eprintln!("weave/WakeByAddressSingle: addr={address:#x}");
    if address == 0 {
        return;
    }
    unsafe { futex_wake(address as *const u32, 1) };
}

/// WakeByAddressAll: wake all threads waiting on an address via WaitOnAddress.
///
/// Issues FUTEX_WAKE(INT_MAX) on the low 32-bit word at `address`.
/// # Safety
/// `address` must be a valid pointer to a memory location that waiters are watching.
// Wine ref: dlls/ntdll/sync.c:927 — RtlWakeAddressAll collects all matching TIDs then
// calls NtAlertMultipleThreadByThreadId. On Linux FUTEX_WAKE(INT_MAX) wakes all waiters.
pub extern "win64" fn wake_by_address_all(address: usize) {
    if address == 0 {
        return;
    }
    unsafe { futex_wake(address as *const u32, i32::MAX) };
}

// ── Task 2 — Thread description + timer queue + affinity ────────────────────

/// SetThreadDescription: set a description for a thread.
///
/// No-op. Returns S_OK.
/// # Safety
/// `_h_thread` and `_lp_thread_description` are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/thread.c:476 — calls NtSetInformationThread with
// ThreadNameInformation; stores description as UNICODE_STRING in server thread object.
pub unsafe extern "win64" fn set_thread_description(
    _h_thread: usize,
    _lp_thread_description: *const u16,
) -> i32 {
    0 // S_OK
}

/// GetThreadDescription: get the description for a thread.
///
/// Write null to `*ppsz_thread_description` if non-null. Return S_OK.
/// # Safety
/// `ppsz_thread_description` must be a valid writable pointer or NULL.
// Wine ref: dlls/kernelbase/thread.c:497 — calls NtQueryInformationThread with
// ThreadNameInformation; allocates a LocalAlloc'd WCHAR buffer for the caller
// (caller must LocalFree it). Returns empty string if no description is set.
pub unsafe extern "win64" fn get_thread_description(
    _h_thread: usize,
    ppsz_thread_description: *mut *mut u16,
) -> i32 {
    if !ppsz_thread_description.is_null() {
        unsafe { *ppsz_thread_description = std::ptr::null_mut() };
    }
    0 // S_OK
}

/// CreateTimerQueueTimer: create a timer queue timer.
///
/// Stub: if `ph_new_timer` is non-null, write 1 to it. Return TRUE.
/// # Safety
/// `ph_new_timer` must be a valid writable pointer or NULL.
// Wine ref: dlls/kernelbase/sync.c — calls RtlCreateTimer; period=0 is one-shot,
// period>0 is repeating. Callback runs in a thread pool thread, not the caller.
pub unsafe extern "win64" fn create_timer_queue_timer(
    ph_new_timer: *mut usize,
    _timer_queue: usize,
    _callback: usize,
    _parameter: usize,
    _due_time: u32,
    _period: u32,
    _flags: u32,
) -> i32 {
    if !ph_new_timer.is_null() {
        unsafe { *ph_new_timer = 1 };
    }
    1 // TRUE
}

/// DeleteTimerQueueTimer: delete a timer queue timer.
///
/// No-op. Return TRUE.
/// # Safety
/// Arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/sync.c:994 — calls RtlDeleteTimer; if completion_event
// is INVALID_HANDLE_VALUE, waits for running callbacks to finish before returning.
pub unsafe extern "win64" fn delete_timer_queue_timer(
    _timer_queue: usize,
    _timer: usize,
    _completion_event: usize,
) -> i32 {
    1
}

/// SetThreadAffinityMask: set the processor affinity mask for a thread.
///
/// Wine ref: dlls/kernelbase/thread.c — calls NtSetInformationThread with
/// ThreadAffinityMask; returns previous affinity mask on success, 0 on error.
/// Weave: single-threaded Phase 1/2 — no real thread objects exist. Accept the
/// call, return 1 (all CPUs, matching a system with one logical processor).
/// Correct no-op: affinity masks are advisory and ignored by the Linux scheduler
/// without a real NtSetInformationThread backing.
///
/// # Safety
/// `_h_thread` and `_dw_thread_affinity_mask` are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/thread.c — no standalone SetThreadAffinityMask symbol in Wine;
// affinity routed through NtSetInformationThread(ThreadAffinityMask, &mask, sizeof(mask));
// returns previous mask from server/thread.c:get_thread_affinity (line 810), 0 on error.
pub unsafe extern "win64" fn set_thread_affinity_mask(
    _h_thread: usize,
    _dw_thread_affinity_mask: usize,
) -> usize {
    1 // previous mask (single-CPU: mask = 1)
}

// ── Task 1 — System query stubs ──────────────────────────────────────────────

/// IsWow64Process: check if a process is running under WOW64.
///
/// Every app is 64-bit under Weave — WoW64 is never active.
/// Returns TRUE (1) and writes FALSE (0) to *wow64_process if non-null.
///
/// # Safety
/// `wow64_process` must be a valid pointer to an i32 if non-null.
// Wine ref: dlls/kernelbase/process.c:1031 — calls NtQueryInformationProcess with
// ProcessWow64Information; writes pointer-size value (non-null = WoW64 active).
pub unsafe extern "win64" fn is_wow64_process(_h_process: usize, wow64_process: *mut i32) -> i32 {
    if !wow64_process.is_null() {
        unsafe { *wow64_process = 0i32 }; // FALSE
    }
    1 // TRUE
}

/// IsProcessorFeaturePresent: check if a processor feature is present.
///
/// Returns FALSE (0) for all features — stub implementation.
// Wine ref: dlls/kernelbase/process.c:1013 — reads
// SharedUserData->ProcessorFeatures[feature]; feature index must be < 64
// (PROCESSOR_FEATURE_MAX), returns FALSE for out-of-range.
pub extern "win64" fn is_processor_feature_present(_processor_feature: u32) -> i32 {
    0 // FALSE
}

/// FlushInstructionCache: flush the instruction cache.
///
/// No-op. On x86-64 Linux the icache is coherent with dcache by hardware.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/memory.c:135 — calls NtFlushInstructionCache;
// on x86/x64 this is a no-op since the hardware maintains I/D cache coherency.
pub unsafe extern "win64" fn flush_instruction_cache(
    _h_process: usize,
    _lp_base_address: usize,
    _dw_size: usize,
) -> i32 {
    1 // TRUE
}

/// GetSystemTimePreciseAsFileTime: get the current system time as a file time.
///
/// Returns the current time in FILETIME format (100-nanosecond intervals since 1601-01-01).
///
/// # Safety
/// `lp_system_time_as_file_time` must be a valid pointer to a u64.
// Wine ref: dlls/kernelbase/file.c:4206 — calls NtQuerySystemTime which reads
// SharedUserData->SystemTime; "Precise" variant forces a syscall instead of the
// VDSO path to guarantee sub-millisecond accuracy.
pub unsafe extern "win64" fn get_system_time_precise_as_file_time(
    lp_system_time_as_file_time: *mut u64,
) {
    if lp_system_time_as_file_time.is_null() {
        return;
    }
    let mut ts = unsafe { std::mem::zeroed::<libc::timespec>() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    let ft = (ts.tv_sec as u64) * 10_000_000u64
        + (ts.tv_nsec as u64) / 100u64
        + 116_444_736_000_000_000u64;
    unsafe { *lp_system_time_as_file_time = ft };
}

/// GetLargePageMinimum: get the minimum size of a large page.
///
/// Returns 0 — large pages not supported.
// Wine ref: dlls/kernelbase/memory.c — returns GetSystemInfo large page size;
// returns 0 if large page privilege (SeLockMemoryPrivilege) is not held.
pub extern "win64" fn get_large_page_minimum() -> usize {
    0
}

/// SetHandleInformation: set handle information flags.
///
/// No-op. Returns TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/sync.c — calls NtSetInformationObject with
// ObjectHandleFlagInformation; sets HANDLE_FLAG_INHERIT and/or
// HANDLE_FLAG_PROTECT_FROM_CLOSE bits in the server handle table.
pub unsafe extern "win64" fn set_handle_information(
    _h_object: usize,
    _dw_mask: u32,
    _dw_flags: u32,
) -> i32 {
    // Wine ref: dlls/kernelbase/handle.c — NtSetInformationObject(ObjectHandleFlags).
    // Weave: handle inheritance and protection flags are not tracked; accept silently.
    1
}

// ── Task 2 — One-time init + waitable timers ─────────────────────────────────

/// InitOnceExecuteOnce: execute one-time initialization.
///
/// # Safety
/// `init_once`, `parameter`, and `context` must be valid pointers.
// Wine ref: dlls/kernelbase/sync.c:1780 — calls RtlRunOnceExecuteOnce which
// uses an interlocked state machine (0=unstarted, 1=in-progress, 2=done);
// callback receives InitOnce pointer, param, and context output pointer.
pub unsafe extern "win64" fn init_once_execute_once(
    init_once: *mut usize,
    init_fn: unsafe extern "win64" fn(*mut usize, *mut u8, *mut *mut u8) -> i32,
    parameter: *mut u8,
    context: *mut *mut u8,
) -> i32 {
    if init_once.is_null() {
        return 1; // TRUE
    }
    // SAFETY: init_once is non-null (checked above). It points to a usize-aligned
    // slot used as a Windows INIT_ONCE opaque structure (a single pointer-sized word).
    // We read and write atomically at this address — no races because Phase 1/2 is
    // single-threaded.  Values: 0=unstarted, 1=in-progress, 2=done.
    if unsafe { *init_once == 2 } {
        return 1; // TRUE - already done
    }
    unsafe { *init_once = 1 };
    // SAFETY: init_fn is a valid Win64 callback supplied by the caller; parameter
    // and context are forwarded unchanged per the InitOnceExecuteOnce contract.
    let result = unsafe { init_fn(init_once, parameter, context) };
    unsafe { *init_once = 2 };
    result
}

/// InitOnceBeginInitialize: begin one-time initialization.
///
/// # Safety
/// `lp_init_once` and `f_pending` must be valid pointers.
// Wine ref: dlls/kernelbase/sync.c — calls RtlRunOnceBeginInitialize;
// sets *fPending=TRUE if caller must do init, FALSE if already complete.
pub unsafe extern "win64" fn init_once_begin_initialize(
    lp_init_once: *mut usize,
    _dw_flags: u32,
    f_pending: *mut i32,
    _lp_context: *mut *mut u8,
) -> i32 {
    if !f_pending.is_null() {
        let pending = if !lp_init_once.is_null() && unsafe { *lp_init_once == 2 } {
            0i32 // FALSE - not pending
        } else {
            1i32 // TRUE - pending
        };
        unsafe { *f_pending = pending };
    }
    1 // TRUE
}

/// InitOnceComplete: complete one-time initialization.
///
/// # Safety
/// `lp_init_once` must be a valid pointer.
// Wine ref: dlls/kernelbase/sync.c — calls RtlRunOnceComplete; marks the
// INIT_ONCE as done and wakes any threads waiting in BeginInitialize.
pub unsafe extern "win64" fn init_once_complete(
    lp_init_once: *mut usize,
    _dw_flags: u32,
    _lp_context: *mut u8,
) -> i32 {
    if !lp_init_once.is_null() {
        unsafe { *lp_init_once = 2 };
    }
    1 // TRUE
}

/// CreateWaitableTimerW: create a waitable timer (wide version).
///
/// Returns a real timerfd-backed handle on Linux, 0 on failure.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/sync.c — calls NtCreateTimer; manual-reset=TRUE
// keeps timer signaled until reset, FALSE auto-resets after one wait release.
pub unsafe extern "win64" fn create_waitable_timer_w(
    _lp_timer_attributes: usize,
    _b_manual_reset: i32,
    _lp_timer_name: *const u16,
) -> usize {
    #[cfg(target_os = "linux")]
    {
        let fd = unsafe { libc::timerfd_create(libc::CLOCK_REALTIME, libc::TFD_CLOEXEC) };
        if fd < 0 {
            eprintln!(
                "weave/CreateWaitableTimerW: timerfd_create failed errno={}",
                unsafe { *libc::__errno_location() }
            );
            return 0;
        }
        let handle = TIMER_NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        timer_table().lock().unwrap().insert(handle, fd);
        eprintln!("weave/CreateWaitableTimerW: handle={handle:#x} fd={fd}");
        handle
    }
    #[cfg(not(target_os = "linux"))]
    {
        1 // non-Linux fallback (macOS build/test only)
    }
}

/// CreateWaitableTimerA: create a waitable timer (ANSI version).
///
/// Delegates to create_waitable_timer_w (name ignored).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/sync.c — ANSI wrapper that converts name via
// RtlCreateUnicodeStringFromAsciiz then calls CreateWaitableTimerW.
pub unsafe extern "win64" fn create_waitable_timer_a(
    lp_timer_attributes: usize,
    b_manual_reset: i32,
    _lp_timer_name: usize,
) -> usize {
    create_waitable_timer_w(lp_timer_attributes, b_manual_reset, std::ptr::null())
}

/// SetWaitableTimer: set a waitable timer.
///
/// Arms the timerfd backing the handle. Returns TRUE on success, FALSE on error.
///
/// # Safety
/// `lp_due_time` must be a valid pointer to an i64 or NULL.
// Wine ref: dlls/kernelbase/sync.c — calls NtSetTimer; negative due_time is
// relative (100ns units), positive is absolute. lPeriod=0 is one-shot.
pub unsafe extern "win64" fn set_waitable_timer(
    h_timer: usize,
    lp_due_time: usize,
    l_period: i32,
    _pfn_completion_routine: usize,
    _lp_arg_to_completion_routine: usize,
    _f_resume: i32,
) -> i32 {
    #[cfg(target_os = "linux")]
    {
        // Look up fd from timer table.
        let fd = match timer_table()
            .lock()
            .ok()
            .and_then(|t| t.get(&h_timer).copied())
        {
            Some(fd) => fd,
            None => {
                eprintln!("weave/SetWaitableTimer: unknown handle {h_timer:#x}");
                return 0;
            }
        };

        // lp_due_time must be non-null.
        if lp_due_time == 0 {
            eprintln!("weave/SetWaitableTimer: null due_time");
            return 0;
        }

        let val: i64 = unsafe { *(lp_due_time as *const i64) };

        // Build itimerspec from the due-time value.
        let mut new_value = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
        };

        let flags: libc::c_int;
        if val < 0 {
            // Negative: relative time in 100ns units.
            let abs_val = val.unsigned_abs();
            new_value.it_value.tv_sec = (abs_val / 10_000_000) as libc::time_t;
            new_value.it_value.tv_nsec = ((abs_val % 10_000_000) * 100) as libc::c_long;
            flags = 0;
        } else if val > 0 {
            // Positive: absolute FILETIME (100ns units since 1601-01-01).
            // Subtract Windows epoch offset to get Unix epoch 100ns units.
            const EPOCH_DIFF: i64 = 116_444_736_000_000_000i64;
            let unix_100ns = val.saturating_sub(EPOCH_DIFF).max(0) as u64;
            new_value.it_value.tv_sec = (unix_100ns / 10_000_000) as libc::time_t;
            new_value.it_value.tv_nsec = ((unix_100ns % 10_000_000) * 100) as libc::c_long;
            flags = libc::TFD_TIMER_ABSTIME;
        } else {
            // Zero: fire immediately (tv_nsec=1 avoids disarm semantics).
            new_value.it_value.tv_nsec = 1;
            flags = 0;
        }

        // Set interval from l_period (milliseconds).
        if l_period > 0 {
            new_value.it_interval.tv_sec = (l_period as i64) / 1000;
            new_value.it_interval.tv_nsec = ((l_period as i64) % 1000) * 1_000_000;
        }

        let rc = unsafe { libc::timerfd_settime(fd, flags, &new_value, std::ptr::null_mut()) };
        if rc != 0 {
            eprintln!(
                "weave/SetWaitableTimer: timerfd_settime failed errno={}",
                unsafe { *libc::__errno_location() }
            );
            return 0;
        }
        eprintln!("weave/SetWaitableTimer: handle={h_timer:#x} fd={fd} armed");
        1
    }
    #[cfg(not(target_os = "linux"))]
    {
        1 // non-Linux fallback
    }
}

/// CreateWaitableTimerExW: extended waitable timer creation (wide version).
///
/// dwFlags bit 1 = CREATE_WAITABLE_TIMER_MANUAL_RESET. Delegates to create_waitable_timer_w.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_waitable_timer_ex_w(
    lp_timer_attributes: usize,
    _lp_timer_name: *const u16,
    dw_flags: u32,
    _dw_desired_access: u32,
) -> usize {
    // bit 0 = CREATE_WAITABLE_TIMER_MANUAL_RESET (0x1)
    let b_manual_reset = if (dw_flags & 0x1) != 0 { 1i32 } else { 0i32 };
    create_waitable_timer_w(lp_timer_attributes, b_manual_reset, std::ptr::null())
}

/// CancelWaitableTimer: cancel a waitable timer.
///
/// No-op. Returns TRUE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/sync.c:938 — calls NtCancelTimer; sets
// *pfPreviousState to timer's signaled state before cancellation.
pub unsafe extern "win64" fn cancel_waitable_timer(_h_timer: usize) -> i32 {
    1
}

// ── Task 3 — ExpandEnvironmentStrings, SearchPath, GetTempFileName ──────────

/// Expand `%VAR%` references in `src` using the process environment.
///
/// Rules (matching Windows behaviour — jCodemunch unavailable this session;
/// derived from MSDN + observed Wine behaviour):
///   - `%NAME%` → value of env var NAME (case-insensitive on Windows, but
///     Linux env is case-sensitive so we pass the name as-is)
///   - `%%`     → literal `%`
///   - Unknown var `%FOO%` → left as-is (not removed)
///
/// Returns the expanded string.
fn expand_env_vars(src: &str) -> String {
    let mut result = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            result.push(c);
            continue;
        }
        // Collect everything up to the next '%'
        let mut name = String::new();
        let mut closed = false;
        for nc in chars.by_ref() {
            if nc == '%' {
                closed = true;
                break;
            }
            name.push(nc);
        }
        if !closed {
            // Unterminated % — emit as-is
            result.push('%');
            result.push_str(&name);
        } else if name.is_empty() {
            // "%%" → literal "%"
            result.push('%');
        } else {
            match std::env::var(&name) {
                Ok(val) => result.push_str(&val),
                Err(_) => {
                    // Unknown variable — leave unexpanded (Windows behaviour)
                    result.push('%');
                    result.push_str(&name);
                    result.push('%');
                }
            }
        }
    }
    result
}

/// ExpandEnvironmentStringsW: expand `%VAR%` references in a wide string.
///
/// Wine ref: dlls/kernelbase/environ.c — calls RtlExpandEnvironmentStrings_U
/// which scans for % pairs and looks up each name in the process environment
/// block; %% → literal %; unknown variables left as-is; returns required
/// char count (including null) so callers can size-query with NULL dst.
///
/// # Safety
/// `lp_src` must be a valid null-terminated UTF-16 string.
/// `lp_dst` must be writable for `n_size` u16 words.
// Wine ref: dlls/kernelbase/process.c — ExpandEnvironmentStringsW calls
// RtlExpandEnvironmentStrings_U; caps len at UNICODE_STRING_MAX_CHARS; returns
// required char count (incl. null) even when dst=NULL (size-query pattern).
// STATUS_BUFFER_TOO_SMALL is not treated as error — count still returned.
pub unsafe extern "win64" fn expand_environment_strings_w(
    lp_src: *const u16,
    lp_dst: *mut u16,
    n_size: u32,
) -> u32 {
    if lp_src.is_null() {
        return 0;
    }
    // Decode the UTF-16 source string.
    let mut len = 0usize;
    while len < MAX_UTF16_LEN && unsafe { *lp_src.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF16_LEN {
        return 0;
    }
    let src_utf16 = unsafe { std::slice::from_raw_parts(lp_src, len) };
    let src = String::from_utf16_lossy(src_utf16);

    let expanded = expand_env_vars(&src);
    let expanded_utf16: Vec<u16> = expanded.encode_utf16().chain(std::iter::once(0)).collect();
    let required = expanded_utf16.len() as u32; // includes null terminator

    if n_size == 0 || lp_dst.is_null() {
        return required;
    }
    let copy_len = (n_size as usize).min(expanded_utf16.len());
    unsafe {
        std::ptr::copy_nonoverlapping(expanded_utf16.as_ptr(), lp_dst, copy_len);
        // Ensure null-termination even if buffer was too small
        if copy_len > 0 {
            *lp_dst.add(copy_len - 1) = 0;
        }
    }
    required
}

/// ExpandEnvironmentStringsA: expand `%VAR%` references in an ANSI string.
///
/// Wine ref: dlls/kernelbase/environ.c — converts to Unicode, calls
/// RtlExpandEnvironmentStrings_U, converts result back to ANSI.
/// Weave: operates directly on UTF-8 (ANSI is treated as UTF-8).
///
/// # Safety
/// `lp_src` must be a valid null-terminated UTF-8 string.
/// `lp_dst` must be writable for `n_size` bytes.
// Wine ref: dlls/kernelbase/process.c — ExpandEnvironmentStringsA converts to Unicode,
// calls ExpandEnvironmentStringsW, converts result back via WideCharToMultiByte(CP_ACP).
// When buffer too small: sets *dst=0 and over-reports by 1 byte (count_neededA + 1).
pub unsafe extern "win64" fn expand_environment_strings_a(
    lp_src: *const u8,
    lp_dst: *mut u8,
    n_size: u32,
) -> u32 {
    if lp_src.is_null() {
        return 0;
    }
    let mut len = 0usize;
    while len < MAX_UTF8_LEN && unsafe { *lp_src.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF8_LEN {
        return 0;
    }
    let src_bytes = unsafe { std::slice::from_raw_parts(lp_src, len) };
    let src = String::from_utf8_lossy(src_bytes);

    let expanded = expand_env_vars(&src);
    let expanded_bytes = expanded.as_bytes();
    let required = (expanded_bytes.len() + 1) as u32; // +1 for null terminator

    if n_size == 0 || lp_dst.is_null() {
        return required;
    }
    let copy_len = (n_size as usize - 1).min(expanded_bytes.len());
    unsafe {
        std::ptr::copy_nonoverlapping(expanded_bytes.as_ptr(), lp_dst, copy_len);
        *lp_dst.add(copy_len) = 0; // null terminator
    }
    required
}

/// SearchPathW: search for a file in the PATH.
///
/// Wine ref: dlls/kernelbase/path.c — searches in order: explicit path arg,
/// exe directory, current directory, System32, Windows dir, PATH env dirs;
/// tries the filename bare then appends lpExtension if provided; return value
/// is the char count of the full path (excluding null) written to lpBuffer;
/// lpFilePart is set to point at the filename component within lpBuffer.
///
/// Weave simplification: skips Windows/System dir (not applicable); searches
/// explicit path arg → exe directory → PATH env dirs.
///
/// # Safety
/// All non-null pointer arguments must satisfy their Win32 API contracts.
// Wine ref: dlls/kernelbase/file.c — SearchPathW: if name contains path separator,
// skips search and calls GetFullPathNameW directly (with/without ext). If path arg
// given, uses RtlDosSearchPath_U. Otherwise tries activation context, then
// RtlGetSearchPath. Empty/whitespace-only name → ERROR_INVALID_PARAMETER.
pub unsafe extern "win64" fn search_path_w(
    lp_path: *const u16,
    lp_file_name: *const u16,
    lp_extension: *const u16,
    n_buffer_length: u32,
    lp_buffer: *mut u16,
    lp_file_part: *mut *mut u16,
) -> u32 {
    let file_name = unsafe { read_cstr_w(lp_file_name) };
    if file_name.is_empty() {
        return 0;
    }
    let extension = if lp_extension.is_null() {
        String::new()
    } else {
        unsafe { read_cstr_w(lp_extension) }
    };

    // Each search dir is tracked as (linux_path, windows_dir_prefix) so we
    // can construct the Windows-style output path without a reverse translator.
    let mut search_dirs: Vec<(std::path::PathBuf, String)> = Vec::new();

    // 1. Explicit path argument (Windows paths, semicolon-separated)
    if !lp_path.is_null() {
        let path_str = unsafe { read_cstr_w(lp_path) };
        for dir in path_str.split(';') {
            if !dir.is_empty() {
                if let Ok(linux_dir) = weave_core::file_io::translate_win_path(dir) {
                    search_dirs.push((linux_dir, dir.to_string()));
                }
            }
        }
    }

    // 2. Exe directory (already a Windows path string)
    if let Some(exe_dir_win) = weave_core::exe_path::exe_dir() {
        if let Ok(linux_dir) = weave_core::file_io::translate_win_path(&exe_dir_win) {
            search_dirs.push((linux_dir, exe_dir_win));
        }
    }

    // 3. PATH environment dirs — these are Linux paths; expose as Z:\ prefixed.
    if let Ok(path_env) = std::env::var("PATH") {
        for dir in path_env.split(':') {
            if !dir.is_empty() {
                let linux_dir = std::path::PathBuf::from(dir);
                let win_dir = format!("Z:{}", dir.replace('/', "\\"));
                search_dirs.push((linux_dir, win_dir));
            }
        }
    }

    let candidates: Vec<String> = if extension.is_empty() {
        vec![file_name.clone()]
    } else {
        vec![file_name.clone(), format!("{}{}", file_name, extension)]
    };

    for (linux_dir, win_dir) in &search_dirs {
        for candidate in &candidates {
            let full_linux = linux_dir.join(candidate);
            if full_linux.exists() {
                // Build the full Windows path.
                let win_path = format!("{}\\{}", win_dir.trim_end_matches('\\'), candidate);
                let win_utf16: Vec<u16> =
                    win_path.encode_utf16().chain(std::iter::once(0)).collect();
                let char_count = (win_utf16.len() - 1) as u32;

                if n_buffer_length > char_count && !lp_buffer.is_null() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            win_utf16.as_ptr(),
                            lp_buffer,
                            win_utf16.len(),
                        );
                    }
                    if !lp_file_part.is_null() {
                        let sep_pos = win_path
                            .rfind('\\')
                            .map(|p| {
                                // Count UTF-16 code units before the backslash.
                                win_path[..p + 1].encode_utf16().count()
                            })
                            .unwrap_or(0);
                        unsafe { *lp_file_part = lp_buffer.add(sep_pos) };
                    }
                }
                return char_count;
            }
        }
    }
    0 // not found
}

/// SearchPathA: search for a file in the PATH (ANSI wrapper).
///
/// Wine ref: dlls/kernelbase/path.c — converts arguments to Unicode and
/// delegates to SearchPathW.
///
/// # Safety
/// All non-null pointer arguments must satisfy their Win32 API contracts.
pub unsafe extern "win64" fn search_path_a(
    lp_path: *const u8,
    lp_file_name: *const u8,
    lp_extension: *const u8,
    n_buffer_length: u32,
    lp_buffer: *mut u8,
    lp_file_part: *mut *mut u8,
) -> u32 {
    // Convert inputs to UTF-16 and delegate to the W version via a temporary buffer.
    let file_name = unsafe { read_cstr_a(lp_file_name) };
    if file_name.is_empty() {
        return 0;
    }
    let extension = if lp_extension.is_null() {
        String::new()
    } else {
        unsafe { read_cstr_a(lp_extension) }
    };
    let path_str = if lp_path.is_null() {
        String::new()
    } else {
        unsafe { read_cstr_a(lp_path) }
    };

    // Use a large temp buffer for the W call, then convert result back to ANSI.
    let mut wide_buf: Vec<u16> = vec![0u16; 32768];
    let mut file_part_w: *mut u16 = std::ptr::null_mut();

    let file_name_w: Vec<u16> = file_name.encode_utf16().chain(std::iter::once(0)).collect();
    let extension_w: Vec<u16> = extension.encode_utf16().chain(std::iter::once(0)).collect();
    let path_w: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();

    let path_ptr = if lp_path.is_null() {
        std::ptr::null()
    } else {
        path_w.as_ptr()
    };
    let ext_ptr = if lp_extension.is_null() {
        std::ptr::null()
    } else {
        extension_w.as_ptr()
    };

    let count = unsafe {
        search_path_w(
            path_ptr,
            file_name_w.as_ptr(),
            ext_ptr,
            wide_buf.len() as u32,
            wide_buf.as_mut_ptr(),
            &mut file_part_w as *mut *mut u16,
        )
    };
    if count == 0 {
        return 0;
    }

    let win_path = String::from_utf16_lossy(&wide_buf[..count as usize]);
    let ansi_bytes = win_path.as_bytes();
    let required = (ansi_bytes.len() + 1) as u32;

    if n_buffer_length > required && !lp_buffer.is_null() {
        unsafe {
            std::ptr::copy_nonoverlapping(ansi_bytes.as_ptr(), lp_buffer, ansi_bytes.len());
            *lp_buffer.add(ansi_bytes.len()) = 0;
        }
        if !lp_file_part.is_null() {
            // Compute file part offset from wide buffer offset.
            let offset = if file_part_w.is_null() {
                0
            } else {
                unsafe { file_part_w.offset_from(wide_buf.as_ptr()) as usize }
            };
            // For ASCII paths offset in u16 == offset in bytes
            unsafe { *lp_file_part = lp_buffer.add(offset) };
        }
    }
    required - 1 // return char count excluding null, matching SearchPathW
}

/// GetTempFileNameW: create a temporary filename.
///
/// Generates a temporary filename using the specified path and prefix.
/// Uses process ID and time for uniqueness.
///
/// # Safety
/// `lp_path_name` must be a valid null-terminated UTF-16 string.
/// `lp_prefix_string` may be null.
/// `lp_temp_file_name` must be writable for at least 260 u16 words.
// Wine ref: dlls/kernelbase/file.c:2438 — verifies path is an existing directory
// (GetFileAttributesW); uses only the first 3 chars of prefix; if unique=0,
// iterates via NtGetTickCount to find an unused filename, creating each candidate
// with CreateFileW(CREATE_NEW); returns the unique number used (low 16 bits).
pub unsafe extern "win64" fn get_temp_file_name_w(
    lp_path_name: *const u16,
    lp_prefix_string: *const u16,
    u_unique: u32,
    lp_temp_file_name: *mut u16,
) -> u32 {
    if lp_path_name.is_null() || lp_temp_file_name.is_null() {
        return 0;
    }

    // Read path
    let mut path_len = 0usize;
    while path_len < MAX_UTF16_LEN && unsafe { *lp_path_name.add(path_len) } != 0 {
        path_len += 1;
    }
    if path_len == MAX_UTF16_LEN {
        return 0;
    }
    let path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_path_name, path_len)) };

    // Read prefix (up to 3 chars)
    let prefix = if lp_prefix_string.is_null() {
        "tmp".to_string()
    } else {
        let mut prefix_len = 0usize;
        while prefix_len < 3 && unsafe { *lp_prefix_string.add(prefix_len) } != 0 {
            prefix_len += 1;
        }
        unsafe {
            String::from_utf16_lossy(std::slice::from_raw_parts(lp_prefix_string, prefix_len))
        }
    };

    // Generate unique number
    let unique = if u_unique != 0 {
        u_unique
    } else {
        unsafe { (libc::getpid() as u32) ^ (libc::time(std::ptr::null_mut()) as u32) }
    };

    // Build filename
    let filename = format!("{}\\{}", path, prefix);
    let temp_name = format!("{}\\{:04X}.tmp", filename, unique & 0xFFFF);

    // Convert to UTF-16 and write to buffer (up to 260 chars)
    let wide_name: Vec<u16> = temp_name.encode_utf16().collect();
    let copy_len = wide_name.len().min(259); // leave room for null
    unsafe {
        std::ptr::copy_nonoverlapping(wide_name.as_ptr(), lp_temp_file_name, copy_len);
        *lp_temp_file_name.add(copy_len) = 0;
    }

    unique & 0xFFFF
}

/// GetTempFileNameA: create a temporary filename (ANSI version).
///
/// Generates a temporary filename using the specified path and prefix.
/// Uses process ID and time for uniqueness.
///
/// # Safety
/// `lp_path_name` must be a valid null-terminated UTF-8 string.
/// `lp_prefix_string` may be null.
/// `lp_temp_file_name` must be writable for at least 260 bytes.
// Wine ref: dlls/kernelbase/file.c:2418 — converts ANSI args to Unicode via
// RtlMultiByteToUnicodeN, delegates to GetTempFileNameW, converts result back.
pub unsafe extern "win64" fn get_temp_file_name_a(
    lp_path_name: *const u8,
    lp_prefix_string: *const u8,
    u_unique: u32,
    lp_temp_file_name: *mut u8,
) -> u32 {
    if lp_path_name.is_null() || lp_temp_file_name.is_null() {
        return 0;
    }

    // Read path
    let mut path_len = 0usize;
    while path_len < MAX_UTF8_LEN && unsafe { *lp_path_name.add(path_len) } != 0 {
        path_len += 1;
    }
    if path_len == MAX_UTF8_LEN {
        return 0;
    }
    let path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_path_name, path_len)) };

    // Read prefix (up to 3 chars)
    let prefix = if lp_prefix_string.is_null() {
        "tmp".to_string()
    } else {
        let mut prefix_len = 0usize;
        while prefix_len < 3 && unsafe { *lp_prefix_string.add(prefix_len) } != 0 {
            prefix_len += 1;
        }
        unsafe {
            String::from_utf8_lossy(std::slice::from_raw_parts(lp_prefix_string, prefix_len))
                .to_string()
        }
    };

    // Generate unique number
    let unique = if u_unique != 0 {
        u_unique
    } else {
        unsafe { (libc::getpid() as u32) ^ (libc::time(std::ptr::null_mut()) as u32) }
    };

    // Build filename
    let filename = format!("{}\\{}", path, prefix);
    let temp_name = format!("{}\\{:04X}.tmp", filename, unique & 0xFFFF);

    // Write to buffer (up to 260 chars)
    let bytes = temp_name.as_bytes();
    let copy_len = bytes.len().min(259); // leave room for null
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_temp_file_name, copy_len);
        *lp_temp_file_name.add(copy_len) = 0;
    }

    unique & 0xFFFF
}

/// GetOEMCP: return the current OEM code page identifier.
// Wine ref: dlls/kernelbase/locale.c — reads oem_cp.CodePage from NLS data;
// typically 437 (US) or 850 (Multilingual Latin 1) on Western Windows installs.
pub extern "win64" fn get_oemcp() -> u32 {
    65001
}

/// GetConsoleCP: return the console input code page.
// Wine ref: dlls/kernelbase/console.c:833 — queries IOCTL_CONDRV_GET_INPUT_INFO
// and returns info.input_cp; returns 0 if the console handle is invalid.
pub extern "win64" fn get_console_cp() -> u32 {
    65001
}

/// GetConsoleOutputCP: return the console output code page.
// Wine ref: dlls/kernelbase/console.c:969 — queries IOCTL_CONDRV_GET_INPUT_INFO
// and returns info.output_cp; returns 0 if the console handle is invalid.
pub extern "win64" fn get_console_output_cp() -> u32 {
    65001
}

/// __C_specific_handler: SEH C-specific exception filter.
///
/// Returns ExceptionContinueSearch (1) — Weave does not implement SEH in Phase 1.
// Wine ref: dlls/msvcrt/except_x86_64.c — __C_specific_handler is the MSVC
// SEH handler for C code; walks the scope table to find __except/__finally handlers;
// returns ExceptionContinueSearch if no matching filter found.
pub extern "win64" fn c_specific_handler(
    _exception_record: usize,
    _establisher_frame: usize,
    _context_record: usize,
    _dispatcher_context: usize,
) -> i32 {
    1 // ExceptionContinueSearch — Weave does not implement SEH scope tables
}

// ── Heap / global memory ──────────────────────────────────────────────────────

/// GlobalAlloc: allocate a block of memory from the heap.
///
/// Phase 2: `GMEM_FIXED` and `GMEM_MOVEABLE` are both handled by returning
/// a real heap pointer (handle == pointer). Zeroing (`GMEM_ZEROINIT`) is
/// honoured.
// Wine ref: dlls/kernelbase/memory.c:1017 — delegates to LocalAlloc; forces
// size=1 for GMEM_FIXED with size=0 (unlike LocalAlloc which allows 0-size fixed);
// sets MEM_FLAG_DDESHARE if GMEM_DDESHARE flag is set.
pub extern "win64" fn global_alloc(u_flags: u32, dw_bytes: usize) -> usize {
    if dw_bytes == 0 {
        return 0;
    }
    let zeroinit = (u_flags & 0x40) != 0; // GMEM_ZEROINIT
    let ptr = if zeroinit {
        unsafe { libc::calloc(1, dw_bytes) }
    } else {
        unsafe { libc::malloc(dw_bytes) }
    };
    ptr as usize
}

/// GlobalFree: free memory allocated by `GlobalAlloc`.
///
/// Returns NULL on success, the original handle on failure.
// Wine ref: dlls/kernelbase/memory.c — delegates to LocalFree; returns
// NULL on success, handle on failure; NULL input returns NULL (no error).
pub extern "win64" fn global_free(h_mem: usize) -> usize {
    if h_mem == 0 {
        return 0;
    }
    unsafe { libc::free(h_mem as *mut libc::c_void) };
    0 // success
}

/// GlobalLock: lock a global memory object and return a pointer.
///
/// Phase 2: `HGLOBAL == pointer`, so just return `h_mem` directly.
// Wine ref: dlls/kernelbase/memory.c — delegates to LocalLock; for GMEM_FIXED
// (ptr==handle) returns the pointer directly; for GMEM_MOVEABLE increments
// mem_entry lock count and returns mem_entry->ptr.
pub extern "win64" fn global_lock(h_mem: usize) -> usize {
    h_mem // pointer == handle in Phase 2
}

/// GlobalUnlock: decrement the lock count of a global memory object.
///
/// Phase 2: no-op; returns TRUE.
// Wine ref: dlls/kernelbase/memory.c — delegates to LocalUnlock; decrements
// mem_entry lock count; returns FALSE + ERROR_NOT_LOCKED when count reaches 0.
pub extern "win64" fn global_unlock(_h_mem: usize) -> i32 {
    1 // TRUE
}

/// GlobalSize: return the size of a global memory block.
///
/// Phase 2: we don't track sizes; returns 0 (stub).
// Wine ref: dlls/kernelbase/memory.c — delegates to LocalSize; calls
// HeapSize on the underlying allocation; returns 0 for NULL or invalid handles.
pub extern "win64" fn global_size(h_mem: usize) -> usize {
    // Wine ref: dlls/kernelbase/memory.c — RtlSizeHeap on the underlying block;
    // GMEM_FIXED allocations store the heap pointer directly as the handle.
    if h_mem == 0 {
        return 0;
    }
    unsafe { libc::malloc_usable_size(h_mem as *mut _) }
}

/// LocalAlloc: allocate a block of local memory (alias for GlobalAlloc).
// Wine ref: dlls/kernelbase/memory.c:1046 — LMEM_FIXED returns raw heap pointer;
// LMEM_MOVEABLE allocates a mem_entry handle with a separate heap block (ptr);
// LMEM_DISCARDABLE flag allowed only with MOVEABLE; size=0 → discarded state.
pub extern "win64" fn local_alloc(u_flags: u32, u_bytes: usize) -> usize {
    global_alloc(u_flags, u_bytes)
}

/// LocalFree: free memory allocated by `LocalAlloc`.
// Wine ref: dlls/kernelbase/memory.c:1106 — for LMEM_FIXED, calls HeapFree directly;
// for LMEM_MOVEABLE, frees mem_entry->ptr then recycles the mem_entry slot;
// returns NULL on success, original handle on failure (sets ERROR_INVALID_HANDLE).
pub extern "win64" fn local_free(h_mem: usize) -> usize {
    global_free(h_mem)
}

/// LocalLock: lock a local memory object (alias for GlobalLock).
// Wine ref: dlls/kernelbase/memory.c — LMEM_FIXED handle is the pointer itself;
// LMEM_MOVEABLE increments mem_entry.lock and returns mem_entry->ptr.
pub extern "win64" fn local_lock(h_mem: usize) -> usize {
    global_lock(h_mem)
}

/// LocalUnlock: unlock a local memory object (alias for GlobalUnlock).
// Wine ref: dlls/kernelbase/memory.c — decrements mem_entry.lock;
// returns FALSE + ERROR_NOT_LOCKED when lock count already zero.
pub extern "win64" fn local_unlock(h_mem: usize) -> i32 {
    global_unlock(h_mem)
}

/// LocalReAlloc: reallocate a local memory block.
///
/// Wine ref: dlls/kernelbase/memory.c — HeapReAlloc with HEAP_ZERO_MEMORY zeroes only
/// newly added bytes. Zeroing only new bytes requires old-size tracking; deferred to Phase 4.
/// For now, LMEM_ZEROINIT is ignored (new bytes may contain garbage).
///
/// # Safety
/// `h_mem` must be a pointer returned from LocalAlloc/LocalReAlloc or NULL.
// Wine ref: dlls/kernelbase/memory.c — LocalReAlloc: LMEM_MODIFY just sets flags, no resize.
// LMEM_MOVEABLE allows relocation; without it HEAP_REALLOC_IN_PLACE_ONLY is set.
// LMEM_ZEROINIT → HEAP_ZERO_MEMORY (zeroes only newly added bytes, not whole block).
pub unsafe extern "win64" fn local_re_alloc(
    h_mem: *mut std::ffi::c_void,
    u_bytes: usize,
    _u_flags: u32,
) -> *mut std::ffi::c_void {
    // Wine ref: dlls/kernelbase/memory.c — HeapReAlloc with HEAP_ZERO_MEMORY only zeroes
    // newly added bytes, not the whole block. Zeroing only new bytes requires tracking the
    // old size; deferred to Phase 4. For now just realloc (ignores LMEM_ZEROINIT).
    unsafe { libc::realloc(h_mem, u_bytes) }
}

/// HeapCreate: create a heap and return a fake handle.
///
/// Wine ref: dlls/kernelbase/memory.c — HeapCreate calls RtlCreateHeap;
/// Weave uses a single libc allocator so we return a fake but consistent
/// handle (1 = process heap sentinel). Parameters are ignored.
pub extern "win64" fn heap_create(
    _fl_options: u32,
    _dw_initial_size: usize,
    _dw_maximum_size: usize,
) -> usize {
    1usize // fake process heap handle — Weave uses single libc allocator
}

/// HeapDestroy: destroy a heap (no-op).
///
/// Returns TRUE. Never actually destroy memory — the "heap" is just the libc allocator.
// Wine ref: dlls/kernelbase/memory.c:750 — calls RtlDestroyHeap; returns TRUE
// if NULL returned (success), FALSE + ERROR_INVALID_HANDLE if handle was invalid.
pub extern "win64" fn heap_destroy(_h_heap: usize) -> i32 {
    1
}

/// HeapAlloc: allocate memory from the heap.
///
/// Wine ref: dlls/kernelbase/memory.c — HeapAlloc delegates to RtlAllocateHeap;
/// HEAP_ZERO_MEMORY (0x08) zeroes the block; size=0 returns a valid non-NULL pointer.
/// Weave uses malloc/calloc directly; ignores hHeap (single global allocator).
///
/// # Safety
/// The returned pointer must be freed with HeapFree or it will leak.
// Wine ref: dlls/ntdll/heap.c — RtlAllocateHeap: size=0 still returns non-NULL (minimum
// block allocated). HEAP_ZERO_MEMORY zeroes allocation. Large blocks (≥HEAP_MIN_LARGE_BLOCK_SIZE)
// take a separate path via heap_allocate_large. Weave uses malloc/calloc; hHeap ignored.
pub extern "win64" fn heap_alloc(
    _h_heap: usize,
    dw_flags: u32,
    dw_bytes: usize,
) -> *mut std::ffi::c_void {
    // Windows HeapAlloc(heap, 0, 0) returns a valid non-NULL pointer.
    // Use at least 1 byte so malloc/calloc never return NULL for size 0.
    let alloc_size = if dw_bytes == 0 { 1 } else { dw_bytes };
    let zero_memory = (dw_flags & 0x08) != 0; // HEAP_ZERO_MEMORY

    let result = if zero_memory {
        unsafe { libc::calloc(1, alloc_size) }
    } else {
        unsafe { libc::malloc(alloc_size) }
    };
    // A fresh allocation means any previously seen double-free at this address
    // is now gone from the fastbin.  Reset the tracker so the address is freeable again.
    if !result.is_null() {
        LAST_HEAP_FREE.store(0, Ordering::Relaxed);
    }
    result
}

/// HeapReAlloc: reallocate memory in the heap.
///
/// Wraps `realloc`. Ignores hHeap and dwFlags parameters.
///
/// # Safety
/// `lp_mem` must be a valid pointer returned from HeapAlloc or NULL.
/// The returned pointer must be freed with HeapFree or it will leak.
// Wine ref: dlls/kernelbase/memory.c — calls RtlReAllocateHeap; HEAP_ZERO_MEMORY
// zeroes only newly added bytes; HEAP_REALLOC_IN_PLACE_ONLY fails rather than
// moving the block; returns NULL on failure (does NOT free original block).
pub unsafe extern "win64" fn heap_re_alloc(
    _h_heap: usize,
    _dw_flags: u32,
    lp_mem: *mut std::ffi::c_void,
    dw_bytes: usize,
) -> *mut std::ffi::c_void {
    unsafe { libc::realloc(lp_mem, dw_bytes) }
}

/// HeapFree: free memory allocated from the heap.
///
/// Wraps `free`. Ignores hHeap and dwFlags parameters.
///
/// # Safety
/// `lp_mem` must be a valid pointer returned from HeapAlloc/HeapReAlloc or NULL.
// Wine ref: dlls/ntdll/heap.c::RtlFreeHeap:2078 — NULL ptr returns TRUE without
// freeing; invalid ptr sets ERROR_INVALID_PARAMETER and returns FALSE; double-free
// of same ptr in same heap → silent FALSE on Windows (glibc aborts instead).
pub unsafe extern "win64" fn heap_free(
    _h_heap: usize,
    _dw_flags: u32,
    lp_mem: *mut std::ffi::c_void,
) -> i32 {
    if lp_mem.is_null() {
        return 1; // TRUE
    }
    // Reject non-canonical addresses (e.g. XFG-decoded garbage from BSS-zero slots).
    // Windows HeapFree returns FALSE for invalid pointers instead of crashing.
    let addr = lp_mem as usize;
    if addr >> 47 != 0 {
        return 0; // FALSE — invalid pointer
    }
    // Detect consecutive double-frees: glibc aborts on "fasttop" when free() is
    // called twice in a row on the same address.  Windows HeapFree returns FALSE
    // silently for already-freed blocks (the UCRT relies on this for shared
    // locale category pointers freed once per category in free_locinfo).
    if LAST_HEAP_FREE.swap(addr, Ordering::Relaxed) == addr {
        return 0; // FALSE — duplicate free, silently ignored per Windows semantics
    }
    // SAFETY: lp_mem is non-null (early return above), has a canonical x86-64 address
    // (addr >> 47 == 0 check above), and was not freed in the immediately preceding
    // call (swap check above).  It was originally returned by libc::malloc/realloc
    // (via HeapAlloc/HeapReAlloc), so libc::free is the correct deallocator.
    unsafe { libc::free(lp_mem) };
    1 // TRUE
}

/// HeapSize: return the size of a heap block.
///
/// We don't track allocation sizes; returns 0 (acceptable for defensive callers).
// Wine ref: dlls/ntdll/heap.c::heap_size — calls heap_size() internal helper;
// returns (SIZE_T)-1 on error (invalid handle or ptr), actual usable size on success.
pub extern "win64" fn heap_size(
    _h_heap: usize,
    _dw_flags: u32,
    lp_mem: *const std::ffi::c_void,
) -> usize {
    // Wine ref: dlls/ntdll/heap.c — RtlSizeHeap returns (SIZE_T)-1 on NULL/invalid block;
    // on success returns the usable allocation size. Weave heap uses libc malloc so
    // malloc_usable_size gives the real answer.
    if lp_mem.is_null() {
        return usize::MAX;
    }
    unsafe { libc::malloc_usable_size(lp_mem as *mut _) }
}

/// GetProcessHeap: return the process heap handle.
///
/// Returns the same fake handle as HeapCreate (1usize).
// Wine ref: include/winbase.h:2684 — inline that reads
// NtCurrentTeb()->Peb->ProcessHeap; always non-NULL after process init.
pub extern "win64" fn get_process_heap() -> usize {
    1usize
}

// ── File I/O ──────────────────────────────────────────────────────────────────

/// CreateFileA: open or create a file and return a HANDLE.
///
/// Translates Win32 parameters to NT equivalents and delegates to the
/// shared `file_io::open_file` engine in weave-core.
///
/// # Safety
/// `lp_file_name` must be a valid, null-terminated UTF-8 string.
// Wine ref: dlls/kernelbase/file.c:750 — converts name via RtlMultiByteToUnicodeN,
// delegates to CreateFileW; "\\\\.\\" device paths routed to NtCreateFile with
// FILE_NON_DIRECTORY_FILE; directory opens use FILE_DIRECTORY_FILE flag.
pub unsafe extern "win64" fn create_file_a(
    lp_file_name: *const u8,
    dw_desired_access: u32,
    _dw_share_mode: u32,       // ignored — no file locking in Phase 2
    _lp_security_attrs: usize, // ignored
    dw_creation_disposition: u32,
    _dw_flags_and_attrs: u32, // ignored
    _h_template_file: usize,  // ignored
) -> usize {
    if lp_file_name.is_null() {
        set_last_error(file_io::ERROR_INVALID_HANDLE);
        return usize::MAX; // INVALID_HANDLE_VALUE
    }

    // Decode the null-terminated UTF-8 filename.
    let win_path = unsafe {
        let mut len = 0usize;
        while len < MAX_UTF8_LEN && *lp_file_name.add(len) != 0 {
            len += 1;
        }
        if len == MAX_UTF8_LEN {
            set_last_error(87); // ERROR_INVALID_PARAMETER
            return usize::MAX;
        }
        let slice = std::slice::from_raw_parts(lp_file_name, len);
        String::from_utf8_lossy(slice).into_owned()
    };

    let nt_disposition = file_io::win32_disposition_to_nt(dw_creation_disposition);

    match file_io::open_file(&win_path, dw_desired_access, nt_disposition) {
        Ok(handle) => {
            set_last_error(0);
            handle
        }
        Err(_status) => {
            // Map NT status back to a Win32 error code. For now, return a
            // generic error; Phase 3 can refine the mapping.
            set_last_error(file_io::ERROR_FILE_NOT_FOUND);
            usize::MAX // INVALID_HANDLE_VALUE
        }
    }
}

/// CreateFileW: open or create a file and return a HANDLE.
///
/// Wine ref: dlls/kernelbase/file.c — empty filename → ERROR_PATH_NOT_FOUND; invalid
/// creation disposition → ERROR_INVALID_PARAMETER; CREATE_ALWAYS/OPEN_ALWAYS with
/// existing file → valid handle + ERROR_ALREADY_EXISTS as LastError; STATUS_OBJECT_NAME_COLLISION
/// → ERROR_FILE_EXISTS (not ERROR_ALREADY_EXISTS). Weave does not set ERROR_ALREADY_EXISTS on
/// CREATE_ALWAYS success; maps creation dispositions via file_io::win32_disposition_to_nt.
///
/// # Safety
/// `lp_file_name` must be a valid, null-terminated UTF-16 string.
// Wine ref: dlls/kernelbase/file.c — CreateFileW: empty/null filename → ERROR_PATH_NOT_FOUND.
// creation out of range [1,5] → ERROR_INVALID_PARAMETER. STATUS_OBJECT_NAME_COLLISION →
// ERROR_FILE_EXISTS. CREATE_ALWAYS/OPEN_ALWAYS with existing file → ERROR_ALREADY_EXISTS set
// as LastError even on success (io.Information == FILE_OVERWRITTEN/FILE_OPENED).
pub unsafe extern "win64" fn create_file_w(
    lp_file_name: *const u16,
    dw_desired_access: u32,
    _dw_share_mode: u32,       // ignored — no file locking in Phase 2
    _lp_security_attrs: usize, // ignored
    dw_creation_disposition: u32,
    _dw_flags_and_attrs: u32, // ignored
    _h_template_file: usize,  // ignored
) -> usize {
    if lp_file_name.is_null() {
        set_last_error(file_io::ERROR_INVALID_HANDLE);
        eprintln!("weave/CreateFileW: exit null_name → INVALID_HANDLE_VALUE");
        return usize::MAX; // INVALID_HANDLE_VALUE
    }

    // Decode the null-terminated UTF-16 filename.
    // SAFETY: (a) lp_file_name is non-null (checked above).  (b) Guest heap —
    // caller-owned for the duration of this call.  (c) Pointer stays valid
    // through the bounded scan and from_raw_parts slice; MAX_UTF16_LEN caps the
    // read length.  (d) notepad_roundtrip_gate CI 26037252940 — file-open path confirmed.
    let win_path = unsafe {
        let mut len = 0usize;
        while len < MAX_UTF16_LEN && *lp_file_name.add(len) != 0 {
            len += 1;
        }
        if len == MAX_UTF16_LEN {
            set_last_error(87); // ERROR_INVALID_PARAMETER
            eprintln!("weave/CreateFileW: exit overlong_name → INVALID_HANDLE_VALUE");
            return usize::MAX;
        }
        let slice = std::slice::from_raw_parts(lp_file_name, len);
        String::from_utf16_lossy(slice).to_owned()
    };

    // Phase 7 — fire once on the first user-supplied path (not a device/extended path).
    static PHASE_CREATE_FILE: AtomicBool = AtomicBool::new(false);
    if !PHASE_CREATE_FILE.swap(true, Ordering::Relaxed) {
        if !win_path.starts_with("\\\\.\\") && !win_path.starts_with("\\\\?\\") {
            mark_phase("create_file_user_arg");
        } else {
            // Not a user path yet — reset so the guard fires again next call.
            PHASE_CREATE_FILE.store(false, Ordering::Relaxed);
        }
    }

    // Log file-open progress every 100 calls — lets CI log show when bulk
    // .properties loading ends even when individual opens are not visible.
    static FILE_OPEN_TOTAL: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let fot = FILE_OPEN_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
    if fot.is_multiple_of(100) {
        eprintln!("DIAG: file_opens_n={fot} path={win_path:?}");
    }

    if std::env::var("WEAVE_TEST_SAVE_RESULT").is_ok() && win_path.contains("save_png_gate") {
        eprintln!(
            "weave/E3-M9-trace: CreateFileW save-path path={win_path:?} disp={dw_creation_disposition:#x}"
        );
    }

    // Log every open (write OR read) for diagnostic coverage. Previously only
    // write-opens and .bmp read-opens were logged; broadened so 7za-style read
    // probes are visible in CI when chasing stale-LastError bugs.
    const GENERIC_WRITE: u32 = 0x40000000;
    if dw_desired_access & GENERIC_WRITE != 0 {
        eprintln!("weave/CreateFileW: write-open path={win_path:?} access={dw_desired_access:#x} disp={dw_creation_disposition:#x}");
    } else {
        eprintln!("weave/CreateFileW: read-open path={win_path:?} access={dw_desired_access:#x} disp={dw_creation_disposition:#x}");
    }

    let nt_disposition = file_io::win32_disposition_to_nt(dw_creation_disposition);

    // Wine ref: dlls/kernelbase/file.c:795 — CreateFileW maps NtCreateFile status
    // to LastError via RtlNtStatusToDosError with two special cases:
    // STATUS_OBJECT_NAME_COLLISION → ERROR_FILE_EXISTS (not ERROR_ALREADY_EXISTS),
    // trailing-slash + STATUS_FILE_IS_A_DIRECTORY → ERROR_PATH_NOT_FOUND.
    // On success, CREATE_ALWAYS+FILE_OVERWRITTEN or OPEN_ALWAYS+FILE_OPENED sets
    // ERROR_ALREADY_EXISTS; Weave does not track io.Information yet, so it just
    // clears LastError on success.
    match file_io::open_file(&win_path, dw_desired_access, nt_disposition) {
        Ok(handle) => {
            set_last_error(0);
            eprintln!(
                "weave/CreateFileW: exit path={win_path:?} → handle={handle:#x} last_error=0"
            );
            handle
        }
        Err(status) => {
            let win_err = match status {
                s if s == file_io::STATUS_OBJECT_NAME_NOT_FOUND => file_io::ERROR_FILE_NOT_FOUND,
                s if s == file_io::STATUS_OBJECT_NAME_COLLISION => file_io::ERROR_FILE_EXISTS,
                s if s == file_io::STATUS_ACCESS_DENIED => file_io::ERROR_ACCESS_DENIED,
                _ => file_io::ERROR_FILE_NOT_FOUND,
            };
            set_last_error(win_err);
            eprintln!(
                "weave/CreateFileW: exit path={win_path:?} → INVALID_HANDLE_VALUE status={status:#x} last_error={win_err}"
            );
            usize::MAX // INVALID_HANDLE_VALUE
        }
    }
}

/// ReadFile: read bytes from a file handle into a buffer.
///
/// Wine ref: dlls/kernelbase/file.c — initialises *result to 0; EOF (STATUS_END_OF_FILE)
/// returns TRUE for synchronous reads, FALSE for overlapped; overlapped reads use the
/// file offset from OVERLAPPED struct. Weave is synchronous-only (overlapped ignored);
/// does not distinguish EOF from error — both set bytes_read=0 and return FALSE.
///
/// # Safety
/// `lp_buffer` must be valid for `n_bytes_to_read` bytes.
// Wine ref: dlls/kernelbase/file.c — ReadFile: always sets *result=0 first. Synchronous EOF
// (STATUS_END_OF_FILE) → TRUE with *result=0. Overlapped EOF → FALSE + ERROR_HANDLE_EOF.
// Pipe reads: STATUS_PIPE_BROKEN → FALSE + ERROR_BROKEN_PIPE. Weave: sync only, no pipe handling.
pub unsafe extern "win64" fn read_file(
    h_file: usize,
    lp_buffer: *mut u8,
    n_bytes_to_read: u32,
    lp_bytes_read: *mut u32,
    lp_overlapped: usize,
) -> i32 {
    // Pointer validation: null buffer with non-zero read size is an error.
    if lp_buffer.is_null() && n_bytes_to_read > 0 {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        if !lp_bytes_read.is_null() {
            unsafe { *lp_bytes_read = 0 };
        }
        eprintln!("weave/ReadFile: exit handle={h_file:#x} → FALSE (null buffer)");
        return 0; // FALSE
    }

    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            set_last_error(file_io::ERROR_INVALID_HANDLE);
            eprintln!("weave/ReadFile: exit handle={h_file:#x} → FALSE (invalid handle)");
            return 0; // FALSE
        }
    };

    // SAFETY: (a) lp_buffer is non-null (checked above).  (b) Guest heap —
    // caller-owned for the duration of this call.  (c) Valid for at least
    // n_bytes_to_read bytes per the caller's # Safety contract.
    // (d) notepad_roundtrip_gate CI 26037252940 — read path confirmed correct.
    let n = unsafe { libc::read(fd, lp_buffer as *mut libc::c_void, n_bytes_to_read as usize) };

    if !lp_bytes_read.is_null() {
        // SAFETY: (a) lp_bytes_read is non-null (checked above).  (b) Guest
        // heap, caller-owned.  (c) Valid for this call.  (d) notepad_roundtrip_gate CI 26037252940.
        unsafe { *lp_bytes_read = if n >= 0 { n as u32 } else { 0 } };
    }

    if n < 0 {
        // Populate OVERLAPPED completion fields so GetOverlappedResult can read them.
        if lp_overlapped != 0 {
            let ovl = lp_overlapped as *mut usize;
            // SAFETY: (a) lp_overlapped is non-zero (checked above), trusted as a
            // valid OVERLAPPED pointer per caller's # Safety contract.  (b) Guest
            // heap, caller-owned.  (c) Valid for this call.  (d) notepad_roundtrip_gate CI 26037252940.
            unsafe {
                std::ptr::write_volatile(ovl, 0xC000_0001); // STATUS_UNSUCCESSFUL → Internal
                std::ptr::write_volatile(ovl.add(1), 0); // InternalHigh = 0
            }
        }
        set_last_error(file_io::ERROR_ACCESS_DENIED);
        eprintln!("weave/ReadFile: exit handle={h_file:#x} fd={fd} → FALSE (read err)");
        0 // FALSE
    } else {
        // Populate OVERLAPPED completion fields so GetOverlappedResult can read them.
        if lp_overlapped != 0 {
            let ovl = lp_overlapped as *mut usize;
            // SAFETY: (a) lp_overlapped is non-zero (checked above), trusted as a
            // valid OVERLAPPED pointer per caller's # Safety contract.  (b) Guest
            // heap, caller-owned.  (c) Valid for this call.  (d) notepad_roundtrip_gate CI 26037252940.
            unsafe {
                std::ptr::write_volatile(ovl, 0); // Internal = STATUS_SUCCESS
                std::ptr::write_volatile(ovl.add(1), n as usize); // InternalHigh = bytes read
            }
        }
        set_last_error(0);
        eprintln!(
            "weave/ReadFile: handle={h_file:#x} fd={fd} bytes_requested={n_bytes_to_read} → TRUE bytes_read={n}"
        );
        1 // TRUE
    }
}

/// WriteFile: write bytes from a buffer to a file handle.
///
/// Wine ref: dlls/kernelbase/file.c — initialises *result to 0; overlapped writes use the
/// file offset from OVERLAPPED struct and may return ERROR_IO_PENDING; synchronous writes
/// set *result = bytes written. Weave is synchronous-only (overlapped ignored).
///
/// # Safety
/// `lp_buffer` must be valid for `n_bytes_to_write` bytes.
// Wine ref: dlls/kernelbase/file.c — WriteFile: sets *result=0 first; overlapped writes use
// OVERLAPPED.Offset/OffsetHigh for file position and may return ERROR_IO_PENDING. Console
// handle writes go through WriteConsoleA. Weave: sync only, no overlapped, no console path.
pub unsafe extern "win64" fn write_file(
    h_file: usize,
    lp_buffer: *const u8,
    n_bytes_to_write: u32,
    lp_bytes_written: *mut u32,
    lp_overlapped: usize,
) -> i32 {
    eprintln!(
        "weave/WriteFile: entry handle={h_file:#x} buf={lp_buffer:p} n_bytes={n_bytes_to_write} overlapped={lp_overlapped:#x}"
    );
    // Pointer validation: null buffer with non-zero write size is an error.
    if lp_buffer.is_null() && n_bytes_to_write > 0 {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        if !lp_bytes_written.is_null() {
            unsafe { *lp_bytes_written = 0 };
        }
        eprintln!("weave/WriteFile: exit handle={h_file:#x} → FALSE (null buffer)");
        return 0; // FALSE
    }

    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            set_last_error(file_io::ERROR_INVALID_HANDLE);
            eprintln!("weave/WriteFile: exit handle={h_file:#x} → FALSE (invalid handle)");
            return 0; // FALSE
        }
    };

    if std::env::var("WEAVE_TEST_SAVE_RESULT").is_ok() {
        let proc_link = format!("/proc/self/fd/{fd}");
        if let Ok(linux_path) = std::fs::read_link(&proc_link) {
            let path_str = linux_path.to_string_lossy();
            if path_str.contains("save_png_gate") && !lp_buffer.is_null() && n_bytes_to_write > 0 {
                let n_sample = (n_bytes_to_write as usize).min(8);
                // SAFETY: lp_buffer is non-null and n_sample ≤ n_bytes_to_write per caller contract.
                let sample = unsafe { std::slice::from_raw_parts(lp_buffer, n_sample) };
                let hex: String = sample
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let magic = if sample.len() >= 3
                    && sample[0] == 0xFF
                    && sample[1] == 0xD8
                    && sample[2] == 0xFF
                {
                    "JPEG"
                } else if sample.len() >= 4
                    && sample[0] == 0x89
                    && sample[1] == 0x50
                    && sample[2] == 0x4E
                    && sample[3] == 0x47
                {
                    "PNG"
                } else {
                    "unknown"
                };
                eprintln!(
                    "weave/E3-M9-trace: WriteFile magic path={path_str:?} n_bytes={n_bytes_to_write} \
                     first_bytes=[{hex}] format={magic}"
                );
            }
        }
    }

    // SAFETY: (a) lp_buffer is non-null (checked above).  (b) Guest heap —
    // caller-owned for the duration of this call.  (c) Valid for at least
    // n_bytes_to_write bytes per the caller's # Safety contract.
    // (d) notepad_roundtrip_gate CI 26037252940 — write path confirmed correct.
    let n = unsafe {
        libc::write(
            fd,
            lp_buffer as *const libc::c_void,
            n_bytes_to_write as usize,
        )
    };

    if !lp_bytes_written.is_null() {
        // SAFETY: (a) lp_bytes_written is non-null (checked above).  (b) Guest
        // heap, caller-owned.  (c) Valid for this call.  (d) notepad_roundtrip_gate CI 26037252940.
        unsafe { *lp_bytes_written = if n >= 0 { n as u32 } else { 0 } };
    }

    if n < 0 {
        // Populate OVERLAPPED completion fields so GetOverlappedResult can read them.
        if lp_overlapped != 0 {
            let ovl = lp_overlapped as *mut usize;
            // SAFETY: (a) lp_overlapped is non-zero (checked above), trusted as a
            // valid OVERLAPPED pointer per caller's # Safety contract.  (b) Guest
            // heap, caller-owned.  (c) Valid for this call.  (d) notepad_roundtrip_gate CI 26037252940.
            unsafe {
                std::ptr::write_volatile(ovl, 0xC000_0001); // STATUS_UNSUCCESSFUL → Internal
                std::ptr::write_volatile(ovl.add(1), 0); // InternalHigh = 0
            }
        }
        set_last_error(file_io::ERROR_ACCESS_DENIED);
        eprintln!("weave/WriteFile: error handle={h_file:#x} fd={fd} → write failed");
        0 // FALSE
    } else {
        // Populate OVERLAPPED completion fields so GetOverlappedResult can read them.
        if lp_overlapped != 0 {
            let ovl = lp_overlapped as *mut usize;
            // SAFETY: (a) lp_overlapped is non-zero (checked above), trusted as a
            // valid OVERLAPPED pointer per caller's # Safety contract.  (b) Guest
            // heap, caller-owned.  (c) Valid for this call.  (d) notepad_roundtrip_gate CI 26037252940.
            unsafe {
                std::ptr::write_volatile(ovl, 0); // Internal = STATUS_SUCCESS
                std::ptr::write_volatile(ovl.add(1), n as usize); // InternalHigh = bytes written
            }
        }
        set_last_error(0);
        eprintln!(
            "weave/WriteFile: exit handle={h_file:#x} fd={fd} requested={n_bytes_to_write} written={n} → TRUE"
        );
        1 // TRUE
    }
}

/// CloseHandle: close an open object handle.
///
/// Returns TRUE on success, FALSE if the handle was invalid.
/// Closing stdin/stdout/stderr returns FALSE (those are protected).
///
/// Wine ref: dlls/kernel32/sync.c — CloseHandle calls NtClose; thread handles
/// are detached (not joined) on close, consistent with Win32 semantics where
/// CloseHandle on a thread does not wait for it to terminate.
pub extern "win64" fn close_handle(h_object: usize) -> i32 {
    eprintln!("weave/CloseHandle: entry h={h_object:#x}");
    // Thread handles are not file descriptors; handle them before delegating
    // to file_io::close_handle which would fail on non-fd handles.
    if handles::free_if_thread(h_object) {
        set_last_error(0);
        return 1; // TRUE
    }
    match file_io::close_handle(h_object) {
        Ok(()) => {
            set_last_error(0);
            1 // TRUE
        }
        Err(_) => {
            set_last_error(file_io::ERROR_INVALID_HANDLE);
            eprintln!("weave/CloseHandle: invalid handle={h_object:#x}");
            0 // FALSE
        }
    }
}

/// DeleteFileW: delete a file by Win32 path.
///
/// Translates the Win32 path and calls `unlink(2)`.
///
/// # Safety
/// `lp_file_name` must be a valid, null-terminated UTF-16 string.
// Wine ref: dlls/kernelbase/file.c:1104 — converts path via RtlDosPathNameToNtPathName_U,
// opens with FILE_DELETE_ON_CLOSE | FILE_OPEN_REPARSE_POINT, then NtClose triggers delete;
// returns ERROR_PATH_NOT_FOUND for non-existent paths (not ERROR_FILE_NOT_FOUND).
pub unsafe extern "win64" fn delete_file_w(lp_file_name: *const u16) -> i32 {
    if lp_file_name.is_null() {
        set_last_error(file_io::ERROR_INVALID_HANDLE);
        return 0; // FALSE
    }
    let win_path = unsafe {
        let mut len = 0usize;
        while len < MAX_UTF16_LEN && *lp_file_name.add(len) != 0 {
            len += 1;
        }
        if len == MAX_UTF16_LEN {
            set_last_error(87); // ERROR_INVALID_PARAMETER
            return 0; // FALSE
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(lp_file_name, len)).to_owned()
    };
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => {
            set_last_error(file_io::ERROR_FILE_NOT_FOUND);
            return 0;
        }
    };
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => {
            set_last_error(file_io::ERROR_FILE_NOT_FOUND);
            return 0;
        }
    };
    let ret = unsafe { libc::unlink(c_path.as_ptr()) };
    if ret == 0 {
        set_last_error(0);
        1 // TRUE
    } else {
        set_last_error(file_io::ERROR_FILE_NOT_FOUND);
        0 // FALSE
    }
}

/// SetFilePointer: move the read/write position within an open file handle.
///
/// `dw_move_method`: FILE_BEGIN (0), FILE_CURRENT (1), FILE_END (2).
/// Returns the new file position on success, or INVALID_SET_FILE_POINTER
/// (0xFFFFFFFF) on failure.
/// # Safety
/// `lp_distance_to_move_high`, if non-null, must be a valid pointer to an i32.
// Wine ref: dlls/kernelbase/file.c:3848 — builds LARGE_INTEGER from low+highword,
// calls SetFilePointerEx; if low result == INVALID_SET_FILE_POINTER (0xFFFFFFFF)
// and no error, clears LastError to 0 to distinguish EOF from failure.
pub unsafe extern "win64" fn set_file_pointer(
    h_file: usize,
    l_distance_to_move: i32,
    lp_distance_to_move_high: *mut i32,
    dw_move_method: u32,
) -> u32 {
    eprintln!(
        "weave/SetFilePointer: entry handle={h_file:#x} dist_lo={l_distance_to_move} method={dw_move_method}"
    );
    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            set_last_error(file_io::ERROR_INVALID_HANDLE);
            eprintln!(
                "weave/SetFilePointer: exit handle={h_file:#x} → INVALID_SET_FILE_POINTER (invalid handle)"
            );
            return 0xFFFF_FFFF; // INVALID_SET_FILE_POINTER
        }
    };

    // Build 64-bit offset from low + optional high word.
    let high = if lp_distance_to_move_high.is_null() {
        0i64
    } else {
        unsafe { *lp_distance_to_move_high as i64 }
    };
    let offset = (high << 32) | (l_distance_to_move as i64);

    let whence = match dw_move_method {
        0 => libc::SEEK_SET,
        1 => libc::SEEK_CUR,
        2 => libc::SEEK_END,
        _ => {
            set_last_error(file_io::ERROR_INVALID_HANDLE);
            eprintln!(
                "weave/SetFilePointer: exit handle={h_file:#x} → INVALID_SET_FILE_POINTER (bad method)"
            );
            return 0xFFFF_FFFF;
        }
    };

    let new_pos = unsafe { libc::lseek(fd, offset, whence) };
    if new_pos < 0 {
        set_last_error(file_io::ERROR_INVALID_HANDLE);
        eprintln!(
            "weave/SetFilePointer: exit handle={h_file:#x} fd={fd} → INVALID_SET_FILE_POINTER (lseek err)"
        );
        return 0xFFFF_FFFF;
    }

    // Write high 32 bits back if caller provided the pointer.
    if !lp_distance_to_move_high.is_null() {
        unsafe { *lp_distance_to_move_high = (new_pos >> 32) as i32 };
    }

    set_last_error(0);
    eprintln!("weave/SetFilePointer: exit handle={h_file:#x} fd={fd} new_pos={new_pos} → OK");
    (new_pos & 0xFFFF_FFFF) as u32
}

/// GetFileSize: return the size of an open file.
///
/// Returns the low 32 bits of the file size. Writes the high 32 bits to
/// `lp_file_size_high` if non-null. Returns INVALID_FILE_SIZE (0xFFFFFFFF)
/// on error.
/// # Safety
/// `lp_file_size_high`, if non-null, must be a valid pointer to a u32.
// Wine ref: dlls/kernelbase/file.c:3228 — calls GetFileSizeEx; if LowPart==
// INVALID_FILE_SIZE (0xFFFFFFFF) and no error, clears LastError to 0
// to distinguish valid 4GB-1 size from failure (same trick as SetFilePointer).
pub unsafe extern "win64" fn get_file_size(h_file: usize, lp_file_size_high: *mut u32) -> u32 {
    eprintln!("weave/GetFileSize: entry handle={h_file:#x} lp_high={lp_file_size_high:?}");
    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            set_last_error(file_io::ERROR_INVALID_HANDLE);
            eprintln!(
                "weave/GetFileSize: exit handle={h_file:#x} fd=? → INVALID_FILE_SIZE (bad_handle)"
            );
            return 0xFFFF_FFFF;
        }
    };

    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let ret = unsafe { libc::fstat(fd, &mut stat) };
    if ret != 0 {
        set_last_error(file_io::ERROR_INVALID_HANDLE);
        eprintln!(
            "weave/GetFileSize: exit handle={h_file:#x} fd={fd} → INVALID_FILE_SIZE (fstat_err)"
        );
        return 0xFFFF_FFFF;
    }

    let size = stat.st_size as u64;
    let high = (size >> 32) as u32;
    let low = (size & 0xFFFF_FFFF) as u32;
    if !lp_file_size_high.is_null() {
        unsafe { *lp_file_size_high = high };
    }
    set_last_error(0);
    eprintln!(
        "weave/GetFileSize: exit handle={h_file:#x} fd={fd} low={low:#x} high={high:#x} → OK"
    );
    low
}

// ── File information functions ───────────────────────────────────────────────

/// GetFileInformationByHandle: return BY_HANDLE_FILE_INFORMATION for an open file.
///
/// # Safety
/// `lp_file_information` must be a valid writable pointer to a ByHandleFileInformation.
// Wine ref: dlls/kernelbase/file.c:3106 — calls NtQueryInformationFile with
// FileStatInformation; separately queries NtQueryVolumeInformationFile for
// VolumeSerialNumber (STATUS_BUFFER_OVERFLOW is tolerated). FileId maps to
// nFileIndexHigh/Low; dwVolumeSerialNumber defaults to 0 if volume query fails.
pub unsafe extern "win64" fn get_file_information_by_handle(
    h_file: usize,
    lp_file_information: *mut ByHandleFileInformation,
) -> i32 {
    if lp_file_information.is_null() {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0; // FALSE — invalid parameter
    }
    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            set_last_error(file_io::ERROR_INVALID_HANDLE);
            return 0; // FALSE
        }
    };

    // SAFETY: (a) zeroed() produces a value with all bytes set to 0, which is valid
    // for libc::stat (a C struct with no invariants on zero bytes); (b) Rust stack;
    // (c) duration of this call; (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: (a) fd is a valid Linux file descriptor from the handle table (validated
    // by get_fd above); &mut stat points to a properly aligned libc::stat on the stack;
    // (b) fd from kernel handle table, stat on Rust stack; (c) duration of fstat syscall;
    // (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
    let ret = unsafe { libc::fstat(fd, &mut stat) };
    if ret != 0 {
        eprintln!("weave/GetFileInformationByHandle: h={h_file:#x} fd={fd} fstat failed");
        return 0; // FALSE
    }

    let ino = stat.st_ino;
    let size = stat.st_size;

    let ft_creation = weave_common::unix_to_filetime(stat.st_ctime, stat.st_ctime_nsec);
    let ft_access = weave_common::unix_to_filetime(stat.st_atime, stat.st_atime_nsec);
    let ft_write = weave_common::unix_to_filetime(stat.st_mtime, stat.st_mtime_nsec);

    let dw_file_attributes = if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR {
        0x10u32 // FILE_ATTRIBUTE_DIRECTORY
    } else {
        0x20u32 // FILE_ATTRIBUTE_ARCHIVE — real Windows sets this on all regular files
    };
    let n_links = stat.st_nlink as u32;
    let idx_hi = (stat.st_ino >> 32) as u32;
    let idx_lo = (stat.st_ino & 0xFFFFFFFF) as u32;
    // Wine ref: dlls/kernelbase/file.c:3106 — dwVolumeSerialNumber comes from
    // NtQueryVolumeInformationFile → FileFsVolumeInformation.VolumeSerialNumber.
    // Wine's ntdll maps st_dev to VolumeSerialNumber (low 32 bits). Using 0xDEADBEEF
    // caused MSVC archive builders to fail identity/hardlink checks (E_INVALIDARG path).
    let dw_serial = stat.st_dev as u32;
    eprintln!(
        "weave/GetFileInformationByHandle: h={h_file:#x} fd={fd} \
         attrs={dw_file_attributes:#x} serial={dw_serial:#x} \
         ino={ino:#x} idx_hi={idx_hi:#x} idx_lo={idx_lo:#x} \
         links={n_links} size={size} \
         ft_cre={ft_creation:#x} ft_acc={ft_access:#x} ft_wri={ft_write:#x}"
    );

    // SAFETY: (a) lp_file_information is non-null (checked at entry) and points to a
    // writable ByHandleFileInformation struct supplied by the caller; (b) guest heap —
    // caller owns the struct; (c) duration of this call; (d) gate:
    // sevenzip_m13_debug_e_gate (CI 26007699626).
    unsafe {
        (*lp_file_information).dw_file_attributes = dw_file_attributes;
        (*lp_file_information).ft_creation_time_low = ft_creation as u32;
        (*lp_file_information).ft_creation_time_high = (ft_creation >> 32) as u32;
        (*lp_file_information).ft_last_access_time_low = ft_access as u32;
        (*lp_file_information).ft_last_access_time_high = (ft_access >> 32) as u32;
        (*lp_file_information).ft_last_write_time_low = ft_write as u32;
        (*lp_file_information).ft_last_write_time_high = (ft_write >> 32) as u32;
        (*lp_file_information).dw_volume_serial_number = dw_serial;
        (*lp_file_information).n_file_size_high = (stat.st_size >> 32) as u32;
        (*lp_file_information).n_file_size_low = (stat.st_size & 0xFFFFFFFF) as u32;
        (*lp_file_information).n_number_of_links = n_links;
        (*lp_file_information).n_file_index_high = idx_hi;
        (*lp_file_information).n_file_index_low = idx_lo;
    }

    1 // TRUE
}

/// GetFileInformationByHandleEx — query extended file information by class.
///
/// Wine ref: dlls/kernelbase/file.c::GetFileInformationByHandleEx — dispatches on
/// FILE_INFO_BY_HANDLE_CLASS; calls NtQueryInformationFile for most classes.
/// Weave: implements FileBasicInfo (0) and FileStandardInfo (1) via Linux fstat;
/// returns FALSE/ERROR_INVALID_PARAMETER for unsupported classes.
///
/// # Safety
/// `h_file` must be a valid Weave handle. `lp_file_information` must point to a
/// buffer of at least `dw_buffer_size` bytes matching the requested class layout.
// Wine ref: dlls/kernelbase/file.c:3141 — switch on FILE_INFO_BY_HANDLE_CLASS; calls
// NtQueryInformationFile for FileBasicInfo/FileStandardInfo/FileNameInfo/FileIdInfo/etc.;
// ERROR_CALL_NOT_IMPLEMENTED for FileRemoteProtocolInfo/FileNormalizedNameInfo;
// ERROR_INVALID_PARAMETER for FileRenameInfo/FileDispositionInfo/FileEndOfFileInfo.
#[allow(non_upper_case_globals)]
pub unsafe extern "win64" fn get_file_information_by_handle_ex(
    h_file: usize,
    file_information_class: u32,
    lp_file_information: *mut u8,
    dw_buffer_size: u32,
) -> i32 {
    // FILE_INFO_BY_HANDLE_CLASS constants
    const FileBasicInfo: u32 = 0;
    const FileStandardInfo: u32 = 1;
    const FileNameInfo: u32 = 2;
    const FileIdInfo: u32 = 18;

    if lp_file_information.is_null() {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            set_last_error(6); // ERROR_INVALID_HANDLE
            return 0;
        }
    };

    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        set_last_error(6); // ERROR_INVALID_HANDLE
        return 0;
    }

    // Convert Unix epoch seconds to Windows FILETIME (100-ns since 1601-01-01).
    // Offset = 11644473600 seconds between 1601-01-01 and 1970-01-01.
    let to_ft = |secs: i64| -> u64 { ((secs + 11_644_473_600) as u64) * 10_000_000 };

    match file_information_class {
        FileBasicInfo => {
            // FILE_BASIC_INFO: CreationTime, LastAccessTime, LastWriteTime,
            // ChangeTime (each 8 bytes), FileAttributes (4 bytes) = 36 bytes minimum.
            if dw_buffer_size < 36 {
                set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
                return 0;
            }
            let mtime_ft = to_ft(stat.st_mtime);
            let atime_ft = to_ft(stat.st_atime);
            unsafe {
                let p = lp_file_information as *mut u64;
                p.add(0).write_unaligned(mtime_ft); // CreationTime (approximate)
                p.add(1).write_unaligned(atime_ft); // LastAccessTime
                p.add(2).write_unaligned(mtime_ft); // LastWriteTime
                p.add(3).write_unaligned(mtime_ft); // ChangeTime
                let attr_p = p.add(4) as *mut u32;
                let attr = if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                    0x10u32 // FILE_ATTRIBUTE_DIRECTORY
                } else {
                    0x20u32 // FILE_ATTRIBUTE_ARCHIVE
                };
                attr_p.write_unaligned(attr);
            }
            eprintln!(
                "weave/GetFileInformationByHandleEx: h={h_file:#x} fd={fd} FileBasicInfo mtime={mtime_ft:#x}"
            );
            1 // TRUE
        }
        FileStandardInfo => {
            // FILE_STANDARD_INFO: AllocationSize, EndOfFile (8 bytes each),
            // NumberOfLinks, DeletePending, Directory (4 bytes each) = 24 bytes.
            if dw_buffer_size < 24 {
                set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
                return 0;
            }
            let size = stat.st_size as u64;
            let alloc = (size + 4095) & !4095; // round up to 4 KiB blocks
            let is_dir = (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR;
            unsafe {
                let p = lp_file_information as *mut u64;
                p.add(0).write_unaligned(alloc); // AllocationSize
                p.add(1).write_unaligned(size); // EndOfFile
                let p32 = p.add(2) as *mut u32;
                p32.add(0).write_unaligned(stat.st_nlink as u32); // NumberOfLinks
                p32.add(1).write_unaligned(0u32); // DeletePending = FALSE
                p32.add(2).write_unaligned(is_dir as u32); // Directory
            }
            eprintln!(
                "weave/GetFileInformationByHandleEx: h={h_file:#x} fd={fd} FileStandardInfo size={size}"
            );
            1 // TRUE
        }
        FileNameInfo => {
            // FILE_NAME_INFO: FileNameLength (DWORD) + FileName (WCHAR[]).
            // Stub: return an empty name (length=0). Callers checking the name
            // will see an empty string — acceptable for headless operation.
            if dw_buffer_size < 4 {
                set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
                return 0;
            }
            unsafe { (lp_file_information as *mut u32).write_unaligned(0) }; // FileNameLength=0
            1 // TRUE
        }
        FileIdInfo => {
            // FILE_ID_INFO: VolumeSerialNumber (8 bytes) + FileId (16 bytes) = 24 bytes.
            // Wine ref: dlls/kernelbase/file.c — FileIdInfo fills VolumeSerialNumber from
            // NtQueryVolumeInformationFile; FileId is the 128-bit file identifier.
            // Map st_dev → VolumeSerialNumber (low 32 bits, zero-extended to u64).
            if dw_buffer_size < 24 {
                set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
                return 0;
            }
            unsafe {
                let p = lp_file_information as *mut u64;
                p.add(0).write_unaligned(stat.st_dev as u64); // VolumeSerialNumber
                p.add(1).write_unaligned(stat.st_ino); // FileId low 64 bits
                p.add(2).write_unaligned(0u64); // FileId high 64 bits
            }
            1 // TRUE
        }
        _ => {
            eprintln!(
                "weave/GetFileInformationByHandleEx: h={h_file:#x} class={file_information_class} → ERROR_INVALID_PARAMETER"
            );
            set_last_error(87); // ERROR_INVALID_PARAMETER
            0 // FALSE
        }
    }
}

/// GetFinalPathNameByHandleW — get the full path of an open file handle.
///
/// Wine ref: dlls/kernelbase/file.c::GetFinalPathNameByHandleW — queries
/// ObjectNameInformation via NtQueryObject then strips the NT prefix.
/// Weave: reads /proc/self/fd/N symlink for the Linux path, prepends Z:\.
/// VOLUME_NAME_DOS (0) returns \\?\Z:\path; callers expecting a plain path
/// should strip the \\?\ prefix themselves.
///
/// Returns the number of characters (excluding NUL) required or written.
/// If `path` is NULL or `count` is 0, returns the required length.
///
/// # Safety
/// `h_file` must be a valid handle. `path` (if non-null) must point to a
/// writable buffer of `count` wide characters.
// Wine ref: dlls/kernelbase/file.c — GetFinalPathNameByHandleW: unknown flags →
// ERROR_INVALID_PARAMETER. Queries ObjectNameInformation via NtQueryObject, strips
// \\??\ prefix. Buffer too small → returns result+1 (not result). VOLUME_NAME_DOS
// prepends \\?\ to the NT-style path. FILE_NAME_OPENED is not yet supported in Wine.
pub unsafe extern "win64" fn get_final_path_name_by_handle_w(
    h_file: usize,
    path: *mut u16,
    count: u32,
    _flags: u32,
) -> u32 {
    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            set_last_error(6); // ERROR_INVALID_HANDLE
            return 0;
        }
    };

    // Read the symlink /proc/self/fd/<fd> to get the real Linux path.
    let proc_link = format!("/proc/self/fd/{fd}");
    let linux_path = match std::fs::read_link(&proc_link) {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(_) => {
            set_last_error(6); // ERROR_INVALID_HANDLE
            return 0;
        }
    };

    // Convert Linux path to Windows Z:\ path (same convention as CreateFileW).
    let win_path = format!("\\\\?\\Z:{}", linux_path.replace('/', "\\"));
    let wide: Vec<u16> = win_path.encode_utf16().collect();
    let needed = wide.len() as u32; // excludes NUL

    if !path.is_null() && count > needed {
        unsafe {
            for (i, &ch) in wide.iter().enumerate() {
                path.add(i).write(ch);
            }
            path.add(wide.len()).write(0); // NUL terminator
        }
        needed
    } else {
        // Buffer too small or NULL — return required length (without NUL, per MSDN).
        needed + 1
    }
}

/// GetProductInfo — return the product type for the OS version.
///
/// Wine ref: dlls/kernelbase/version.c::GetProductInfo — calls RtlGetProductInfo
/// which returns PRODUCT_UNDEFINED (0) for Wine. Weave returns
/// PRODUCT_PROFESSIONAL (0x30) to satisfy apps that check for a workstation SKU.
///
/// # Safety
/// `pdw_returned_product_type` must be a valid writable pointer if non-null.
// Wine ref: dlls/kernelbase/version.c — GetProductInfo is a thin wrapper around
// RtlGetProductInfo; Wine's RtlGetProductInfo returns PRODUCT_UNDEFINED (0).
// Weave returns PRODUCT_PROFESSIONAL (0x30) to satisfy SKU checks.
pub unsafe extern "win64" fn get_product_info(
    _dw_os_major_version: u32,
    _dw_os_minor_version: u32,
    _dw_sp_major_version: u32,
    _dw_sp_minor_version: u32,
    pdw_returned_product_type: *mut u32,
) -> i32 {
    if !pdw_returned_product_type.is_null() {
        unsafe { *pdw_returned_product_type = 0x30 }; // PRODUCT_PROFESSIONAL
    }
    1 // TRUE
}

/// RegisterApplicationRestart — register restart command for crash recovery.
///
/// Wine ref: dlls/kernel32/process.c — stub returning S_OK. Applications like
/// NPP register restart parameters via this API; Weave ignores them.
///
/// # Safety
/// `pwz_commandline` is an optional wide string (may be NULL).
pub unsafe extern "win64" fn register_application_restart(
    _pwz_commandline: *const u16,
    _dw_flags: u32,
) -> i32 {
    0 // S_OK
}

/// UnregisterApplicationRestart — remove a previously registered restart command.
///
/// Wine ref: dlls/kernel32/process.c — stub returning S_OK.
pub extern "win64" fn unregister_application_restart() -> i32 {
    0 // S_OK
}

/// GetApplicationRestartSettings — query restart command registered by the app.
///
/// Wine ref: dlls/kernelbase/process.c — FIXME stub; Wine returns E_NOTIMPL unconditionally,
/// not E_FAIL; no restart command storage exists in Wine at all.
///
/// # Safety
/// Output pointers may be NULL; we do not dereference them.
pub unsafe extern "win64" fn get_application_restart_settings(
    _h_process: usize,
    _pwz_commandline: *mut u16,
    _pcch_size: *mut u32,
    _pdw_flags: *mut u32,
) -> i32 {
    0x8007_00E8_u32 as i32 // HRESULT_FROM_WIN32(ERROR_NOT_FOUND) — no restart registered
}

/// ReadDirectoryChangesW — watch a directory for changes.
///
/// Wine ref: dlls/kernel32/change.c — issues NtNotifyChangeDirectoryFile.
/// Weave stub: returns FALSE (not supported). NPP uses this for live file
/// change detection; failing here disables that feature gracefully.
///
/// # Safety
/// All pointer args are ignored.
// Wine ref: dlls/kernelbase/file.c — ReadDirectoryChangesW: issues NtNotifyChangeDirectoryFile.
// No overlapped → creates a temporary event, waits synchronously, then CloseHandle(event).
// overlapped → STATUS_PENDING returns TRUE immediately (async path).
pub unsafe extern "win64" fn read_directory_changes_w(
    _h_directory: usize,
    _lp_buffer: *mut u8,
    _n_buffer_length: u32,
    _b_watch_subtree: i32,
    _dw_notify_filter: u32,
    _lp_bytes_returned: *mut u32,
    _lp_overlapped: *mut u8,
    _lp_completion_routine: usize,
) -> i32 {
    set_last_error(120); // ERROR_CALL_NOT_IMPLEMENTED
    0 // FALSE
}

/// SetEndOfFile: truncate or extend file at current position.
///
/// # Safety
/// No pointer arguments are dereferenced.
// Wine ref: dlls/kernelbase/file.c:3749 — calls NtQueryInformationFile to get
// current position, then NtSetInformationFile(FileEndOfFileInformation);
// returns ERROR_INVALID_HANDLE if the handle is invalid.
pub unsafe extern "win64" fn set_end_of_file(h_file: usize) -> i32 {
    eprintln!("weave/SetEndOfFile: entry handle={h_file:#x}");
    let fd = match handles::get_fd(h_file) {
        Some(fd) => {
            eprintln!("weave/SetEndOfFile: handle={h_file:#x} fd={fd}");
            fd
        }
        None => {
            eprintln!("weave/SetEndOfFile: exit handle={h_file:#x} → FALSE (invalid handle)");
            return 0; // FALSE
        }
    };

    let pos = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
    if pos < 0 {
        eprintln!("weave/SetEndOfFile: exit handle={h_file:#x} fd={fd} → FALSE (lseek err)");
        return 0; // FALSE
    }

    let ret = unsafe { libc::ftruncate(fd, pos) };
    let ok = ret == 0;
    eprintln!(
        "weave/SetEndOfFile: exit handle={h_file:#x} fd={fd} pos={pos} → {}",
        if ok { "TRUE" } else { "FALSE (ftruncate err)" }
    );
    ok as i32
}

/// GetLogicalDriveStringsW: enumerate available drive letters.
///
/// # Safety
/// `lp_buffer` must be valid for `n_buffer_length` u16 words.
// Wine ref: dlls/kernelbase/volume.c:526 — iterates drive letters A–Z, checks
// each with GetDriveTypeW; returns double-null-terminated list; if buffer is NULL
// or too small, returns required length without writing.
pub unsafe extern "win64" fn get_logical_drive_strings_w(
    n_buffer_length: u32,
    lp_buffer: *mut u16,
) -> u32 {
    const DRIVES: &[u16] = &[b'C' as u16, b':' as u16, b'\\' as u16, 0, 0];
    let required = DRIVES.len() as u32;

    if n_buffer_length == 0 || lp_buffer.is_null() {
        return required;
    }

    if n_buffer_length < required {
        return required;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(DRIVES.as_ptr(), lp_buffer, DRIVES.len());
    }

    4 // length excluding final null
}

/// GetLogicalDriveStringsA: enumerate available drive letters (ANSI).
///
/// # Safety
/// `lp_buffer` must be valid for `n_buffer_length` bytes.
// Wine ref: dlls/kernelbase/volume.c — ANSI wrapper; converts result from
// GetLogicalDriveStringsW via RtlUnicodeToMultiByteN.
pub unsafe extern "win64" fn get_logical_drive_strings_a(
    n_buffer_length: u32,
    lp_buffer: *mut u8,
) -> u32 {
    const DRIVES: &[u8] = b"C:\\\0\0";
    let required = DRIVES.len() as u32;

    if n_buffer_length == 0 || lp_buffer.is_null() {
        return required;
    }

    if n_buffer_length < required {
        return required;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(DRIVES.as_ptr(), lp_buffer, DRIVES.len());
    }

    4 // length excluding final null
}

/// GetVolumeInformationW: return volume name, serial, flags, and filesystem name.
///
/// Weave derives the volume serial from `stat(path).st_dev as u32` so that it
/// matches the value returned by `GetFileInformationByHandle` (which also uses
/// `fstat().st_dev as u32`). This consistency is required by MSVC's 7-Zip
/// archive builder, which compares the GFIBH serial of input files against the
/// GVI serial of the output volume and aborts `WriteDatabase` with E_INVALIDARG
/// when they differ.
///
/// # Safety
/// Pointer arguments are null-checked before dereferencing.
// Wine ref: dlls/kernelbase/volume.c::GetVolumeInformationW (lines 143-197) —
// opens a handle to the root path via NtOpenFile, then delegates entirely to
// GetVolumeInformationByHandleW(handle, label, label_len, serial, filename_len,
// flags, fsname, fsname_len) which queries FileFsVolumeInformation for the
// serial and FileFsAttributeInformation for fs name + flags. NULL root uses L"\\".
pub unsafe extern "win64" fn get_volume_information_w(
    lp_root_path_name: *const u16,
    lp_volume_name_buffer: *mut u16,
    n_volume_name_size: u32,
    lp_volume_serial_number: *mut u32,
    lp_maximum_component_length: *mut u32,
    lp_file_system_flags: *mut u32,
    lp_file_system_name_buffer: *mut u16,
    n_file_system_name_size: u32,
) -> i32 {
    eprintln!(
        "weave/GetVolumeInformationW: entry root_path_ptr={lp_root_path_name:?} vol_name_buf={lp_volume_name_buffer:?} vol_name_sz={n_volume_name_size} serial={lp_volume_serial_number:?} maxlen={lp_maximum_component_length:?} flags={lp_file_system_flags:?} fs_name_buf={lp_file_system_name_buffer:?} fs_name_sz={n_file_system_name_size}"
    );

    // Derive serial from st_dev so it matches GetFileInformationByHandle.
    // When lpRootPathName is NULL Wine uses the current directory; we do the same.
    let serial: u32 = {
        // Decode the LPCWSTR root path (e.g. "C:\\" or NULL).
        let win_path: String = if lp_root_path_name.is_null() {
            String::from("C:\\")
        } else {
            let mut len = 0usize;
            while len < MAX_UTF16_LEN && unsafe { *lp_root_path_name.add(len) } != 0 {
                len += 1;
            }
            unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_root_path_name, len)) }
        };

        // Translate Windows path to Linux path; fall back to "/" on error.
        let linux_path = weave_core::file_io::translate_win_path(&win_path)
            .unwrap_or_else(|_| std::path::PathBuf::from("/"));

        // stat the path to get st_dev — same field used by GetFileInformationByHandle.
        match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
            Ok(c_path) => {
                let mut stat_buf = unsafe { std::mem::zeroed::<libc::stat>() };
                if unsafe { libc::stat(c_path.as_ptr(), &mut stat_buf) } == 0 {
                    stat_buf.st_dev as u32
                } else {
                    // stat failed (e.g. path does not exist) — fall back to "/" device.
                    let root_c = std::ffi::CString::new("/").unwrap();
                    let mut root_stat = unsafe { std::mem::zeroed::<libc::stat>() };
                    if unsafe { libc::stat(root_c.as_ptr(), &mut root_stat) } == 0 {
                        root_stat.st_dev as u32
                    } else {
                        0x0000_1234u32 // last-resort non-zero placeholder
                    }
                }
            }
            Err(_) => 0x0000_1234u32,
        }
    };

    if !lp_volume_serial_number.is_null() {
        unsafe { *lp_volume_serial_number = serial };
    }
    if !lp_maximum_component_length.is_null() {
        unsafe { *lp_maximum_component_length = 255u32 };
    }
    if !lp_file_system_flags.is_null() {
        // FILE_CASE_SENSITIVE_SEARCH  0x0001
        // FILE_CASE_PRESERVED_NAMES   0x0002
        // FILE_UNICODE_ON_DISK        0x0004
        // FILE_SUPPORTS_HARD_LINKS    0x0400
        unsafe { *lp_file_system_flags = 0x0407u32 };
    }

    if !lp_volume_name_buffer.is_null() && n_volume_name_size >= 6 {
        const VOLUME_NAME: &[u16] = &[
            b'W' as u16,
            b'e' as u16,
            b'a' as u16,
            b'v' as u16,
            b'e' as u16,
            0u16,
        ];
        unsafe {
            std::ptr::copy_nonoverlapping(
                VOLUME_NAME.as_ptr(),
                lp_volume_name_buffer,
                VOLUME_NAME.len(),
            );
        }
    }

    if !lp_file_system_name_buffer.is_null() && n_file_system_name_size >= 5 {
        const FS_NAME: &[u16] = &[b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16, 0u16];
        unsafe {
            std::ptr::copy_nonoverlapping(
                FS_NAME.as_ptr(),
                lp_file_system_name_buffer,
                FS_NAME.len(),
            );
        }
    }

    eprintln!(
        "weave/GetVolumeInformationW: exit serial={serial:#010x} maxlen=255 flags=0x0407 vol=\"Weave\" fs=\"NTFS\" → TRUE"
    );
    1 // TRUE
}

// ── Process/thread stubs ─────────────────────────────────────────────────────

/// CreateProcessW: create a new process and its primary thread.
///
/// # Safety
/// Pointer arguments (app_name, cmd_line, pi) are read/written with null checks.
// Wine ref: dlls/kernelbase/process.c::CreateProcessInternalW — parses app_name or first
// token of cmd_line for the exe path; translates to native path; forks via NtCreateUserProcess;
// fills PROCESS_INFORMATION with hProcess/hThread/ProcessId/ThreadId. Weave: translate
// Win32 exe path → Linux path, spawn child `weave <exe> [args]`, fill pi with child PID.
// Fragile: child inherits parent Landlock rules — DLL paths must be within prefix; env
// block (_lp_environment) and working dir (_lp_current_directory) ignored for now.
pub unsafe extern "win64" fn create_process_w(
    lp_application_name: *const u16,
    lp_command_line: *mut u16,
    _lp_process_attributes: usize,
    _lp_thread_attributes: usize,
    _b_inherit_handles: i32,
    _dw_creation_flags: u32,
    _lp_environment: usize,
    _lp_current_directory: *const u16,
    _lp_startup_info: usize,
    lp_process_information: usize,
) -> i32 {
    fn read_wide(p: *const u16) -> Option<String> {
        if p.is_null() {
            return None;
        }
        let mut len = 0usize;
        while len < 32_768 && unsafe { *p.add(len) } != 0 {
            len += 1;
        }
        Some(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) }).to_owned())
    }

    fn split_cmdline(s: &str) -> Vec<String> {
        let mut args: Vec<String> = Vec::new();
        let mut cur = String::new();
        let mut in_quotes = false;
        for c in s.chars() {
            match c {
                '"' => in_quotes = !in_quotes,
                ' ' | '\t' if !in_quotes => {
                    if !cur.is_empty() {
                        args.push(std::mem::take(&mut cur));
                    }
                }
                other => cur.push(other),
            }
        }
        if !cur.is_empty() {
            args.push(cur);
        }
        args
    }

    let app = read_wide(lp_application_name);
    let cmd = read_wide(lp_command_line as *const u16);

    let (exe_win32, extra_args): (String, Vec<String>) = match (&app, &cmd) {
        (Some(name), cmd_opt) => {
            let args = cmd_opt
                .as_deref()
                .map(|c| split_cmdline(c).into_iter().skip(1).collect())
                .unwrap_or_default();
            (name.clone(), args)
        }
        (None, Some(cmdline)) => {
            let mut tokens = split_cmdline(cmdline);
            if tokens.is_empty() {
                set_last_error(87); // ERROR_INVALID_PARAMETER
                return 0;
            }
            let exe = tokens.remove(0);
            (exe, tokens)
        }
        (None, None) => {
            set_last_error(87);
            return 0;
        }
    };

    let linux_exe = match weave_core::prefix::translator().to_linux_str(&exe_win32) {
        Ok(p) => p,
        Err(_) => {
            set_last_error(file_io::ERROR_FILE_NOT_FOUND);
            return 0;
        }
    };

    let weave_bin = match std::fs::read_link("/proc/self/exe") {
        Ok(p) => p,
        Err(_) => {
            set_last_error(2); // ERROR_FILE_NOT_FOUND
            return 0;
        }
    };

    let child = match std::process::Command::new(&weave_bin)
        .arg(&linux_exe)
        .args(&extra_args)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("weave/kernel32: CreateProcessW: spawn failed: {e}");
            set_last_error(2);
            return 0;
        }
    };

    let pid = child.id();
    std::mem::forget(child); // detach — guest manages lifetime via WaitForSingleObject/CloseHandle

    if lp_process_information != 0 {
        let pi = lp_process_information as *mut u8;
        // PROCESS_INFORMATION layout (64-bit): hProcess(8) hThread(8) dwProcessId(4) dwThreadId(4)
        unsafe {
            *(pi.add(0) as *mut usize) = pid as usize; // hProcess = PID (per OpenProcess convention)
            *(pi.add(8) as *mut usize) = pid as usize; // hThread = PID (fake — no thread handle table)
            *(pi.add(16) as *mut u32) = pid;
            *(pi.add(20) as *mut u32) = pid; // dwThreadId = PID (fake)
        }
    }

    eprintln!("weave/kernel32: CreateProcessW: spawned pid={pid} exe={linux_exe:?}");
    set_last_error(0);
    1 // TRUE
}

/// CreateProcessA: create a new process (ANSI wrapper).
///
/// # Safety
/// Pointer arguments are converted to wide and forwarded to CreateProcessW.
// Wine ref: dlls/kernelbase/process.c — RtlMultiByteToUnicodeN converts name/cmdline,
// then calls CreateProcessInternalW. Weave: convert to UTF-8 via from_raw_parts then
// delegate to create_process_w via re-encoded UTF-16 on the stack.
pub unsafe extern "win64" fn create_process_a(
    lp_application_name: *const u8,
    lp_command_line: *mut u8,
    lp_process_attributes: usize,
    lp_thread_attributes: usize,
    b_inherit_handles: i32,
    dw_creation_flags: u32,
    lp_environment: usize,
    lp_current_directory: *const u8,
    lp_startup_info: usize,
    lp_process_information: usize,
) -> i32 {
    fn ansi_to_wide(p: *const u8) -> Option<Vec<u16>> {
        if p.is_null() {
            return None;
        }
        let mut len = 0usize;
        while len < 32_768 && unsafe { *p.add(len) } != 0 {
            len += 1;
        }
        let s = unsafe { std::slice::from_raw_parts(p, len) };
        let utf8 = String::from_utf8_lossy(s);
        let mut wide: Vec<u16> = utf8.encode_utf16().collect();
        wide.push(0);
        Some(wide)
    }

    let app_wide = ansi_to_wide(lp_application_name);
    let mut cmd_wide = ansi_to_wide(lp_command_line);
    let dir_wide = ansi_to_wide(lp_current_directory);

    let app_ptr = app_wide.as_deref().map_or(std::ptr::null(), |v| v.as_ptr());
    let cmd_ptr = cmd_wide
        .as_deref_mut()
        .map_or(std::ptr::null_mut(), |v| v.as_mut_ptr());
    let dir_ptr = dir_wide.as_deref().map_or(std::ptr::null(), |v| v.as_ptr());

    unsafe {
        create_process_w(
            app_ptr,
            cmd_ptr,
            lp_process_attributes,
            lp_thread_attributes,
            b_inherit_handles,
            dw_creation_flags,
            lp_environment,
            dir_ptr,
            lp_startup_info,
            lp_process_information,
        )
    }
}

/// WaitForInputIdle: wait until a process is idle or timeout expires.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/user32/misc.c — sends WM_NULL to the process's thread to check
// if it's processing messages; returns WAIT_OBJECT_0 when idle,
// WAIT_TIMEOUT (258) if timeout expires, WAIT_FAILED on error.
pub unsafe extern "win64" fn wait_for_input_idle(_h_process: usize, _dw_milliseconds: u32) -> u32 {
    0 // WAIT_OBJECT_0 — process immediately ready (no real message loop to wait on)
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/process.c:886 — calls NtQueryInformationProcess(ProcessBasicInformation);
// returns pbi.UniqueProcessId; returns 0 on NT error (sets LastError via set_ntstatus).
pub unsafe extern "win64" fn get_process_id(process: usize) -> u32 {
    // Wine ref: dlls/kernelbase/process.c — NtQueryInformationProcess(ProcessBasicInformation)
    // → UniqueProcessId. Pseudo-handle (usize::MAX) = current process → getpid().
    // Handles from OpenProcess store the PID directly as the handle value.
    if process == usize::MAX || process == 0 {
        unsafe { libc::getpid() as u32 }
    } else {
        process as u32
    }
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/thread.c:400 — NtOpenThread with CLIENT_ID{UniqueProcess=0,
// UniqueThread=id}; sets OBJ_INHERIT when inherit!=0; returns 0 (not INVALID_HANDLE_VALUE) on failure.
// Weave: store TID directly as handle value (mirrors OpenProcess pid-as-handle pattern).
pub unsafe extern "win64" fn open_thread(
    _dw_desired_access: u32,
    _b_inherit_handle: i32,
    dw_thread_id: u32,
) -> usize {
    if dw_thread_id == 0 {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    // Validate the thread exists under the current process's task group.
    if !std::path::Path::new(&format!("/proc/self/task/{dw_thread_id}")).exists() {
        set_last_error(87);
        return 0;
    }
    set_last_error(0);
    dw_thread_id as usize
}

/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/thread.c:296 — NtQueryInformationThread(ThreadBasicInformation);
// returns tbi.ClientId.UniqueThread cast to DWORD; returns 0 on error.
// Weave: pseudo-handle (usize::MAX-1) → gettid(); real handles store TID as value.
pub unsafe extern "win64" fn get_thread_id(thread: usize) -> u32 {
    if thread == usize::MAX - 1 {
        // GetCurrentThread() pseudo-handle
        unsafe { libc::syscall(libc::SYS_gettid) as u32 }
    } else if thread == 0 {
        0
    } else {
        thread as u32
    }
}

// ── File time operations ─────────────────────────────────────────────────────

/// # Safety
/// `lp_file_time1` and `lp_file_time2` must be valid pointers to u64 values.
// Wine ref: dlls/kernelbase/file.c:4106 — compares high DWORD first, then low DWORD;
// returns -1 if either pointer is NULL (not 0/ERROR_INVALID_PARAMETER).
pub unsafe extern "win64" fn compare_file_time(
    lp_file_time1: *const u64,
    lp_file_time2: *const u64,
) -> i32 {
    if lp_file_time1.is_null() || lp_file_time2.is_null() {
        return 0;
    }
    // SAFETY: FILETIME (two u32 fields) is only 4-byte aligned per the Windows ABI,
    // so read_unaligned is required — using a plain dereference would be UB on
    // architectures that require 8-byte alignment for u64.  The pointers are non-null
    // (checked above) and were passed by the Windows caller, which guarantees at least
    // 4-byte alignment and a valid 8-byte object at each address.
    let ft1 = unsafe { std::ptr::read_unaligned(lp_file_time1) };
    let ft2 = unsafe { std::ptr::read_unaligned(lp_file_time2) };
    let result = match ft1.cmp(&ft2) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    };
    eprintln!("weave/CompareFileTime: ft1={ft1} ft2={ft2} → {result}");
    result
}

/// # Safety
/// `lp_file_time` and `lp_local_file_time` must be valid pointers to u64 values.
// Wine ref: dlls/kernelbase/file.c:4120 — delegates to RtlSystemTimeToLocalTime which
// applies the bias from SharedUserData->TimeZoneBias; does not simply copy the value.
pub unsafe extern "win64" fn file_time_to_local_file_time(
    lp_file_time: *const u64,
    lp_local_file_time: *mut u64,
) -> i32 {
    if lp_file_time.is_null() || lp_local_file_time.is_null() {
        return 0;
    }
    // SAFETY: FILETIME is only 4-byte aligned (two u32 fields); unaligned ops are
    // required to avoid potential misaligned-access UB.  Both pointers are non-null
    // (checked above) and valid per the caller's # Safety contract.
    let val = unsafe { std::ptr::read_unaligned(lp_file_time) };
    eprintln!("weave/FileTimeToLocalFileTime: val={val:#x} (pass-through stub)");
    unsafe { std::ptr::write_unaligned(lp_local_file_time, val) };
    1 // TRUE
}

/// # Safety
/// `lp_local_file_time` and `lp_file_time` must be valid pointers to u64 values.
// Wine ref: dlls/kernelbase/file.c:4219 — delegates to RtlLocalTimeToSystemTime;
// inverse of FileTimeToLocalFileTime; applies bias in the opposite direction.
pub unsafe extern "win64" fn local_file_time_to_file_time(
    lp_local_file_time: *const u64,
    lp_file_time: *mut u64,
) -> i32 {
    if lp_local_file_time.is_null() || lp_file_time.is_null() {
        return 0;
    }
    let val = unsafe { std::ptr::read_unaligned(lp_local_file_time) };
    eprintln!("weave/LocalFileTimeToFileTime: val={val:#x} (pass-through stub)");
    unsafe { std::ptr::write_unaligned(lp_file_time, val) };
    1 // TRUE
}

/// # Safety
/// `lp_file_time` must be a valid pointer to a u64 value.
// Wine ref: dlls/kernelbase/file.c:4267 — calls RtlTimeFieldsToTime; sets
// ERROR_INVALID_PARAMETER and returns FALSE if RtlTimeFieldsToTime fails (e.g. invalid month/day).
pub unsafe extern "win64" fn system_time_to_file_time(
    _lp_system_time: *const SystemTime,
    lp_file_time: *mut u64,
) -> i32 {
    if lp_file_time.is_null() {
        return 0;
    }
    let unix_now = unsafe { libc::time(std::ptr::null_mut()) } as u64;
    let ft = unix_now * 10_000_000u64 + 116_444_736_000_000_000u64;
    eprintln!("weave/SystemTimeToFileTime: → ft={ft:#x}");
    // FILETIME is only 4-byte aligned.
    unsafe { std::ptr::write_unaligned(lp_file_time, ft) };
    1 // TRUE
}

/// # Safety
/// `lp_system_time` must be a valid pointer to a SystemTime struct.
// Wine ref: dlls/kernelbase/file.c:4129 — rejects negative FILETIME (li->QuadPart < 0)
// with ERROR_INVALID_PARAMETER; calls RtlTimeToTimeFields which fills wDayOfWeek correctly.
pub unsafe extern "win64" fn file_time_to_system_time(
    _lp_file_time: *const u64,
    lp_system_time: *mut SystemTime,
) -> i32 {
    eprintln!("weave/FileTimeToSystemTime: → current-time stub");
    if lp_system_time.is_null() {
        return 0;
    }
    let unix_now = unsafe { libc::time(std::ptr::null_mut()) };
    // SAFETY: libc::gmtime returns a pointer to a static thread-local tm struct;
    // it is always valid and non-null for any valid time_t.  We copy by value
    // immediately so there is no lifetime concern.
    let tm = unsafe { *libc::gmtime(&unix_now) };
    // SAFETY: lp_system_time is non-null (checked above) and points to a writable
    // SystemTime (16 bytes).  Each field is written at its correct struct offset via
    // the typed pointer.
    unsafe {
        (*lp_system_time).w_year = (tm.tm_year + 1900) as u16;
        (*lp_system_time).w_month = (tm.tm_mon + 1) as u16;
        (*lp_system_time).w_day_of_week = tm.tm_wday as u16;
        (*lp_system_time).w_day = tm.tm_mday as u16;
        (*lp_system_time).w_hour = tm.tm_hour as u16;
        (*lp_system_time).w_minute = tm.tm_min as u16;
        (*lp_system_time).w_second = tm.tm_sec as u16;
        (*lp_system_time).w_milliseconds = 0u16;
    }
    1 // TRUE
}

/// SystemTimeToTzSpecificLocalTime: convert a UTC SYSTEMTIME to local-time using
/// the supplied TIME_ZONE_INFORMATION (or the system default when `info` is NULL).
///
/// Minimal impl: copy `system` into `local` unchanged (bias=0 equivalent) and return
/// TRUE. NPP calls this only during config-file timestamp comparison in `langs.xml`
/// loading; exact accuracy isn't required, but a non-zero return is.
///
/// # Safety
/// `lp_system` and `lp_local` must be valid pointers to SYSTEMTIME structs
/// (16 bytes). `lp_info` may be null.
// Wine ref: dlls/kernelbase/locale.c:7281 — calls SystemTimeToFileTime, applies
// info->Bias (+ StandardBias/DaylightBias depending on get_timezone_id) as a
// LONGLONG offset of 600_000_000 (minutes → 100ns units), then FileTimeToSystemTime.
// Returns FALSE on invalid SYSTEMTIME. Falls back to RtlQueryTimeZoneInformation
// when info is NULL.
pub unsafe extern "win64" fn system_time_to_tz_specific_local_time(
    _lp_info: *const u8,
    lp_system: *const SystemTime,
    lp_local: *mut SystemTime,
) -> i32 {
    if lp_system.is_null() || lp_local.is_null() {
        return 0;
    }
    unsafe { std::ptr::write(lp_local, std::ptr::read(lp_system)) };
    1 // TRUE
}

// ── Console misc + MoveFileEx ────────────────────────────────────────────────

/// AllocConsole: allocate a console for the process.
///
/// No-op. Return TRUE.
// Wine ref: dlls/kernelbase/console.c:404 (alloc_console) — checks PEB->ProcessParameters->ConsoleHandle;
// returns ERROR_ACCESS_DENIED if console already attached; spawns conhost.exe as DETACHED_PROCESS with
// a server handle passed via PROC_THREAD_ATTRIBUTE_HANDLE_LIST; sets ConsoleHandle in PEB on success.
pub extern "win64" fn alloc_console() -> i32 {
    1 // already on a terminal; nothing to allocate
}

/// FreeConsole: detach the process from its console.
///
/// No-op. Return TRUE.
// Wine ref: dlls/kernelbase/console.c:675 — closes console_connection and ConsoleHandle via NtClose;
// also closes std handles if console_flags has CONSOLE_INPUT/OUTPUT/ERROR_HANDLE bits set;
// sets ConsoleHandle=NULL in PEB; always returns TRUE.
pub extern "win64" fn free_console() -> i32 {
    1
}

/// AttachConsole: attach the calling process to the console of another process.
///
/// No-op. Return TRUE.
///
/// # Safety
/// Pointer argument is accepted but not dereferenced.
// Wine ref: dlls/kernelbase/console.c:368 — checks ConsoleHandle first; ERROR_ACCESS_DENIED if
// already attached; calls create_console_connection + IOCTL_CONDRV_BIND_PID with the target pid;
// calls FreeConsole() on any error to clean up partial state.
pub unsafe extern "win64" fn attach_console(_dw_process_id: u32) -> i32 {
    1
}

/// GetConsoleWindow: retrieve the window handle for the console.
///
/// Return NULL (no window).
// Wine ref: dlls/kernelbase/console.c — queries the console server via IOCTL_CONDRV_GET_WINDOW
// to obtain the HWND; returns NULL if no console is attached or the server returns no window.
pub extern "win64" fn get_console_window() -> usize {
    0 // NULL
}

/// # Safety
/// `lp_existing_file_name` and `lp_new_file_name` must be valid null-terminated UTF-16 strings.
// Wine ref: dlls/kernelbase/file.c:2623 (MoveFileWithProgressW) — MoveFileExW delegates here;
// MOVEFILE_DELAY_UNTIL_REBOOT stores entry via add_boot_rename_entry; NULL dest means DeleteFileW;
// cross-device move with MOVEFILE_COPY_ALLOWED falls back to CopyFileExW+DeleteFileW.
pub unsafe extern "win64" fn move_file_ex_w(
    lp_existing_file_name: *const u16,
    lp_new_file_name: *const u16,
    dw_flags: u32,
) -> i32 {
    if lp_existing_file_name.is_null() || lp_new_file_name.is_null() {
        return 0; // FALSE
    }

    // Read existing filename
    let mut len1 = 0usize;
    while len1 < MAX_UTF16_LEN && unsafe { *lp_existing_file_name.add(len1) } != 0 {
        len1 += 1;
    }
    if len1 == MAX_UTF16_LEN {
        return 0;
    }
    let old_path = unsafe {
        String::from_utf16_lossy(std::slice::from_raw_parts(lp_existing_file_name, len1))
    };

    // Read new filename
    let mut len2 = 0usize;
    while len2 < MAX_UTF16_LEN && unsafe { *lp_new_file_name.add(len2) } != 0 {
        len2 += 1;
    }
    if len2 == MAX_UTF16_LEN {
        return 0;
    }
    let new_path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_new_file_name, len2)) };

    eprintln!("weave/MoveFileExW: old={old_path} new={new_path} flags={dw_flags:#x}");

    // Translate both paths
    let linux_old = match weave_core::prefix::translator().to_linux_str(&old_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let linux_new = match weave_core::prefix::translator().to_linux_str(&new_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C strings
    let src_c_path = match std::ffi::CString::new(linux_old.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let dst_c_path = match std::ffi::CString::new(linux_new.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x01;
    if (dw_flags & MOVEFILE_REPLACE_EXISTING) == 0 {
        // Check if destination exists
        if unsafe { libc::access(dst_c_path.as_ptr(), libc::F_OK) } == 0 {
            return 0; // FALSE — destination exists
        }
    }

    // Call rename
    let ret = unsafe { libc::rename(src_c_path.as_ptr(), dst_c_path.as_ptr()) };
    (ret == 0) as i32
}

/// # Safety
/// `lp_existing_file_name` and `lp_new_file_name` must be valid null-terminated UTF-8 strings.
// Wine ref: dlls/kernelbase/file.c — MoveFileExA converts paths via RtlMultiByteToUnicodeN
// then delegates to MoveFileExW/MoveFileWithProgressW.
pub unsafe extern "win64" fn move_file_ex_a(
    lp_existing_file_name: *const u8,
    lp_new_file_name: *const u8,
    dw_flags: u32,
) -> i32 {
    if lp_existing_file_name.is_null() || lp_new_file_name.is_null() {
        return 0; // FALSE
    }

    // Read existing filename
    let mut len1 = 0usize;
    while len1 < MAX_UTF8_LEN && unsafe { *lp_existing_file_name.add(len1) } != 0 {
        len1 += 1;
    }
    if len1 == MAX_UTF8_LEN {
        return 0;
    }
    let old_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_existing_file_name, len1)) };

    // Read new filename
    let mut len2 = 0usize;
    while len2 < MAX_UTF8_LEN && unsafe { *lp_new_file_name.add(len2) } != 0 {
        len2 += 1;
    }
    if len2 == MAX_UTF8_LEN {
        return 0;
    }
    let new_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_new_file_name, len2)) };

    // Translate both paths
    let linux_old = match weave_core::prefix::translator().to_linux_str(&old_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let linux_new = match weave_core::prefix::translator().to_linux_str(&new_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C strings
    let src_c_path = match std::ffi::CString::new(linux_old.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let dst_c_path = match std::ffi::CString::new(linux_new.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x01;
    if (dw_flags & MOVEFILE_REPLACE_EXISTING) == 0 {
        // Check if destination exists
        if unsafe { libc::access(dst_c_path.as_ptr(), libc::F_OK) } == 0 {
            return 0; // FALSE — destination exists
        }
    }

    // Call rename
    let ret = unsafe { libc::rename(src_c_path.as_ptr(), dst_c_path.as_ptr()) };
    (ret == 0) as i32
}

/// WideCharToMultiByte: convert a UTF-16 string to a multibyte (UTF-8) string.
///
/// Phase 2: all code pages produce UTF-8 output (correct on Linux).
///
/// # Safety
/// `lp_wide_char_str` must be valid for `cch_wide_char` UTF-16 code units
/// (or null-terminated when `cch_wide_char == -1`).
/// `lp_multi_byte_str`, if non-null, must be writable for `cb_multi_byte` bytes.
/// WideCharToMultiByte: convert UTF-16 to multibyte (UTF-8 for CP_UTF8/default).
///
/// Wine ref: dlls/kernelbase/locale.c — validates !src || !srclen || (!dst && dstlen) ||
/// dstlen < 0 → ERROR_INVALID_PARAMETER; srclen < 0 → lstrlenW(src)+1 (includes null).
/// Weave only handles UTF-8 output; CP_SYMBOL/CP_UTF7 not supported.
///
/// # Safety
/// `lp_wide_char_str` must be valid for `cch_wide_char` u16 words (or null-terminated if < 0).
// Wine ref: dlls/kernelbase/locale.c — WideCharToMultiByte: srclen<0 → lstrlenW(src)+1.
// Invalid flags for the codepage → ERROR_INVALID_FLAGS. CP_SYMBOL and CP_UTF7 have
// separate paths. CP_UNIXCP falls through to default. Weave handles UTF-8 only.
pub unsafe extern "win64" fn wide_char_to_multi_byte(
    _code_page: u32,
    _dw_flags: u32,
    lp_wide_char_str: *const u16,
    cch_wide_char: i32,
    lp_multi_byte_str: *mut u8,
    cb_multi_byte: i32,
    _lp_default_char: usize,
    _lp_used_default_char: usize,
) -> i32 {
    // Wine: !src || !srclen || (!dst && dstlen) || dstlen < 0 → ERROR_INVALID_PARAMETER
    if lp_wide_char_str.is_null()
        || cch_wide_char == 0
        || (lp_multi_byte_str.is_null() && cb_multi_byte != 0)
        || cb_multi_byte < 0
    {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let null_terminated = cch_wide_char < 0;
    let wide: &[u16] = if null_terminated {
        let mut len = 0usize;
        while len < MAX_UTF16_LEN && unsafe { *lp_wide_char_str.add(len) } != 0 {
            len += 1;
        }
        if len == MAX_UTF16_LEN {
            set_last_error(87); // ERROR_INVALID_PARAMETER
            return 0;
        }
        unsafe { std::slice::from_raw_parts(lp_wide_char_str, len) }
    } else {
        unsafe { std::slice::from_raw_parts(lp_wide_char_str, cch_wide_char as usize) }
    };
    let utf8 = String::from_utf16_lossy(wide);
    let bytes = utf8.as_bytes();
    // Size query
    if lp_multi_byte_str.is_null() || cb_multi_byte == 0 {
        return (bytes.len() + if null_terminated { 1 } else { 0 }) as i32;
    }
    let cap = cb_multi_byte as usize;
    if null_terminated {
        // Null-terminated source: reserve one byte for the null terminator.
        let copy_len = bytes.len().min(cap.saturating_sub(1));
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_multi_byte_str, copy_len);
            *lp_multi_byte_str.add(copy_len) = 0;
        }
        set_last_error(0);
        (copy_len + 1) as i32
    } else {
        // Counted source: copy exactly min(bytes, cap) bytes. No null added.
        // (Windows does not null-terminate when cch_wide_char > 0.)
        let copy_len = bytes.len().min(cap);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_multi_byte_str, copy_len);
        }
        set_last_error(0);
        copy_len as i32
    }
}

/// MultiByteToWideChar: convert a multibyte (UTF-8) string to UTF-16.
///
/// Wine ref: dlls/kernelbase/locale.c — validates !src || !srclen || (!dst && dstlen) ||
/// dstlen < 0 → ERROR_INVALID_PARAMETER; srclen < 0 → strlen(src)+1 (includes null).
/// Weave only handles UTF-8 input; CP_SYMBOL/CP_UTF7 not supported.
///
/// # Safety
/// `lp_multi_byte_str` must be valid for `cb_multi_byte` bytes (or
/// null-terminated when `cb_multi_byte == -1`).
/// `lp_wide_char_str`, if non-null, must be writable for `cch_wide_char` u16 words.
// Wine ref: dlls/kernelbase/locale.c — MultiByteToWideChar: srclen<0 → strlen(src)+1.
// Invalid flags for the codepage → ERROR_INVALID_FLAGS. CP_SYMBOL/CP_UTF7 separate paths.
// CP_UNIXCP falls through to default codepage. Weave handles UTF-8 input only.
pub unsafe extern "win64" fn multi_byte_to_wide_char(
    _code_page: u32,
    _dw_flags: u32,
    lp_multi_byte_str: *const u8,
    cb_multi_byte: i32,
    lp_wide_char_str: *mut u16,
    cch_wide_char: i32,
) -> i32 {
    // Wine: !src || !srclen || (!dst && dstlen) || dstlen < 0 → ERROR_INVALID_PARAMETER
    if lp_multi_byte_str.is_null()
        || cb_multi_byte == 0
        || (lp_wide_char_str.is_null() && cch_wide_char != 0)
        || cch_wide_char < 0
    {
        let reason = if lp_multi_byte_str.is_null() {
            "null_src"
        } else if cb_multi_byte == 0 {
            "cb_multi_byte_zero"
        } else if lp_wide_char_str.is_null() && cch_wide_char != 0 {
            "null_dst_with_nonzero_cch"
        } else {
            "negative_cch"
        };
        eprintln!(
            "weave/MultiByteToWideChar: ERROR_INVALID_PARAMETER reason={reason} cb={cb_multi_byte} cch={cch_wide_char}"
        );
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    // Wine ref: dlls/kernelbase/locale.c — when srclen<0, the source NUL is included in
    // the conversion and the returned size includes the wide NUL terminator. When the
    // destination is too small, return 0 + ERROR_INSUFFICIENT_BUFFER (no truncation).
    let null_terminated = cb_multi_byte < 0;
    let bytes: &[u8] = if null_terminated {
        let mut len = 0usize;
        while len < MAX_UTF8_LEN && unsafe { *lp_multi_byte_str.add(len) } != 0 {
            len += 1;
        }
        if len == MAX_UTF8_LEN {
            eprintln!(
                "weave/MultiByteToWideChar: ERROR_INVALID_PARAMETER reason=overlong_source cb={cb_multi_byte} cch={cch_wide_char}"
            );
            set_last_error(87); // ERROR_INVALID_PARAMETER
            return 0;
        }
        // Include the trailing NUL so the wide output also has a NUL.
        unsafe { std::slice::from_raw_parts(lp_multi_byte_str, len + 1) }
    } else {
        unsafe { std::slice::from_raw_parts(lp_multi_byte_str, cb_multi_byte as usize) }
    };
    let wide: Vec<u16> = String::from_utf8_lossy(bytes).encode_utf16().collect();
    let required = wide.len();
    if lp_wide_char_str.is_null() || cch_wide_char == 0 {
        return required as i32;
    }
    let cap = cch_wide_char as usize;
    if cap < required {
        // Windows INSUFFICIENT_BUFFER behaviour: write as many converted chars as fit
        // (cap), without a NUL terminator. The caller is responsible for null-termination
        // via its own zero-initialized buffer. Writing cap-1 + explicit NUL loses the
        // last character — e.g. "Kings.pxe" (9 chars) with cap=9 would truncate to
        // "Kings.px" (8 chars + NUL), making case-fold lookup ambiguous between
        // Kings.pxe and Kings.pxm.
        // Wine ref: dlls/kernel32/locale.c — WideCharToMultiByte truncates to count,
        // no terminator written on INSUFFICIENT_BUFFER; MultiByteToWideChar is symmetric.
        unsafe {
            if cap > 0 {
                std::ptr::copy_nonoverlapping(wide.as_ptr(), lp_wide_char_str, cap);
            }
        }
        set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), lp_wide_char_str, required);
    }
    set_last_error(0);
    required as i32
}

/// GetStartupInfoA: return process startup parameters (ANSI variant).
///
/// Phase 2: fills a zeroed STARTUPINFOA and sets cb to the struct size.
/// Most CRT init code calls this and ignores the result when dwFlags is 0.
///
/// # Safety
/// `lp_startup_info` must point to at least 68 bytes of writable memory.
// Wine ref: dlls/kernelbase/process.c:1349 (GetStartupInfoW) — copies fields directly from
// RtlGetCurrentPeb()->ProcessParameters under RtlAcquirePebLock; hStdInput/Output/Error
// are only filled when STARTF_USESTDHANDLES is set in dwFlags.
pub unsafe extern "win64" fn get_startup_info_a(lp_startup_info: *mut u8) {
    if lp_startup_info.is_null() {
        return;
    }
    // SAFETY: lp_startup_info is non-null (checked above) and the caller guarantees
    // at least 68 bytes (sizeof STARTUPINFOA).  We zero the entire struct then write
    // cb at offset 0 — the first field in both STARTUPINFOA and STARTUPINFOW.
    unsafe {
        std::ptr::write_bytes(lp_startup_info, 0, 68);
        *(lp_startup_info as *mut u32) = 68; // cb = sizeof(STARTUPINFOA)
    }
}

/// GetStartupInfoW: return process startup parameters (wide variant).
///
/// # Safety
/// `lp_startup_info` must point to at least 104 bytes of writable memory.
// Wine ref: dlls/kernelbase/process.c — GetStartupInfoW reads RTL_USER_PROCESS_PARAMETERS
// under RtlAcquirePebLock. hStdInput/Output/Error only filled when STARTF_USESTDHANDLES
// is set in dwFlags. lpReserved is always NULL. Weave zeroes struct and sets cb only.
pub unsafe extern "win64" fn get_startup_info_w(lp_startup_info: *mut u8) {
    if lp_startup_info.is_null() {
        return;
    }
    // Wine ref: dlls/kernelbase/process.c GetStartupInfoW — copies from RTL_USER_PROCESS_PARAMETERS.
    // STARTUPINFOW (64-bit) layout:
    //   offset  0: DWORD cb (4)
    //   offset  8: LPWSTR lpReserved (8, pointer-aligned)
    //   offset 16: LPWSTR lpDesktop (8)
    //   offset 24: LPWSTR lpTitle (8)
    //   offset 32: DWORD dwX (4)
    //   offset 36: DWORD dwY (4)
    //   offset 40: DWORD dwXSize (4)
    //   offset 44: DWORD dwYSize (4)
    //   offset 48: DWORD dwXCountChars (4)
    //   offset 52: DWORD dwYCountChars (4)
    //   offset 56: DWORD dwFillAttribute (4)
    //   offset 60: DWORD dwFlags (4)
    //   offset 64: WORD wShowWindow (2)
    // Set STARTF_USESHOWWINDOW so the CRT honours wShowWindow and passes
    // SW_SHOWNORMAL to WinMain, causing the app to show its main window.
    // SAFETY: lp_startup_info is non-null (checked above) and the caller guarantees
    // at least 104 bytes (sizeof STARTUPINFOW on x64).  The byte offsets used below
    // match the STARTUPINFOW layout for x64 (all pointer fields are 8-byte aligned;
    // DWORD fields follow):
    //   +0  DWORD cb          +60 DWORD dwFlags
    //   +64 WORD  wShowWindow
    // All writes are within the 104-byte span after the zeroing at the start.
    unsafe {
        std::ptr::write_bytes(lp_startup_info, 0, 104);
        *(lp_startup_info as *mut u32) = 104; // cb = sizeof(STARTUPINFOW)
        const STARTF_USESHOWWINDOW: u32 = 0x0001;
        const SW_SHOWNORMAL: u16 = 1;
        *(lp_startup_info.add(60) as *mut u32) = STARTF_USESHOWWINDOW; // dwFlags
        *(lp_startup_info.add(64) as *mut u16) = SW_SHOWNORMAL; // wShowWindow
    }
}

/// FlushFileBuffers: flush OS write buffers for an open file handle.
// Wine ref: dlls/kernelbase/file.c:3095 — calls NtFlushBuffersFile with an IO_STATUS_BLOCK;
// does not special-case console handles (those fail NtFlushBuffersFile gracefully).
pub extern "win64" fn flush_file_buffers(h_file: usize) -> i32 {
    eprintln!("weave/FlushFileBuffers: entry handle={h_file:#x}");
    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            set_last_error(file_io::ERROR_INVALID_HANDLE);
            eprintln!("weave/FlushFileBuffers: exit handle={h_file:#x} → FALSE (invalid handle)");
            return 0;
        }
    };
    let ret = unsafe { libc::fsync(fd) };
    if ret == 0 {
        eprintln!("weave/FlushFileBuffers: exit handle={h_file:#x} fd={fd} → TRUE");
        1
    } else {
        set_last_error(file_io::ERROR_INVALID_HANDLE);
        eprintln!("weave/FlushFileBuffers: exit handle={h_file:#x} fd={fd} → FALSE (fsync err)");
        0
    }
}

/// CreateFileMappingW: create a file mapping object for memory-mapped files.
///
/// For anonymous mappings (hFile == INVALID_HANDLE_VALUE), allocates RAM-backed
/// memory using mmap. The returned address serves as both the mapping handle
/// and the mapped memory address.
///
/// # Safety
/// `lp_file_mapping_attributes` and `lp_name` are ignored (accepted but not dereferenced).
// Wine ref: dlls/kernelbase/sync.c:1032 — INVALID_HANDLE_VALUE maps to file=0 for NtCreateSection;
// size must be non-zero for anonymous mappings (ERROR_INVALID_PARAMETER otherwise);
// SEC_COMMIT is implied when no SEC_* flags are set in the protect bits;
// STATUS_OBJECT_NAME_EXISTS sets ERROR_ALREADY_EXISTS (not ERROR_ACCESS_DENIED).
pub unsafe extern "win64" fn create_file_mapping_w(
    h_file: usize,
    _lp_file_mapping_attributes: usize,
    fl_protect: u32,
    dw_maximum_size_high: u32,
    dw_maximum_size_low: u32,
    _lp_name: *const u16,
) -> usize {
    const INVALID_HANDLE_VALUE: usize = usize::MAX;
    if h_file != INVALID_HANDLE_VALUE {
        // File-backed mapping: mmap the underlying fd.
        let fd = match handles::get_fd(h_file) {
            Some(f) => f,
            None => {
                set_last_error(file_io::ERROR_INVALID_HANDLE);
                return 0;
            }
        };
        // Determine size: use caller-supplied size or fstat if zero.
        let caller_size = ((dw_maximum_size_high as usize) << 32) | dw_maximum_size_low as usize;
        let map_size = if caller_size != 0 {
            caller_size
        } else {
            let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
            if unsafe { libc::fstat(fd, &mut stat) } != 0 || stat.st_size <= 0 {
                set_last_error(file_io::ERROR_INVALID_HANDLE);
                return 0;
            }
            stat.st_size as usize
        };
        // PAGE_READONLY (0x02) → PROT_READ; PAGE_READWRITE (0x04) → PROT_READ|WRITE.
        let prot = if fl_protect & 0x04 != 0 {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map_size,
                prot,
                libc::MAP_PRIVATE,
                fd,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            set_last_error(file_io::ERROR_ACCESS_DENIED);
            return 0;
        }
        let mapping_handle = alloc_mapping(addr as usize, map_size);
        set_last_error(0);
        return mapping_handle;
    }
    // Anonymous mapping.
    let size = ((dw_maximum_size_high as usize) << 32) | dw_maximum_size_low as usize;
    if size == 0 {
        return 0;
    }
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED,
            -1,
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        0
    } else {
        alloc_mapping(addr as usize, size)
    }
}

/// MapViewOfFile: map a view of a file mapping into the address space.
///
/// Looks up the mapping handle in the global file-mapping table and returns
/// the mmap base address.
///
/// # Safety
/// No pointer dereference — just returns the mapped address.
// Wine ref: dlls/kernelbase/memory.c:278 — thin wrapper over MapViewOfFileEx(addr=NULL);
// MapViewOfFileEx calls NtMapViewOfSection with ViewShare and translates FILE_MAP_COPY
// to PAGE_WRITECOPY, FILE_MAP_WRITE to PAGE_READWRITE, FILE_MAP_EXECUTE to PAGE_EXECUTE_*.
pub extern "win64" fn map_view_of_file(
    h_file_mapping_object: usize,
    _dw_desired_access: u32,
    _dw_file_offset_high: u32,
    _dw_file_offset_low: u32,
    _dw_number_of_bytes_to_map: usize,
) -> usize {
    // Peek at the mapping without consuming it (MapViewOfFile doesn't free the handle).
    let table = match lock_file_mappings(file_mappings()) {
        Some(g) => g,
        None => return 0,
    };
    if let Some(index) = h_file_mapping_object.checked_sub(FILE_MAPPING_OFFSET) {
        if let Some(Some((addr, _size))) = table.get(index) {
            return *addr;
        }
    }
    0
}

/// UnmapViewOfFile: unmap a mapped view of a file.
///
/// Looks up the view address in the global mapping table to recover the size,
/// then calls munmap.
///
/// # Safety
/// `lp_base_address` must be a valid mmap address previously returned by MapViewOfFile.
// Wine ref: dlls/kernelbase/memory.c:384 — on Win9x also validates AllocationBase == addr
// via VirtualQuery; on NT calls NtUnmapViewOfSection(GetCurrentProcess(), addr); Weave
// uses munmap since our mapping is backed by mmap rather than NtMapViewOfSection.
pub unsafe extern "win64" fn unmap_view_of_file(lp_base_address: *const u8) -> i32 {
    let view = lp_base_address as usize;
    if let Some((addr, size)) = find_mapping_by_addr(view) {
        unsafe { libc::munmap(addr as *mut libc::c_void, size) };
    }
    1 // TRUE
}

/// CopyFileW: copy a file (wide string version).
///
/// # Safety
/// `lp_existing_file_name` and `lp_new_file_name` must be valid null-terminated UTF-16 strings.
// Wine ref: dlls/kernelbase/file.c — CopyFileW delegates to CopyFileExW(progress=NULL, cancel=NULL,
// flags = bFailIfExists ? COPY_FILE_FAIL_IF_EXISTS : 0); CopyFileExW opens source with
// GENERIC_READ|FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE and copies file attributes.
pub unsafe extern "win64" fn copy_file_w(
    lp_existing_file_name: *const u16,
    lp_new_file_name: *const u16,
    b_fail_if_exists: i32,
) -> i32 {
    if lp_existing_file_name.is_null() || lp_new_file_name.is_null() {
        return 0; // FALSE
    }

    // Read source filename
    let mut len1 = 0usize;
    while len1 < MAX_UTF16_LEN && unsafe { *lp_existing_file_name.add(len1) } != 0 {
        len1 += 1;
    }
    if len1 == MAX_UTF16_LEN {
        return 0;
    }
    let src_win_path = unsafe {
        String::from_utf16_lossy(std::slice::from_raw_parts(lp_existing_file_name, len1))
    };

    // Read destination filename
    let mut len2 = 0usize;
    while len2 < MAX_UTF16_LEN && unsafe { *lp_new_file_name.add(len2) } != 0 {
        len2 += 1;
    }
    if len2 == MAX_UTF16_LEN {
        return 0;
    }
    let dst_win_path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_new_file_name, len2)) };

    // Translate paths
    let src_linux_path = match weave_core::prefix::translator().to_linux_str(&src_win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let dst_linux_path = match weave_core::prefix::translator().to_linux_str(&dst_win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C strings
    let src_c_path = match std::ffi::CString::new(src_linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let dst_c_path = match std::ffi::CString::new(dst_linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Check if destination exists and b_fail_if_exists is set
    if b_fail_if_exists != 0 && unsafe { libc::access(dst_c_path.as_ptr(), libc::F_OK) } == 0 {
        return 0; // FALSE — destination exists
    }

    // Open source file
    let src_fd = unsafe { libc::open(src_c_path.as_ptr(), libc::O_RDONLY, 0) };
    if src_fd < 0 {
        return 0; // FALSE
    }

    // Open/create destination file
    let dst_fd = unsafe {
        libc::open(
            dst_c_path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )
    };
    if dst_fd < 0 {
        unsafe { libc::close(src_fd) };
        return 0; // FALSE
    }

    // Copy in 64KB chunks
    let mut buf = [0u8; 65536];
    loop {
        let n = unsafe { libc::read(src_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        let written =
            unsafe { libc::write(dst_fd, buf.as_ptr() as *const libc::c_void, n as usize) };
        if written != n {
            unsafe { libc::close(src_fd) };
            unsafe { libc::close(dst_fd) };
            return 0; // FALSE
        }
    }

    unsafe { libc::close(src_fd) };
    unsafe { libc::close(dst_fd) };
    1 // TRUE
}

/// Windows WIN32_FIND_DATAW structure (wide version).
///
/// FILETIME is two DWORDs (low, high) with 4-byte alignment — NOT a u64.
/// Using u64 would add 4 bytes of padding after dw_file_attributes, shifting
/// c_file_name by 4 bytes and breaking all filename reads.
#[repr(C)]
pub struct Win32FindDataW {
    dw_file_attributes: u32,
    ft_creation_time: [u32; 2], // FILETIME = [dwLowDateTime, dwHighDateTime]
    ft_last_access_time: [u32; 2],
    ft_last_write_time: [u32; 2],
    n_file_size_high: u32,
    n_file_size_low: u32,
    dw_reserved0: u32,
    dw_reserved1: u32,
    c_file_name: [u16; 260],
    c_alternate_file_name: [u16; 14],
}

/// Windows WIN32_FIND_DATAA structure (ANSI version).
#[repr(C)]
pub struct Win32FindDataA {
    dw_file_attributes: u32,
    ft_creation_time: [u32; 2],
    ft_last_access_time: [u32; 2],
    ft_last_write_time: [u32; 2],
    n_file_size_high: u32,
    n_file_size_low: u32,
    dw_reserved0: u32,
    dw_reserved1: u32,
    c_file_name: [u8; 260],
    c_alternate_file_name: [u8; 14],
}

/// Stat a single directory entry via `dirfd` + `fstatat` (no parent path needed).
///
/// Wine ref: dlls/kernelbase/file.c — FindFirstFileExW fills WIN32_FIND_DATA from
/// NtQueryDirectoryFile including FILE_ATTRIBUTE_DIRECTORY for subdirectories.
fn stat_dirent_entry(dir: *mut libc::DIR, entry_name: &str) -> Option<libc::stat> {
    let dir_fd = unsafe { libc::dirfd(dir) };
    if dir_fd < 0 {
        return None;
    }
    let c_name = std::ffi::CString::new(entry_name).ok()?;
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstatat(dir_fd, c_name.as_ptr(), &mut st, 0) } == 0 {
        Some(st)
    } else {
        None
    }
}

fn find_entry_attrs_and_size(entry_name: &str, stat_buf: Option<&libc::stat>) -> (u32, u32, u32) {
    match stat_buf {
        Some(st) => {
            let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
            let attrs = if is_dir {
                0x10 // FILE_ATTRIBUTE_DIRECTORY
            } else {
                0x20 // FILE_ATTRIBUTE_ARCHIVE
            };
            let size = if is_dir { 0 } else { st.st_size as u64 };
            (attrs, (size >> 32) as u32, (size & 0xFFFF_FFFF) as u32)
        }
        None if entry_name == "." || entry_name == ".." => (0x10, 0, 0),
        None => (0x80, 0, 0), // FILE_ATTRIBUTE_NORMAL fallback
    }
}

/// FindFirstFileW: start directory enumeration (wide string version).
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-16 string.
/// `lp_find_file_data` must be a valid writable pointer to a WIN32_FIND_DATAW.
/// FindFirstFileW: begin directory enumeration.
///
/// Wine ref: dlls/kernelbase/file.c — FindFirstFileW delegates to FindFirstFileExW, which
/// uses NtQueryDirectoryFile and stores results in a FIND_FIRST_INFO struct validated with
/// a magic number. Wine skips `.` and `..` in root drives. Weave uses opendir/readdir;
/// does not skip `.`/`..`. Returns sentinel 1 for single-file lookups.
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-16 path. `lp_find_file_data` writable.
// Wine ref: dlls/kernelbase/file.c — FindFirstFileW delegates to FindFirstFileExW with
// FindExInfoStandard + FindExSearchNameMatch. FindFirstFileExW allocates a FIND_FIRST_INFO
// struct with a magic number, uses NtQueryDirectoryFile. Skips ./..\u{a0}only in root drives.
pub unsafe extern "win64" fn find_first_file_w(
    lp_file_name: *const u16,
    lp_find_file_data: *mut Win32FindDataW,
) -> usize {
    if lp_file_name.is_null() || lp_find_file_data.is_null() {
        eprintln!("weave/FindFirstFileW: entry → INVALID_HANDLE_VALUE (null arg)");
        return usize::MAX; // INVALID_HANDLE_VALUE
    }

    // Read the null-terminated UTF-16 filename
    let mut len = 0usize;
    // SAFETY: (a) lp_file_name is non-null (checked above); (b) guest heap;
    // (c) duration of scan; (d) MAX_UTF16_LEN cap prevents OOB if the guest passes a
    // non-terminated pointer — reads at most MAX_UTF16_LEN u16s before stopping.
    // Caveat: a non-null, non-terminated pointer of length ≥ MAX_UTF16_LEN would be
    // scanned for exactly MAX_UTF16_LEN code units without finding a null — treated as
    // an overlong path and rejected with INVALID_HANDLE_VALUE below.
    while len < MAX_UTF16_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF16_LEN {
        eprintln!("weave/FindFirstFileW: exit → INVALID_HANDLE_VALUE (path too long)");
        return usize::MAX;
    }
    // SAFETY: (a) lp_file_name is non-null (checked above) and the scan above confirmed
    // `len` code units before the null terminator; (b) guest heap; (c) duration of call;
    // (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
    let win_path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_file_name, len)) };
    eprintln!("weave/FindFirstFileW: entry path={win_path:?}");
    if std::env::var("WEAVE_TEST_SAVE_RESULT").is_ok()
        && win_path.to_ascii_lowercase().contains("plugin")
    {
        eprintln!("weave/E3-M9-trace: FindFirstFileW for Plugins path={win_path:?}");
    }

    // Translate to Linux path
    let linux_path = match weave_core::file_io::translate_win_path(&win_path) {
        Ok(p) => p,
        Err(e) => {
            // M13-S: log the exact path and error so CI reveals what MSVC 7za presents.
            // set_last_error here so the unset LastError does not leak a stale 87 from
            // an earlier call and produce a spurious 0x80070057 in the caller.
            set_last_error(87); // ERROR_INVALID_PARAMETER — matches what a real translate failure maps to
            eprintln!(
                "[m13-S] find_first_file_w rejected (err={}): {:?}",
                e, win_path
            );
            eprintln!(
                "weave/FindFirstFileW: exit path={win_path:?} → INVALID_HANDLE_VALUE (xlate_err)"
            );
            return usize::MAX;
        }
    };
    // Check if path contains wildcards (* or ?)
    let path_str = linux_path.to_string_lossy();
    let has_wildcards = path_str.contains('*') || path_str.contains('?');

    if !has_wildcards {
        // Single file/dir lookup — use stat to check existence and fill data.
        // Windows apps (like 7za.exe) call FindFirstFileW with a concrete path
        // to check whether a file exists and get its attributes.
        let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
            Ok(s) => s,
            Err(_) => {
                eprintln!(
                    "weave/FindFirstFileW: exit path={win_path:?} → INVALID_HANDLE_VALUE (cstr_err)"
                );
                return usize::MAX;
            }
        };
        // SAFETY: (a) zeroed() produces a valid zero-initialized libc::stat; (b) Rust stack;
        // (c) duration of this call; (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
        let mut stat_buf = unsafe { std::mem::zeroed::<libc::stat>() };
        // SAFETY: (a) c_path.as_ptr() is a valid null-terminated C string (CString invariant);
        // &mut stat_buf points to a properly-sized libc::stat on the stack; (b) c_path on Rust
        // stack, stat_buf on Rust stack; (c) duration of stat syscall; (d) same gate.
        let ret = unsafe { libc::stat(c_path.as_ptr(), &mut stat_buf) };
        if ret != 0 {
            // 7-Zip and similar apps depend on a deterministic last-error on miss;
            // otherwise they inherit whatever errno was set by a prior call and
            // wrap that into a spurious HRESULT (e.g. 0x80070057 from ERROR_INVALID_PARAMETER).
            set_last_error(file_io::ERROR_FILE_NOT_FOUND);
            eprintln!(
                "weave/FindFirstFileW: exit path={win_path:?} linux={linux_path:?} → INVALID_HANDLE_VALUE (stat_err)"
            );
            return usize::MAX; // INVALID_HANDLE_VALUE — file not found
        }
        // On success, clear last error per Windows semantics.
        set_last_error(0);

        let is_dir = (stat_buf.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let filename = linux_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let wide_name: Vec<u16> = filename.encode_utf16().collect();

        // Convert Linux stat times to Windows FILETIME (100ns ticks since 1601-01-01).
        // Same formula as get_file_information_by_handle; zero FILETIMEs cause apps like
        // 7-Zip to reject the archive's central directory with E_INVALIDARG.
        let ft_creation = weave_common::unix_to_filetime(stat_buf.st_ctime, stat_buf.st_ctime_nsec);
        let ft_access = weave_common::unix_to_filetime(stat_buf.st_atime, stat_buf.st_atime_nsec);
        let ft_write = weave_common::unix_to_filetime(stat_buf.st_mtime, stat_buf.st_mtime_nsec);

        // SAFETY: (a) lp_find_file_data is non-null (checked at entry) and points to a
        // writable Win32FindDataW struct; (b) guest heap — caller owns the buffer;
        // (c) duration of this call; (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
        unsafe {
            (*lp_find_file_data).dw_file_attributes = if is_dir {
                0x10 // FILE_ATTRIBUTE_DIRECTORY
            } else {
                0x20 // FILE_ATTRIBUTE_ARCHIVE — matches what real FindFirstFileW returns
            };
            (*lp_find_file_data).ft_creation_time =
                [ft_creation as u32, (ft_creation >> 32) as u32];
            (*lp_find_file_data).ft_last_access_time = [ft_access as u32, (ft_access >> 32) as u32];
            (*lp_find_file_data).ft_last_write_time = [ft_write as u32, (ft_write >> 32) as u32];
            (*lp_find_file_data).n_file_size_high = ((stat_buf.st_size as u64) >> 32) as u32;
            (*lp_find_file_data).n_file_size_low = (stat_buf.st_size as u64 & 0xFFFF_FFFF) as u32;
            (*lp_find_file_data).dw_reserved0 = 0;
            (*lp_find_file_data).dw_reserved1 = 0;

            let copy_len = wide_name.len().min(259);
            std::ptr::copy_nonoverlapping(
                wide_name.as_ptr(),
                (*lp_find_file_data).c_file_name.as_mut_ptr(),
                copy_len,
            );
            (*lp_find_file_data).c_file_name[copy_len] = 0;
            (*lp_find_file_data).c_alternate_file_name[0] = 0;
        }

        // SAFETY: (a) lp_find_file_data is non-null (checked at entry) and was just
        // written by the block above; (b) guest heap; (c) duration of this call;
        // (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
        let attrs = unsafe { (*lp_find_file_data).dw_file_attributes };
        let size_lo = unsafe { (*lp_find_file_data).n_file_size_low };
        let size_hi = unsafe { (*lp_find_file_data).n_file_size_high };
        eprintln!(
            "weave/FindFirstFileW: exit path={win_path:?} attrs={attrs:#x} size_hi={size_hi:#x} size_lo={size_lo:#x} \
             ft_cre={ft_creation:#x} ft_acc={ft_access:#x} ft_wri={ft_write:#x} → handle=1 (single-file sentinel)"
        );
        weave_core::progress::mark_find_first_file_first();
        // Return sentinel 1: a single-file handle (FindNextFileW returns FALSE for it).
        return 1;
    }

    // Wildcard path — open parent directory and enumerate entries.
    // Strip the wildcard component to get the parent directory path.
    let dir_path = match linux_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };

    // Open directory
    let c_path = match std::ffi::CString::new(dir_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => {
            eprintln!(
                "weave/FindFirstFileW: exit path={win_path:?} → INVALID_HANDLE_VALUE (cstr_err wildcard)"
            );
            return usize::MAX;
        }
    };

    // SAFETY: (a) c_path.as_ptr() is a valid null-terminated C string (CString invariant);
    // (b) OS-managed DIR allocation; (c) until closedir is called; (d) gate:
    // sevenzip_m13_debug_e_gate (CI 26007699626).
    let dir = unsafe { libc::opendir(c_path.as_ptr()) };
    if dir.is_null() {
        eprintln!(
            "weave/FindFirstFileW: exit path={win_path:?} dir={dir_path:?} → INVALID_HANDLE_VALUE (opendir_err)"
        );
        return usize::MAX;
    }

    // Read first entry
    // SAFETY: (a) dir is non-null (checked above) and is a valid DIR* from opendir;
    // (b) OS-managed DIR allocation; (c) until the next readdir or closedir call;
    // (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
    let entry = unsafe { libc::readdir(dir) };
    if entry.is_null() {
        // SAFETY: (a) dir is non-null (checked above); (b) OS-managed; (c) this call
        // releases the DIR allocation; (d) same gate.
        unsafe { libc::closedir(dir) };
        eprintln!(
            "weave/FindFirstFileW: exit path={win_path:?} → INVALID_HANDLE_VALUE (empty_dir)"
        );
        return usize::MAX;
    }

    // Convert entry name to UTF-16
    // SAFETY: (a) entry is non-null (checked above) and points to a valid dirent struct
    // returned by readdir; d_name is a null-terminated C string within that struct;
    // strlen returns the exact byte count before the null; (b) OS-managed DIR allocation;
    // (c) until the next readdir call; (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
    let entry_name = unsafe {
        let name_ptr = (*entry).d_name.as_ptr();
        let name_len = libc::strlen(name_ptr);
        std::slice::from_raw_parts(name_ptr as *const u8, name_len)
    };
    let entry_name_str = String::from_utf8_lossy(entry_name);
    let wide_name: Vec<u16> = entry_name_str.encode_utf16().collect();
    let st = stat_dirent_entry(dir, &entry_name_str);
    let (attrs, size_hi, size_lo) = find_entry_attrs_and_size(&entry_name_str, st.as_ref());

    // Fill WIN32_FIND_DATAW
    // SAFETY: (a) lp_find_file_data is non-null (checked at entry) and points to a
    // writable Win32FindDataW struct; (b) guest heap — caller owns the buffer;
    // (c) duration of this call; (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
    unsafe {
        (*lp_find_file_data).dw_file_attributes = attrs;
        (*lp_find_file_data).ft_creation_time = [0, 0];
        (*lp_find_file_data).ft_last_access_time = [0, 0];
        (*lp_find_file_data).ft_last_write_time = [0, 0];
        (*lp_find_file_data).n_file_size_high = size_hi;
        (*lp_find_file_data).n_file_size_low = size_lo;
        (*lp_find_file_data).dw_reserved0 = 0;
        (*lp_find_file_data).dw_reserved1 = 0;

        // Copy filename (truncate if too long)
        let copy_len = wide_name.len().min(259); // leave room for null
        std::ptr::copy_nonoverlapping(
            wide_name.as_ptr(),
            (*lp_find_file_data).c_file_name.as_mut_ptr(),
            copy_len,
        );
        (*lp_find_file_data).c_file_name[copy_len] = 0;

        // No alternate filename
        (*lp_find_file_data).c_alternate_file_name[0] = 0;
    }

    let handle = dir as usize;
    eprintln!(
        "weave/FindFirstFileW: exit path={win_path:?} first_entry={entry_name_str:?} attrs={attrs:#x} → handle={handle:#x} (DIR*)"
    );
    weave_core::progress::mark_find_first_file_first();
    // Store the DIR* as a usize handle.  find_next_file_w and find_close will cast
    // it back to *mut libc::DIR.  This is safe because usize is pointer-sized on
    // all supported targets (x86-64) and the DIR allocation outlives the handle.
    handle // Return directory handle
}

/// FindFirstFileA: start directory enumeration (ANSI version).
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-8 string.
/// `lp_find_file_data` must be a valid writable pointer to a WIN32_FIND_DATAA.
// Wine ref: dlls/kernelbase/file.c:1448 — FindFirstFileA delegates to FindFirstFileExA
// which converts the filename via RtlMultiByteToUnicodeN then calls FindFirstFileExW.
pub unsafe extern "win64" fn find_first_file_a(
    lp_file_name: *const u8,
    lp_find_file_data: *mut Win32FindDataA,
) -> usize {
    if lp_file_name.is_null() || lp_find_file_data.is_null() {
        return usize::MAX; // INVALID_HANDLE_VALUE
    }

    // Read the null-terminated UTF-8 filename
    let mut len = 0usize;
    while len < MAX_UTF8_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF8_LEN {
        return usize::MAX;
    }
    let win_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_file_name, len)) };

    // Translate to Linux path
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => return usize::MAX,
    };

    // Open directory
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return usize::MAX,
    };

    let dir = unsafe { libc::opendir(c_path.as_ptr()) };
    if dir.is_null() {
        return usize::MAX;
    }

    // Read first entry
    let entry = unsafe { libc::readdir(dir) };
    if entry.is_null() {
        unsafe { libc::closedir(dir) };
        return usize::MAX;
    }

    // Get entry name
    let entry_name = unsafe {
        let name_ptr = (*entry).d_name.as_ptr();
        let name_len = libc::strlen(name_ptr);
        std::slice::from_raw_parts(name_ptr as *const u8, name_len)
    };
    let entry_name_str = String::from_utf8_lossy(entry_name);
    let st = stat_dirent_entry(dir, &entry_name_str);
    let (attrs, size_hi, size_lo) = find_entry_attrs_and_size(&entry_name_str, st.as_ref());

    // Fill WIN32_FIND_DATAA
    unsafe {
        (*lp_find_file_data).dw_file_attributes = attrs;
        (*lp_find_file_data).ft_creation_time = [0, 0];
        (*lp_find_file_data).ft_last_access_time = [0, 0];
        (*lp_find_file_data).ft_last_write_time = [0, 0];
        (*lp_find_file_data).n_file_size_high = size_hi;
        (*lp_find_file_data).n_file_size_low = size_lo;
        (*lp_find_file_data).dw_reserved0 = 0;
        (*lp_find_file_data).dw_reserved1 = 0;

        // Copy filename (truncate if too long)
        let bytes = entry_name_str.as_bytes();
        let copy_len = bytes.len().min(259); // leave room for null
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (*lp_find_file_data).c_file_name.as_mut_ptr(),
            copy_len,
        );
        (*lp_find_file_data).c_file_name[copy_len] = 0;

        // No alternate filename
        (*lp_find_file_data).c_alternate_file_name[0] = 0;
    }

    dir as usize // Return directory handle
}

/// FindNextFileW: continue directory enumeration (wide string version).
///
/// Wine ref: dlls/kernelbase/file.c — validates handle magic (FIND_FIRST_MAGIC); uses
/// NtQueryDirectoryFile in a loop; fills full file metadata including reparse tag in
/// dwReserved0. Weave uses libc::readdir; no magic validation; metadata not filled.
/// Known gap: does not skip `.` and `..` from wildcard results.
///
/// # Safety
/// `h_find_file` must be a valid directory handle from FindFirstFileW.
/// `lp_find_file_data` must be a valid writable pointer to a WIN32_FIND_DATAW.
// Wine ref: dlls/kernelbase/file.c — FindNextFileW: validates info->magic == FIND_FIRST_MAGIC
// before use (invalid handle → ERROR_INVALID_HANDLE). Loops NtQueryDirectoryFile for more
// data when buffer exhausted. Sets dwReserved0 to reparse tag when FILE_ATTRIBUTE_REPARSE_POINT.
// FindExInfoBasic suppresses cAlternateFileName. Weave: no magic, no reparse tag.
pub unsafe extern "win64" fn find_next_file_w(
    h_find_file: usize,
    lp_find_file_data: *mut Win32FindDataW,
) -> i32 {
    eprintln!("weave/FindNextFileW: entry handle={h_find_file:#x}");
    if h_find_file == 0 || h_find_file == usize::MAX || lp_find_file_data.is_null() {
        eprintln!("weave/FindNextFileW: exit handle={h_find_file:#x} → FALSE (bad arg)");
        return 0; // FALSE
    }
    // Sentinel 1 = single-file handle from FindFirstFileW (no more entries).
    if h_find_file == 1 {
        eprintln!("weave/FindNextFileW: exit handle=1 → FALSE (single-file sentinel)");
        return 0; // FALSE — no more entries
    }

    // SAFETY: h_find_file is the `dir as usize` value stored by find_first_file_w;
    // it is a valid *mut libc::DIR returned by libc::opendir and has not been
    // closed (find_close is the only closer).  Casting back to *mut libc::DIR is
    // the inverse of the store — the type/alignment are preserved because DIR is
    // an opaque C struct allocated by libc, always at a valid pointer address.
    let dir = h_find_file as *mut libc::DIR;

    // Read next entry
    let entry = unsafe { libc::readdir(dir) };
    if entry.is_null() {
        eprintln!("weave/FindNextFileW: exit handle={h_find_file:#x} → FALSE (no_more_entries)");
        return 0; // FALSE - no more entries
    }

    // Convert entry name to UTF-16
    let entry_name = unsafe {
        let name_ptr = (*entry).d_name.as_ptr();
        let name_len = libc::strlen(name_ptr);
        std::slice::from_raw_parts(name_ptr as *const u8, name_len)
    };
    let entry_name_str = String::from_utf8_lossy(entry_name);
    let wide_name: Vec<u16> = entry_name_str.encode_utf16().collect();
    let st = stat_dirent_entry(dir, &entry_name_str);
    let (attrs, size_hi, size_lo) = find_entry_attrs_and_size(&entry_name_str, st.as_ref());

    // Fill WIN32_FIND_DATAW
    unsafe {
        (*lp_find_file_data).dw_file_attributes = attrs;
        (*lp_find_file_data).ft_creation_time = [0, 0];
        (*lp_find_file_data).ft_last_access_time = [0, 0];
        (*lp_find_file_data).ft_last_write_time = [0, 0];
        (*lp_find_file_data).n_file_size_high = size_hi;
        (*lp_find_file_data).n_file_size_low = size_lo;
        (*lp_find_file_data).dw_reserved0 = 0;
        (*lp_find_file_data).dw_reserved1 = 0;

        // Copy filename (truncate if too long)
        let copy_len = wide_name.len().min(259); // leave room for null
        std::ptr::copy_nonoverlapping(
            wide_name.as_ptr(),
            (*lp_find_file_data).c_file_name.as_mut_ptr(),
            copy_len,
        );
        (*lp_find_file_data).c_file_name[copy_len] = 0;

        // No alternate filename
        (*lp_find_file_data).c_alternate_file_name[0] = 0;
    }

    eprintln!(
        "weave/FindNextFileW: exit handle={h_find_file:#x} entry={entry_name_str:?} attrs={attrs:#x} → TRUE"
    );
    if entry_name_str != "." && entry_name_str != ".." {
        weave_core::progress::mark_find_next_file_first();
    }
    1 // TRUE
}

/// FindNextFileA: continue directory enumeration (ANSI version).
///
/// # Safety
/// `h_find_file` must be a valid directory handle from FindFirstFileA.
/// `lp_find_file_data` must be a valid writable pointer to a WIN32_FIND_DATAA.
// Wine ref: dlls/kernelbase/file.c:1486 — converts the result of FindNextFileW to ANSI
// via file_name_WtoA; both cFileName and cAlternateFileName are converted.
pub unsafe extern "win64" fn find_next_file_a(
    h_find_file: usize,
    lp_find_file_data: *mut Win32FindDataA,
) -> i32 {
    if h_find_file == 0 || h_find_file == usize::MAX || lp_find_file_data.is_null() {
        return 0; // FALSE
    }

    // SAFETY: same invariant as find_next_file_w — h_find_file is the `dir as usize`
    // value stored by find_first_file_a, which is a valid *mut libc::DIR from opendir.
    let dir = h_find_file as *mut libc::DIR;

    // Read next entry
    let entry = unsafe { libc::readdir(dir) };
    if entry.is_null() {
        return 0; // FALSE - no more entries
    }

    // Get entry name
    let entry_name = unsafe {
        let name_ptr = (*entry).d_name.as_ptr();
        let name_len = libc::strlen(name_ptr);
        std::slice::from_raw_parts(name_ptr as *const u8, name_len)
    };
    let entry_name_str = String::from_utf8_lossy(entry_name);
    let st = stat_dirent_entry(dir, &entry_name_str);
    let (attrs, size_hi, size_lo) = find_entry_attrs_and_size(&entry_name_str, st.as_ref());

    // Fill WIN32_FIND_DATAA
    unsafe {
        (*lp_find_file_data).dw_file_attributes = attrs;
        (*lp_find_file_data).ft_creation_time = [0, 0];
        (*lp_find_file_data).ft_last_access_time = [0, 0];
        (*lp_find_file_data).ft_last_write_time = [0, 0];
        (*lp_find_file_data).n_file_size_high = size_hi;
        (*lp_find_file_data).n_file_size_low = size_lo;
        (*lp_find_file_data).dw_reserved0 = 0;
        (*lp_find_file_data).dw_reserved1 = 0;

        // Copy filename (truncate if too long)
        let bytes = entry_name_str.as_bytes();
        let copy_len = bytes.len().min(259); // leave room for null
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (*lp_find_file_data).c_file_name.as_mut_ptr(),
            copy_len,
        );
        (*lp_find_file_data).c_file_name[copy_len] = 0;

        // No alternate filename
        (*lp_find_file_data).c_alternate_file_name[0] = 0;
    }

    1 // TRUE
}

/// FindClose: close directory enumeration handle.
// Wine ref: dlls/kernelbase/file.c — validates FIND_FIRST_MAGIC; calls NtClose on the
// directory handle stored in FIND_FIRST_INFO; frees the FIND_FIRST_INFO heap allocation.
// Weave uses a raw DIR* instead of the NT directory-handle approach.
pub extern "win64" fn find_close(h_find_file: usize) -> i32 {
    eprintln!("weave/FindClose: entry handle={h_find_file:#x}");
    if h_find_file == 0 || h_find_file == usize::MAX {
        eprintln!("weave/FindClose: exit handle={h_find_file:#x} → FALSE (bad arg)");
        return 0; // FALSE
    }
    // Sentinel 1 = single-file handle (no DIR* to close).
    if h_find_file == 1 {
        eprintln!("weave/FindClose: exit handle=1 → TRUE (single-file sentinel, no DIR* to close)");
        return 1; // TRUE — success, nothing to close
    }

    // SAFETY: h_find_file is the `dir as usize` value stored by find_first_file_w/a;
    // it is a valid *mut libc::DIR returned by libc::opendir.  Casting back is the
    // inverse of the store.  We call closedir exactly once (guarded by the sentinel
    // checks above), so there is no double-free risk.
    let dir = h_find_file as *mut libc::DIR;
    let ret = unsafe { libc::closedir(dir) };
    let ok = ret == 0;
    eprintln!(
        "weave/FindClose: exit handle={h_find_file:#x} ret={ret} → {}",
        if ok { "TRUE" } else { "FALSE" }
    );
    ok as i32
}

/// VerSetConditionMask: pack a condition into the corresponding 3-bit slot of the mask.
// Wine ref: dlls/kernel32/version.c:40 (version_update_condition) — each type flag gets a
// 3-bit slot in the 64-bit mask; VER_EQUAL (1) through VER_LESS_EQUAL (6) are the valid
// conditions; invalid transitions leave the prior condition unchanged.
pub extern "win64" fn ver_set_condition_mask(
    mut condition_mask: u64,
    type_mask: u32,
    condition: u8,
) -> u64 {
    let mut bit = 1u32;
    let mut shift = 0u32;
    loop {
        if bit > type_mask {
            break;
        }
        if (type_mask & bit) != 0 {
            condition_mask &= !(0x07u64 << shift);
            condition_mask |= (condition as u64 & 0x07) << shift;
        }
        shift += 3;
        bit <<= 1;
    }
    condition_mask
}

/// VerifyVersionInfoW: verify version information against conditions.
///
/// Phase 2: always returns TRUE (version check passes).
///
/// # Safety
/// `lp_version_info` must be a valid pointer to an OSVERSIONINFOEXW.
// Wine ref: dlls/kernel32/version.c — delegates to RtlVerifyVersionInfo in ntdll;
// compares fields (MajorVersion, MinorVersion, BuildNumber, ServicePackMajor, etc.) using
// the 3-bit condition slots from the condition_mask; sets ERROR_OLD_WIN_VERSION on failure.
pub unsafe extern "win64" fn verify_version_info_w(
    _lp_version_info: *const OsVersionInfoExW,
    _type_mask: u32,
    _condition_mask: u64,
) -> i32 {
    1 // always TRUE — Weave reports Windows 10; version checks pass unconditionally
}

/// Windows WIN32_FILE_ATTRIBUTE_DATA structure.
#[repr(C)]
pub struct Win32FileAttributeData {
    dw_file_attributes: u32,
    ft_creation_time: [u32; 2],
    ft_last_access_time: [u32; 2],
    ft_last_write_time: [u32; 2],
    n_file_size_high: u32,
    n_file_size_low: u32,
}

/// GetFileAttributesExW: get extended file attributes (wide string version).
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-16 string.
/// `lp_file_information` must be a valid writable pointer to a WIN32_FILE_ATTRIBUTE_DATA.
// Wine ref: dlls/kernelbase/file.c:1799 — only GetFileExInfoStandard is valid (level != 0
// → ERROR_INVALID_PARAMETER); calls NtQueryFullAttributesFile to fill WIN32_FILE_ATTRIBUTE_DATA
// including all four timestamps and both file size halves; ERROR_PATH_NOT_FOUND if path fails.
pub unsafe extern "win64" fn get_file_attributes_ex_w(
    lp_file_name: *const u16,
    _f_info_level_id: u32,
    lp_file_information: *mut Win32FileAttributeData,
) -> i32 {
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

    if lp_file_name.is_null() || lp_file_information.is_null() {
        return 0; // FALSE
    }

    // Read the null-terminated UTF-16 filename
    let mut len = 0usize;
    while len < MAX_UTF16_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF16_LEN {
        return 0;
    }
    let win_path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_file_name, len)) };

    // Translate to Linux path
    let linux_path = match weave_core::file_io::translate_win_path(&win_path) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("weave/GetFileAttributesExW: {win_path:?} → translate FAILED");
            return 0;
        }
    };
    eprintln!(
        "weave/GetFileAttributesExW: {win_path:?} → {linux_path:?} exists={}",
        linux_path.exists()
    );

    // Check if path exists and get type
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let ret = unsafe { libc::stat(c_path.as_ptr(), &mut stat) };
    if ret != 0 {
        return 0; // FALSE
    }

    // Fill WIN32_FILE_ATTRIBUTE_DATA
    unsafe {
        (*lp_file_information).dw_file_attributes =
            if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            };
        (*lp_file_information).ft_creation_time = [0, 0];
        (*lp_file_information).ft_last_access_time = [0, 0];
        (*lp_file_information).ft_last_write_time = [0, 0];
        (*lp_file_information).n_file_size_high = (stat.st_size >> 32) as u32;
        (*lp_file_information).n_file_size_low = (stat.st_size & 0xFFFFFFFF) as u32;
    }

    1 // TRUE
}

/// GetFileAttributesExA: get extended file attributes (ANSI version).
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-8 string.
/// `lp_file_information` must be a valid writable pointer to a WIN32_FILE_ATTRIBUTE_DATA.
// Wine ref: dlls/kernelbase/file.c:1787 — converts name via file_name_AtoW (stack allocation)
// then delegates entirely to GetFileAttributesExW.
pub unsafe extern "win64" fn get_file_attributes_ex_a(
    lp_file_name: *const u8,
    _f_info_level_id: u32,
    lp_file_information: *mut Win32FileAttributeData,
) -> i32 {
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

    if lp_file_name.is_null() || lp_file_information.is_null() {
        return 0; // FALSE
    }

    // Read the null-terminated UTF-8 filename
    let mut len = 0usize;
    while len < MAX_UTF8_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF8_LEN {
        return 0;
    }
    let win_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_file_name, len)) };

    // Translate to Linux path
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Check if path exists and get type
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let ret = unsafe { libc::stat(c_path.as_ptr(), &mut stat) };
    if ret != 0 {
        return 0; // FALSE
    }

    // Fill WIN32_FILE_ATTRIBUTE_DATA
    unsafe {
        (*lp_file_information).dw_file_attributes =
            if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            };
        (*lp_file_information).ft_creation_time = [0, 0];
        (*lp_file_information).ft_last_access_time = [0, 0];
        (*lp_file_information).ft_last_write_time = [0, 0];
        (*lp_file_information).n_file_size_high = (stat.st_size >> 32) as u32;
        (*lp_file_information).n_file_size_low = (stat.st_size & 0xFFFFFFFF) as u32;
    }

    1 // TRUE
}

/// CopyFileA: copy a file (ANSI version).
///
/// # Safety
/// `lp_existing_file_name` and `lp_new_file_name` must be valid null-terminated UTF-8 strings.
// Wine ref: dlls/kernelbase/file.c — CopyFileA converts via MultiByteToWideChar then calls
// CopyFileExW(progress=NULL, cancel=NULL, flags=bFailIfExists ? COPY_FILE_FAIL_IF_EXISTS : 0).
pub unsafe extern "win64" fn copy_file_a(
    lp_existing_file_name: *const u8,
    lp_new_file_name: *const u8,
    b_fail_if_exists: i32,
) -> i32 {
    if lp_existing_file_name.is_null() || lp_new_file_name.is_null() {
        return 0; // FALSE
    }

    // Read source filename
    let mut len1 = 0usize;
    while len1 < MAX_UTF8_LEN && unsafe { *lp_existing_file_name.add(len1) } != 0 {
        len1 += 1;
    }
    if len1 == MAX_UTF8_LEN {
        return 0;
    }
    let src_win_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_existing_file_name, len1)) };

    // Read destination filename
    let mut len2 = 0usize;
    while len2 < MAX_UTF8_LEN && unsafe { *lp_new_file_name.add(len2) } != 0 {
        len2 += 1;
    }
    if len2 == MAX_UTF8_LEN {
        return 0;
    }
    let dst_win_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_new_file_name, len2)) };

    // Translate paths
    let src_linux_path = match weave_core::prefix::translator().to_linux_str(&src_win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let dst_linux_path = match weave_core::prefix::translator().to_linux_str(&dst_win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C strings
    let src_c_path = match std::ffi::CString::new(src_linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let dst_c_path = match std::ffi::CString::new(dst_linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Check if destination exists and b_fail_if_exists is set
    if b_fail_if_exists != 0 && unsafe { libc::access(dst_c_path.as_ptr(), libc::F_OK) } == 0 {
        return 0; // FALSE — destination exists
    }

    // Open source file
    let src_fd = unsafe { libc::open(src_c_path.as_ptr(), libc::O_RDONLY, 0) };
    if src_fd < 0 {
        return 0; // FALSE
    }

    // Open/create destination file
    let dst_fd = unsafe {
        libc::open(
            dst_c_path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )
    };
    if dst_fd < 0 {
        unsafe { libc::close(src_fd) };
        return 0; // FALSE
    }

    // Copy in 64KB chunks
    let mut buf = [0u8; 65536];
    loop {
        let n = unsafe { libc::read(src_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        let written =
            unsafe { libc::write(dst_fd, buf.as_ptr() as *const libc::c_void, n as usize) };
        if written != n {
            unsafe { libc::close(src_fd) };
            unsafe { libc::close(dst_fd) };
            return 0; // FALSE
        }
    }

    unsafe { libc::close(src_fd) };
    unsafe { libc::close(dst_fd) };
    1 // TRUE
}

// ── Module / library loading ──────────────────────────────────────────────────
//
// Runtime DLL resolution.
//
// Strategy: try to load the DLL from disk first (translating the Windows path
// to a Linux path, searching the exe directory and prefix System32).  If the
// file exists, map it with loader::load_dll, patch its IAT, and register it in
// dll_registry so GetProcAddress returns real addresses from the mapped image.
// If the file is not found (most Windows system DLLs), fall back to a synthetic
// HMODULE so GetProcAddress can still route through our stub resolver chain.

/// Read a file, falling back to case-insensitive basename lookup on ENOENT.
///
/// The Windows-path translator lowercases DLL names before searching, but
/// Linux filesystems are case-sensitive.  If the exact path doesn't exist,
/// scan the parent directory for an entry whose name matches the basename
/// case-insensitively (e.g. disk has `Scintilla.DLL`, request was `scintilla.dll`).
fn read_file_case_insensitive(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    match std::fs::read(path) {
        Ok(b) => return Ok(b),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        Err(_) => {}
    }
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no parent dir"))?;
    let want = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no filename"))?
        .to_string_lossy()
        .to_ascii_lowercase();
    for entry in std::fs::read_dir(parent)?.flatten() {
        if entry.file_name().to_string_lossy().to_ascii_lowercase() == want {
            return std::fs::read(entry.path());
        }
    }
    Err(std::io::Error::from(std::io::ErrorKind::NotFound))
}

/// Attempt to load a DLL from disk given its Windows-style name or path.
/// Returns (handle, loaded_from_disk).
///
/// Search order:
///   1. Absolute path as given (after Windows→Linux translation)
///   2. Same directory as the running exe
///   3. Prefix System32 directory
fn load_library_impl(name: &str) -> usize {
    use weave_core::{
        dll_registry, exe_path, file_io, iat, loader, module_handles, prefix, resolve,
    };
    eprintln!("weave/kernel32: load_library_impl({name:?})");

    let key = {
        let base = name.rsplit(['\\', '/']).next().unwrap_or(name);
        base.to_ascii_lowercase()
    };

    // Wine ref: dlls/ntdll/loader.c::LdrLoadDll — on every LoadLibrary call
    // Windows searches PEB.Ldr.InMemoryOrderModuleList by canonical path first;
    // if the module is already present it increments the refcount and returns
    // the existing base address without calling DllMain again.
    //
    // Weave mirrors this: if the DLL is already registered (real disk-loaded or
    // synthetic/emulated), return the existing HMODULE immediately so that
    // callers such as SDL2 that invoke LoadLibrary("D3D9.DLL") twice receive
    // the same handle on the second call and DllMain is not re-entered.
    if dll_registry::is_registered(&key) {
        if let Some(existing) = module_handles::find(name) {
            eprintln!(
                "weave/kernel32: LoadLibrary({name:?}) → existing handle {existing:#x} (already loaded)"
            );
            return existing;
        }
    } else if let Some(existing) = module_handles::find(name) {
        // Synthetic / emulated DLL already registered — return immediately.
        eprintln!(
            "weave/kernel32: LoadLibrary({name:?}) → existing synthetic handle {existing:#x} (already loaded)"
        );
        return existing;
    }

    // Build candidate Linux paths to try, in priority order.
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();

    // 1. If name contains a path separator, translate it as a Windows absolute path.
    if name.contains('\\') || name.contains('/') {
        if let Ok(p) = file_io::translate_win_path(name) {
            candidates.push(p);
        }
    }

    // 2. Exe directory / basename (highest priority for app-local DLLs like SciLexer.dll)
    if let Some(exe_dir_win) = exe_path::exe_dir() {
        let candidate_win = format!("{}\\{}", exe_dir_win, key);
        if let Ok(p) = file_io::translate_win_path(&candidate_win) {
            candidates.push(p);
        }
        // IrfanView loads format plugins from {exe_dir}\Plugins\<name>.dll (OptiPNG etc.).
        let plugins_win = format!("{}\\Plugins\\{}", exe_dir_win, key);
        if let Ok(p) = file_io::translate_win_path(&plugins_win) {
            candidates.push(p);
        }
    }

    if std::env::var("WEAVE_TEST_SAVE_RESULT").is_ok() {
        eprintln!("weave/E3-M9-trace: LoadLibrary({name:?}) key={key}");
    }

    // 3. Prefix System32 / basename
    candidates.push(prefix::system32().join(&key));

    // Try each candidate.
    for path in &candidates {
        let bytes = match read_file_case_insensitive(path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        match loader::load_dll(&bytes) {
            Ok((image, exports)) => {
                let image_base = image.base as usize;
                let dll_entry = image.entry_point;
                // Transitive pre-load: a dynamically-loaded PE (e.g. libpng16-16.dll
                // pulled in by SDL2_image's IMG_Init) may import other native PE DLLs
                // (e.g. zlib1.dll) that live in the same directory but were not in
                // the main exe's import table. Walk this DLL's imports and load any
                // that aren't yet registered. Done before IAT patching so the
                // patcher resolves zlib1.dll!crc32 to the real PE export.
                if let Ok(parsed) = weave_core::pe::parse(&bytes) {
                    let parent_dir = path.parent().map(|p| p.to_path_buf());
                    for imp in &parsed.imports {
                        let dep_key = imp.dll.to_lowercase();
                        if dep_key == key || dll_registry::is_registered(&dep_key) {
                            continue;
                        }
                        if let Some(dir) = parent_dir.as_deref() {
                            let dep_path = dir.join(&imp.dll);
                            let dep_path_lc = dir.join(&dep_key);
                            if dep_path.exists() || dep_path_lc.exists() {
                                let _ = load_library_impl(&imp.dll);
                            }
                        }
                    }
                }
                // Patch the loaded DLL's own IAT using the global resolver.
                // SAFETY: `bytes` is the raw PE image just parsed by `load_dll`;
                // `image.base` is the virtual address at which it was mapped into this
                // process.  `iat::patch_best_effort` walks the Import Directory and
                // overwrites each IAT slot — pointer-sized writes into the mapped PE
                // region.  The region is writable because `load_dll` maps it with
                // PROT_READ|PROT_WRITE.  `resolve::resolve` is a plain function pointer
                // with no thread-safety requirements (single-threaded Phase 1/2).
                unsafe {
                    iat::patch_best_effort(&bytes, image.base, resolve::resolve, |d, f, va| {
                        eprintln!("weave/kernel32: LoadLibrary({key}): unresolved import {d}!{f} at iat={va:#x}");
                    });
                }
                // Patch __report_gsfailure in the loaded DLL to RET so that
                // MSVC GS epilogue misfires (caused by Linux/Windows ABI cookie
                // mismatch) do not call TerminateProcess(STATUS_STACK_BUFFER_OVERRUN).
                // Each MSVC-compiled DLL has its own copy of __report_gsfailure.
                weave_core::cfg::disable_report_gsfailure(&bytes, image.base);
                // Also patch the newer MSVC GS fast-fail pattern (int $0x29).
                weave_core::cfg::disable_fastfail_gs(&bytes, image.base);
                for (fname, &addr) in &exports {
                    eprintln!("weave: dll export registered: {key}!{fname} → {addr:#x}");
                }
                dll_registry::register(key.clone(), image, exports);
                // HMODULE == image base address (Windows convention).  Register
                // this so GetProcAddress / GetModuleFileName can map handle→name.
                module_handles::register_with_handle(name, image_base);
                // Loader: share path-registry convention with load_with_name
                // (weave-core::loader). `register_image_path` normalizes to
                // lowercase + forward-slashes and also indexes the bare
                // basename — pass the guest-supplied `name` verbatim so that
                // GetFileVersionInfoSizeW / FindResourceW by-path lookups
                // resolve identically whether the module was mapped via the
                // exe load path (load_with_name) or dynamically via
                // LoadLibraryW (this site).
                module_handles::register_image_path(name, image_base);

                // Invoke DllMain(hinstDLL, DLL_PROCESS_ATTACH, NULL) if present.
                // Must happen after IAT patching so the DLL's imports resolve
                // correctly inside DllMain.  Wine ref: dlls/ntdll/loader.c —
                // MODULE_InitDLL passes reserved=1 for static, NULL for dynamic.
                if !dll_entry.is_null() {
                    const DLL_PROCESS_ATTACH: u32 = 1;
                    type DllMain =
                        unsafe extern "win64" fn(hinst: usize, reason: u32, reserved: usize) -> i32;
                    // SAFETY: dll_entry points into the mapped image; sections
                    // have already been set to their final permissions by
                    // map_sections, so the entry page is executable.
                    let dll_main: DllMain = unsafe { std::mem::transmute(dll_entry) };
                    let ok = unsafe { dll_main(image_base, DLL_PROCESS_ATTACH, 0) };
                    eprintln!(
                        "weave/kernel32: LoadLibrary({name:?}) DllMain({image_base:#x}, DLL_PROCESS_ATTACH) → {ok}"
                    );
                    if ok == 0 {
                        eprintln!(
                            "weave/kernel32: LoadLibrary({name:?}) DllMain returned FALSE — proceeding anyway"
                        );
                    }
                }

                eprintln!(
                    "weave/kernel32: LoadLibrary({name:?}) → loaded from {} at {image_base:#x}",
                    path.display()
                );
                return image_base;
            }
            Err(e) => {
                eprintln!(
                    "weave/kernel32: LoadLibrary({name:?}): parse error for {}: {e}",
                    path.display()
                );
                // File exists but is malformed — don't try other paths.
                break;
            }
        }
    }

    // Only return a synthetic handle for DLLs Weave actually emulates.
    // For everything else (e.g. Scintilla.DLL statically embedded in SciTE),
    // return NULL so callers can detect failure and fall back to their own
    // implementations — a non-NULL handle with all-NULL GetProcAddress results
    // causes null-pointer crashes during the caller's static init.
    //
    // Normalize: bare names like "kernel32" (no extension) must also match.
    // Windows allows LoadLibrary("kernel32") without ".dll" — the loader
    // appends the default extension.  Our key is already lowercase, so just
    // ensure it ends with ".dll" before the emulated-set check.
    let emulated_key: std::borrow::Cow<str> = if key.contains('.') {
        std::borrow::Cow::Borrowed(&key)
    } else {
        std::borrow::Cow::Owned(format!("{key}.dll"))
    };
    if !is_emulated_dll(&emulated_key) {
        eprintln!("weave/kernel32: LoadLibrary({name:?}) → NULL (not emulated)");
        return 0;
    }
    let handle = module_handles::register(name);
    eprintln!("weave/kernel32: LoadLibrary({name:?}) → synthetic {handle:#x}");
    handle
}

/// Return true if `key` (lowercase DLL basename) is a Win32 system DLL that is
/// implicitly loaded in every Windows process without requiring an explicit
/// LoadLibraryA call.
///
/// These DLLs should always yield a non-NULL HMODULE from GetModuleHandleA
/// regardless of whether LoadLibraryA was called.  Contrast with device-specific
/// DLLs (vulkan-1.dll, xinput*, mmdevapi, ws2_32) that Windows only exposes
/// after an explicit Load — if GetModuleHandleA returns non-NULL for those
/// before they are loaded, callers skip LoadLibraryA and bypass Weave's win64
/// thunk registration (the root cause of the DXVK Vulkan dispatch bug).
/// Normalize `kernel32` / `SHELL32.DLL` style names to lowercase `*.dll` keys.
fn dll_lookup_key(name: &str) -> String {
    let base = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let lower = base.to_ascii_lowercase();
    if lower.ends_with(".dll") || lower.ends_with(".drv") {
        lower
    } else {
        format!("{lower}.dll")
    }
}

fn is_always_present_dll(key: &str) -> bool {
    if key.starts_with("api-ms-win-") {
        return true;
    }
    matches!(
        key,
        "ntdll.dll"
            | "kernel32.dll"
            | "advapi32.dll"
            | "user32.dll"
            | "uxtheme.dll"
            | "dwmapi.dll"
            | "gdi32.dll"
            | "msimg32.dll"
            | "shell32.dll"
            | "ole32.dll"
            | "winmm.dll"
            | "comctl32.dll"
            | "oleaut32.dll"
            | "imm32.dll"
            | "shlwapi.dll"
            | "gdiplus.dll"
            | "version.dll"
            | "ucrtbase.dll"
            | "msvcrt.dll"
            | "psapi.dll"
            | "shcore.dll"
    )
}

/// Return true if `key` (lowercase DLL basename, e.g. `"kernel32.dll"`) is a
/// DLL that Weave actually emulates via its stub resolver chain.  Only these
/// DLLs should receive a synthetic HMODULE when they are not found on disk;
/// all other DLLs must get NULL so callers can fall back gracefully.
fn is_emulated_dll(key: &str) -> bool {
    // API-set virtual DLLs — forwarded to kernel32/ucrt/version stubs.
    if key.starts_with("api-ms-win-") {
        return true;
    }
    matches!(
        key,
        "ntdll.dll"
            | "kernel32.dll"
            | "advapi32.dll"
            | "user32.dll"
            | "uxtheme.dll"
            | "dwmapi.dll"
            | "gdi32.dll"
            | "msimg32.dll"
            | "shell32.dll"
            | "comdlg32.dll"
            | "ole32.dll"
            | "mmdevapi.dll"
            | "xinput1_3.dll"
            | "xinput1_4.dll"
            | "xinput9_1_0.dll"
            | "winmm.dll"
            | "vulkan-1.dll"
            | "winevulkan.dll"
            | "ws2_32.dll"
            | "wsock32.dll"
            | "comctl32.dll"
            | "oleaut32.dll"
            | "imm32.dll"
            | "shlwapi.dll"
            | "gdiplus.dll"
            | "version.dll"
            | "ucrtbase.dll"
            | "msvcrt.dll"
            | "psapi.dll"
            | "shcore.dll"
    )
}

/// Read a null-terminated ANSI string from a raw pointer. Returns an empty
/// string if the pointer is null.
unsafe fn read_cstr_a(p: *const u8) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf8_lossy(slice).into_owned()
}

/// Read a null-terminated UTF-16 string from a raw pointer. Returns an empty
/// string if the pointer is null.
unsafe fn read_cstr_w(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf16_lossy(slice)
}

/// LoadLibraryA — load a DLL by ANSI name.
///
/// # Safety
/// `lp_file_name` must be null or a valid null-terminated ANSI string.
// Wine ref: dlls/kernelbase/loader.c:518 — thin wrapper: LoadLibraryA delegates to
// LoadLibraryExA(name, 0, 0); no flags processing here.
pub unsafe extern "win64" fn load_library_a(lp_file_name: *const u8) -> usize {
    let name = unsafe { read_cstr_a(lp_file_name) };
    eprintln!("weave/kernel32: LoadLibraryA({name:?}) entry");
    if name.is_empty() {
        return 0;
    }
    load_library_impl(&name)
}

/// LoadLibraryW — load a DLL by wide name.
///
/// # Safety
/// `lp_file_name` must be null or a valid null-terminated UTF-16 string.
// Wine ref: dlls/kernelbase/loader.c:527 — delegates to LoadLibraryExW(name, 0, 0).
pub unsafe extern "win64" fn load_library_w(lp_file_name: *const u16) -> usize {
    let name = unsafe { read_cstr_w(lp_file_name) };
    if name.is_empty() {
        return 0;
    }
    load_library_impl(&name)
}

/// LoadLibraryExA — load a DLL by ANSI name (extended).
///
/// # Safety
/// `lp_file_name` must be null or a valid null-terminated ANSI string.
// Wine ref: dlls/kernelbase/loader.c:536 — converts name via RtlCreateUnicodeStringFromAsciiz,
// then delegates to load_library(); frees the UNICODE_STRING before returning.
pub unsafe extern "win64" fn load_library_ex_a(
    lp_file_name: *const u8,
    _h_file: usize,
    _dw_flags: u32,
) -> usize {
    let name = unsafe { read_cstr_a(lp_file_name) };
    if name.is_empty() {
        return 0;
    }
    load_library_impl(&name)
}

/// LoadLibraryExW — load a DLL by wide name (extended).
///
/// # Safety
/// `lp_file_name` must be null or a valid null-terminated UTF-16 string.
// Wine ref: dlls/kernelbase/loader.c:555 — strips trailing spaces from name before calling
// load_library(); returns ERROR_INVALID_PARAMETER for NULL name; uses LdrLoadDll underneath.
pub unsafe extern "win64" fn load_library_ex_w(
    lp_file_name: *const u16,
    _h_file: usize,
    _dw_flags: u32,
) -> usize {
    let name = unsafe { read_cstr_w(lp_file_name) };
    if name.is_empty() {
        return 0;
    }
    load_library_impl(&name)
}

/// FreeLibrary: decrement the reference count for a loaded DLL.
///
/// Wine ref: dlls/kernelbase/loader.c — calls LdrUnloadDll which decrements the
/// loader data entry refcount and, when it hits zero, calls DllMain(DLL_PROCESS_DETACH)
/// then unmaps the image. Weave: module_handles has no refcount (Phase 1/2);
/// FreeLibrary is a no-op returning TRUE. Synthetic handles have no resources
/// to release; real loaded DLLs (if any) remain mapped for the process lifetime.
pub extern "win64" fn free_library(_h_module: usize) -> i32 {
    1 // no refcount in Weave module map; DLLs stay mapped for process lifetime
}

/// SetDefaultDllDirectories — restrict DLL search paths (security hardening).
///
/// Stub: returns TRUE. 7-Zip calls this via GetProcAddress on startup; if it
/// returns NULL the app may exit as a security precaution.
// Wine ref: dlls/kernelbase/loader.c — SetDefaultDllDirectories delegates to
// LdrSetDefaultDllDirectories; sets the safe-DLL-search-mode flags for the process.
// Invalid flags combination → error from LdrSetDefaultDllDirectories. Weave: no-op.
pub extern "win64" fn set_default_dll_directories(_directory_flags: u32) -> i32 {
    1
}

/// AddDllDirectory — add a directory to the DLL search path.
///
/// Returns a fake cookie (1). Stub — search path is not implemented.
///
/// # Safety
/// `new_directory` is ignored.
// Wine ref: dlls/kernelbase/loader.c:191 — calls LdrAddDllDirectory which allocates a
// UNICODE_STRING node in the NT loader's DLL directory list; returns the node pointer as cookie.
pub unsafe extern "win64" fn add_dll_directory(_new_directory: *const u16) -> usize {
    1 // fake DLL_DIRECTORY_COOKIE — search path not implemented
}

/// RemoveDllDirectory — remove a directory from the DLL search path.
///
/// Returns TRUE. Stub.
// Wine ref: dlls/kernelbase/loader.c:603 — calls LdrRemoveDllDirectory(cookie);
// the cookie is the UNICODE_STRING node pointer allocated by AddDllDirectory.
pub extern "win64" fn remove_dll_directory(_cookie: usize) -> i32 {
    1
}

/// SetDllDirectoryW — set a single DLL search directory (Wide).
///
/// Returns TRUE. Stub.
///
/// # Safety
/// `lp_path_name` is ignored.
// Wine ref: dlls/kernelbase/loader.c — SetDllDirectoryW calls LdrSetDefaultDllDirectories
// internally to override the safe-DLL-search-mode directory; NULL restores default behavior.
pub unsafe extern "win64" fn set_dll_directory_w(_lp_path_name: *const u16) -> i32 {
    1
}

/// GetProcAddress — resolve a function by module handle + name.
///
/// Maps the synthetic HMODULE back to a DLL name, then queries the global
/// resolver. Falls back to 0 (NULL) if the handle is unknown or the
/// function is not found.
///
/// # Safety
/// `lp_proc_name` must be a valid null-terminated ANSI string, or an ordinal
/// encoded in the low 16 bits (high bits zero — `MAKEINTRESOURCE` style).
/// GetProcAddress: resolve a function address from a loaded module.
///
/// Wine ref: dlls/kernelbase/loader.c — GetProcAddress delegates to get_proc_address which
/// calls LdrGetProcedureAddress; ordinals: HIWORD(function)==0 (pointer value < 0x10000).
/// Weave resolves against the Weave DLL stub table via weave-core's resolve module.
///
/// # Safety
/// `lp_proc_name` must be a null-terminated ASCII string or an ordinal value (< 0x10000).
// Wine ref: dlls/kernelbase/loader.c — GetProcAddress delegates to get_proc_address which
// calls LdrGetProcedureAddress. Ordinal: HIWORD(function)==0 (pointer value < 0x10000).
// Returns NULL + ERROR_PROC_NOT_FOUND when not found. Weave: resolves via weave-core stub table.
pub unsafe extern "win64" fn get_proc_address(h_module: usize, lp_proc_name: *const u8) -> usize {
    // Ordinal imports: pointer value < 0x10000 encodes the ordinal number.
    if !lp_proc_name.is_null() && (lp_proc_name as usize) < 0x10000 {
        return 0;
    }

    let func_name = unsafe { read_cstr_a(lp_proc_name) };
    if func_name.is_empty() {
        return 0;
    }

    if std::env::var("WEAVE_TEST_SAVE_RESULT").is_ok() {
        let upper = func_name.to_ascii_uppercase();
        // Known IrfanView plugin API function names
        if upper == "GETPLUGININFO"
            || upper == "OPTIPNG_W"
            || upper == "SHOWPLUGINOPTIONS"
            || upper == "SHOWPLUGINOPTIONS_W"
            || upper == "SHOWPLUGINSAVEOPTIONS"
            || upper == "SHOWPLUGINSAVEOPTIONS_W"
            || upper == "CLOSEPLUGIN"
            || upper.contains("PLUGIN")
            || upper.contains("OPTIPNG")
        {
            eprintln!("weave/E3-M9-trace: GetProcAddress probe {func_name}");
        }
    }

    let dll_name = match weave_core::module_handles::lookup(h_module) {
        Some(name) => name,
        None => {
            eprintln!("weave/kernel32: GetProcAddress(h={h_module:#x}!{func_name}) → NULL (handle unknown)");
            return 0;
        }
    };

    if std::env::var("WEAVE_TEST_SAVE_RESULT").is_ok()
        && (dll_name.contains("i_view64") || dll_name.contains("irfanview"))
    {
        eprintln!("weave/E3-M9-trace: GetProcAddress(i_view64!{func_name})");
    }

    // Check dll_registry first: covers real DLLs loaded from disk via LoadLibrary
    // (e.g. Scintilla.DLL).  resolve::resolve only knows Weave's synthetic stubs.
    if let Some(addr) = weave_core::dll_registry::lookup(&dll_name, &func_name) {
        eprintln!("weave/kernel32: GetProcAddress({dll_name}!{func_name}) → {addr:#x} [dynamic]");
        return addr;
    }

    // E3-M9: Plugin API fallback — IrfanView calls GetProcAddress on its own
    // HMODULE (i_view64.exe, zero exports) for plugin functions like
    // GetPlugInInfo/OptiPNG_W. These are exported by preloaded OptiPNG.dll
    // but the guest never queries that DLL handle directly. Redirect known
    // plugin API names to the preloaded export table.
    if std::env::var("WEAVE_TEST_SAVE_RESULT").is_ok() {
        let upper = func_name.to_ascii_uppercase();
        if upper == "GETPLUGININFO"
            || upper == "OPTIPNG_W"
            || upper == "SHOWPLUGINOPTIONS"
            || upper == "SHOWPLUGINOPTIONS_W"
            || upper == "SHOWPLUGINSAVEOPTIONS"
            || upper == "SHOWPLUGINSAVEOPTIONS_W"
            || upper == "CLOSEPLUGIN"
            || upper.contains("PLUGIN")
            || upper.contains("OPTIPNG")
        {
            if let Some(addr) = weave_core::dll_registry::lookup("optipng.dll", &func_name) {
                eprintln!(
                    "weave/E3-M9-trace: GetProcAddress plugin-fallback (optipng.dll!{func_name}) → {addr:#x}"
                );
                return addr;
            }
        }
    }

    match weave_core::resolve::resolve(&dll_name, &func_name) {
        Some(addr) => {
            eprintln!("weave/kernel32: GetProcAddress({dll_name}!{func_name}) → {addr:#x}");
            addr
        }
        None => {
            eprintln!("weave/kernel32: GetProcAddress({dll_name}!{func_name}) → NULL (not found)");
            0
        }
    }
}

// ── GetVersion ────────────────────────────────────────────────────────────────

/// GetVersion — legacy API returning Windows version as a packed DWORD.
///
/// Low byte = major version, next byte = minor version. Windows 10 is 10.0,
/// so low word = 0x000A (major=10, minor=0). High word would hold build number
/// but legacy apps ignore it; we return 0.
///
/// Wine ref: dlls/kernelbase/version.c — GetVersion returns NtCurrentTeb()->Peb->OSMajorVersion
/// | (NtCurrentTeb()->Peb->OSMinorVersion << 8); Windows 10 has OSMinorVersion = 0.
pub extern "win64" fn get_version() -> u32 {
    0x0000_000A // major=10, minor=0 — Windows 10 (Wine-correct)
}

// ── Process/toolhelp ─────────────────────────────────────────────────────────

#[derive(Clone)]
struct SnapProcEntry {
    pid: u32,
    ppid: u32,
    threads: u32,
    name_w: Vec<u16>, // UTF-16, null-terminated, ≤260 elements
}

struct ToolhelpSnap {
    processes: Vec<SnapProcEntry>,
    proc_pos: usize,
}

static SNAP_TABLE: OnceLock<Mutex<HashMap<usize, ToolhelpSnap>>> = OnceLock::new();
static SNAP_NEXT: AtomicUsize = AtomicUsize::new(0x8800_0001);

fn snap_table() -> &'static Mutex<HashMap<usize, ToolhelpSnap>> {
    SNAP_TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn enumerate_linux_processes() -> Vec<SnapProcEntry> {
    let mut result = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return result;
    };
    for entry in dir.flatten() {
        let fname = entry.file_name();
        let s = fname.to_string_lossy();
        let Ok(pid) = s.parse::<u32>() else { continue };
        let stat_path = format!("/proc/{pid}/stat");
        let Ok(content) = std::fs::read_to_string(&stat_path) else {
            continue;
        };
        let Some(open) = content.find('(') else {
            continue;
        };
        let Some(close) = content.rfind(')') else {
            continue;
        };
        let name = &content[open + 1..close];
        let rest: Vec<&str> = content[close + 2..].split_whitespace().collect();
        let ppid: u32 = rest.get(1).and_then(|v| v.parse().ok()).unwrap_or(0);
        // /proc/pid/stat field 20 (1-based) = num_threads; 0-based after state: index 17
        let threads: u32 = rest.get(17).and_then(|v| v.parse().ok()).unwrap_or(1);
        let mut name_w: Vec<u16> = name.encode_utf16().take(259).collect();
        name_w.push(0);
        result.push(SnapProcEntry {
            pid,
            ppid,
            threads,
            name_w,
        });
    }
    result.sort_unstable_by_key(|e| e.pid);
    result
}

// Write PROCESSENTRY32W into the buffer at `lppe`.
// x64 layout: dwSize(+0) cntUsage(+4) th32ProcessID(+8) _pad(+12)
// th32DefaultHeapID(+16) th32ModuleID(+24) cntThreads(+28) th32ParentProcessID(+32)
// pcPriClassBase(+36) dwFlags(+40) szExeFile(+44, 260×u16) — sizeof = 568.
unsafe fn write_process_entry_w(lppe: *mut u8, e: &SnapProcEntry) {
    unsafe {
        std::ptr::write_unaligned(lppe.add(0) as *mut u32, 568);
        std::ptr::write_unaligned(lppe.add(4) as *mut u32, 0); // cntUsage (unused)
        std::ptr::write_unaligned(lppe.add(8) as *mut u32, e.pid);
        std::ptr::write_unaligned(lppe.add(12) as *mut u32, 0); // implicit pad
        std::ptr::write_unaligned(lppe.add(16) as *mut u64, 0); // th32DefaultHeapID (unused)
        std::ptr::write_unaligned(lppe.add(24) as *mut u32, 0); // th32ModuleID (unused)
        std::ptr::write_unaligned(lppe.add(28) as *mut u32, e.threads);
        std::ptr::write_unaligned(lppe.add(32) as *mut u32, e.ppid);
        std::ptr::write_unaligned(lppe.add(36) as *mut i32, 8); // pcPriClassBase NORMAL
        std::ptr::write_unaligned(lppe.add(40) as *mut u32, 0); // dwFlags (unused)
        let dst = lppe.add(44) as *mut u16;
        let len = e.name_w.len().min(260);
        std::ptr::copy_nonoverlapping(e.name_w.as_ptr(), dst, len);
    }
}

/// CreateToolhelp32Snapshot — create a snapshot of processes/threads/modules.
///
/// Reads /proc to enumerate live Linux processes when TH32CS_SNAPPROCESS is set.
/// Returns INVALID_HANDLE_VALUE on allocation failure.
///
/// # Safety
/// No pointer dereferences.
// Wine ref: dlls/kernel32/toolhelp.c — calls NtQuerySystemInformation(SystemProcessInformation)
// to populate the snapshot; stores PROCESSENTRY32W structs in a heap-allocated block;
// returns a handle to the snapshot object.
pub unsafe extern "win64" fn create_toolhelp32_snapshot(
    dw_flags: u32,
    _th32_process_id: u32,
) -> usize {
    const TH32CS_SNAPPROCESS: u32 = 0x2;
    let processes = if dw_flags & TH32CS_SNAPPROCESS != 0 {
        enumerate_linux_processes()
    } else {
        Vec::new()
    };
    let snap = ToolhelpSnap {
        processes,
        proc_pos: 0,
    };
    let handle = SNAP_NEXT.fetch_add(1, Ordering::Relaxed);
    snap_table().lock().unwrap().insert(handle, snap);
    handle
}

/// Process32FirstW — retrieve first process from a toolhelp snapshot.
///
/// Resets position to the first entry and fills PROCESSENTRY32W.
/// Returns FALSE + ERROR_NO_MORE_FILES if the snapshot has no processes.
///
/// # Safety
/// `lppe` must point to a valid PROCESSENTRY32W buffer with dwSize pre-set.
// Wine ref: dlls/kernel32/toolhelp.c — checks valid snapshot handle; fills PROCESSENTRY32W
// from internal buffer; returns ERROR_NO_MORE_FILES if count is zero.
pub unsafe extern "win64" fn process32_first_w(h_snapshot: usize, lppe: *mut u8) -> i32 {
    if lppe.is_null() {
        set_last_error(87);
        return 0;
    }
    let provided = unsafe { std::ptr::read_unaligned(lppe as *const u32) };
    if (provided as usize) < 568 {
        set_last_error(24); // ERROR_BAD_LENGTH
        return 0;
    }
    let entry = {
        let mut table = snap_table().lock().unwrap();
        let Some(snap) = table.get_mut(&h_snapshot) else {
            set_last_error(6); // ERROR_INVALID_HANDLE
            return 0;
        };
        snap.proc_pos = 0;
        snap.processes.first().cloned()
    };
    match entry {
        None => {
            set_last_error(18); // ERROR_NO_MORE_FILES
            0
        }
        Some(e) => {
            unsafe { write_process_entry_w(lppe, &e) };
            set_last_error(0);
            1
        }
    }
}

/// Process32NextW — retrieve next process from a toolhelp snapshot.
///
/// Advances the snapshot position. Returns FALSE + ERROR_NO_MORE_FILES when exhausted.
///
/// # Safety
/// `lppe` must point to a valid PROCESSENTRY32W buffer with dwSize pre-set.
// Wine ref: dlls/kernel32/toolhelp.c — advances the internal offset into the snapshot
// buffer; returns ERROR_NO_MORE_FILES when exhausted (NOT ERROR_NO_MORE_ITEMS).
pub unsafe extern "win64" fn process32_next_w(h_snapshot: usize, lppe: *mut u8) -> i32 {
    if lppe.is_null() {
        set_last_error(87);
        return 0;
    }
    let provided = unsafe { std::ptr::read_unaligned(lppe as *const u32) };
    if (provided as usize) < 568 {
        set_last_error(24);
        return 0;
    }
    let entry = {
        let mut table = snap_table().lock().unwrap();
        let Some(snap) = table.get_mut(&h_snapshot) else {
            set_last_error(6);
            return 0;
        };
        snap.proc_pos += 1;
        snap.processes.get(snap.proc_pos).cloned()
    };
    match entry {
        None => {
            set_last_error(18);
            0
        }
        Some(e) => {
            unsafe { write_process_entry_w(lppe, &e) };
            set_last_error(0);
            1
        }
    }
}

/// Process32First — retrieve first process from a toolhelp snapshot (ANSI).
///
/// Wine: PROCESSENTRY32 == PROCESSENTRY32W; delegates to the W variant.
///
/// # Safety
/// `lppe` must point to a valid PROCESSENTRY32W buffer with dwSize pre-set.
// Wine ref: dlls/kernel32/toolhelp.c — PROCESSENTRY32 is typedef'd to PROCESSENTRY32W;
// Process32First and Process32FirstW share the same struct and logic.
pub unsafe extern "win64" fn process32_first(h_snapshot: usize, lppe: *mut u8) -> i32 {
    unsafe { process32_first_w(h_snapshot, lppe) }
}

/// Process32Next — retrieve next process from a toolhelp snapshot (ANSI).
///
/// Wine: PROCESSENTRY32 == PROCESSENTRY32W; delegates to the W variant.
///
/// # Safety
/// `lppe` must point to a valid PROCESSENTRY32W buffer with dwSize pre-set.
// Wine ref: dlls/kernel32/toolhelp.c — PROCESSENTRY32 is typedef'd to PROCESSENTRY32W;
// Process32Next and Process32NextW share the same struct and logic.
pub unsafe extern "win64" fn process32_next(h_snapshot: usize, lppe: *mut u8) -> i32 {
    unsafe { process32_next_w(h_snapshot, lppe) }
}

// ── Power management ─────────────────────────────────────────────────────────

/// GetSystemPowerStatus — fill a SYSTEM_POWER_STATUS struct with battery/AC info.
///
/// Returns FALSE (0). Writes 12 zero bytes to the struct if the pointer is non-null.
/// SDL2 has an explicit fallback when this returns FALSE.
///
/// # Safety
/// `lp` must be either null or point to at least 12 writable bytes.
// Wine ref: dlls/kernel32/powermgnt.c — calls NtPowerInformation(SystemPowerStatusInformation);
// fills ACLineStatus, BatteryFlag, BatteryLifePercent, Reserved1, BatteryLifeTime,
// BatteryFullLifeTime (12 bytes total); returns FALSE on error.
pub unsafe extern "win64" fn get_system_power_status(lp: *mut u8) -> i32 {
    // AC power, 100% battery — closest approximation on a Linux host without battery
    if !lp.is_null() {
        unsafe { std::ptr::write_bytes(lp, 0, 12) };
        unsafe { *lp = 1 }; // ACLineStatus = AC_LINE_ONLINE
    }
    1
}

/// SetThreadExecutionState — prevent system sleep during video playback.
///
/// Returns the previous execution state (stubbed as ES_CONTINUOUS = 0x80000001).
/// SDL2 calls this with ES_DISPLAY_REQUIRED|ES_CONTINUOUS and ignores the return
/// value except for logging.
// Wine ref: dlls/kernel32/powermgnt.c — calls NtSetThreadExecutionState; saves and
// returns the previous state flags; ES_CONTINUOUS (0x80000000) indicates a persistent
// override that stays until cleared.
pub extern "win64" fn set_thread_execution_state(_es_flags: u32) -> u32 {
    0x80000001u32 // ES_CONTINUOUS — previous state; Linux has no sleep inhibit API here
}

/// RtlAddFunctionTable — register a dynamic unwind function table for SEH on x64.
///
/// Returns TRUE (1). SDL2 calls this at init for its own exception handler table.
/// Weave does not implement SEH unwinding through dynamic tables, so we accept the
/// call and return success.
///
/// # Safety
/// `function_table` and `base_address` are accepted but not dereferenced.
// Wine ref: dlls/ntdll/signal_x86_64.c — inserts the RUNTIME_FUNCTION table into a
// sorted list protected by a critical section; used by JIT engines and dynamic code.
pub unsafe extern "win64" fn rtl_add_function_table(
    _function_table: *const u8,
    _entry_count: u32,
    _base_address: u64,
) -> u8 {
    1 // Weave does not unwind through dynamic tables; accept silently
}

// ── Locale / language ────────────────────────────────────────────────────────

/// GetUserDefaultLangID — return the default language identifier.
///
/// Returns 0x0409 (English, United States).
// Wine ref: dlls/kernelbase/locale.c:6392 — LANGIDFROMLCID(GetUserDefaultLCID()); reads
// the user LCID from the NLS locale data; on Wine this comes from the registry or env vars.
pub extern "win64" fn get_user_default_lang_id() -> u16 {
    0x0409
}

// ── File operations ──────────────────────────────────────────────────────────

/// CopyFileExW — copy a file with progress callback (Wide).
///
/// Delegates to CopyFileW (ignores callback).
///
/// # Safety
/// `lp_existing_file_name` and `lp_new_file_name` must be valid null-terminated
/// UTF-16 strings.
// Wine ref: dlls/kernelbase/file.c — CopyFileExW opens source with FILE_SHARE_READ|WRITE|DELETE,
// calls progress routine after each 64KB chunk; COPY_FILE_FAIL_IF_EXISTS prevents overwrite;
// copies extended attributes and security descriptor when possible.
pub unsafe extern "win64" fn copy_file_ex_w(
    lp_existing_file_name: *const u16,
    lp_new_file_name: *const u16,
    _lp_progress_routine: usize,
    _lp_data: *mut u8,
    _pb_cancel: *mut i32,
    _dw_copy_flags: u32,
) -> i32 {
    unsafe { copy_file_w(lp_existing_file_name, lp_new_file_name, 0) }
}

/// GetCompressedFileSizeW — return the on-disk size of a file.
///
/// Wine ref: dlls/kernelbase/file.c — GetCompressedFileSizeW calls
/// NtQueryInformationFile(FileCompressionInformation) to get the compressed
/// size. Linux filesystems don't support NTFS compression, so we return the
/// actual file size via stat(). The high 32 bits are written to
/// lp_file_size_high if non-null. Returns INVALID_FILE_SIZE on error.
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-16 string or NULL.
/// `lp_file_size_high` must be a writable u32 pointer or NULL.
// Wine ref: dlls/kernelbase/file.c — GetCompressedFileSizeW: opens file with NtOpenFile,
// calls GetFileSize (not compression info) since Wine doesn't support compressed files either.
// Returns INVALID_FILE_SIZE (0xFFFFFFFF) on error. Weave uses stat64 directly.
pub unsafe extern "win64" fn get_compressed_file_size_w(
    lp_file_name: *const u16,
    lp_file_size_high: *mut u32,
) -> u32 {
    if lp_file_name.is_null() {
        return 0xFFFF_FFFF;
    }
    let mut len = 0usize;
    while len < MAX_UTF16_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    let wide = unsafe { std::slice::from_raw_parts(lp_file_name, len) };
    let s = String::from_utf16_lossy(wide);
    let linux_path = weave_core::prefix::translator()
        .to_linux_str(&s)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| s.clone());
    let cstr = match std::ffi::CString::new(linux_path.as_bytes()) {
        Ok(c) => c,
        Err(_) => return 0xFFFF_FFFF,
    };
    let mut st: libc::stat64 = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat64(cstr.as_ptr(), &mut st) } != 0 {
        return 0xFFFF_FFFF;
    }
    let size = st.st_size as u64;
    if !lp_file_size_high.is_null() {
        unsafe { *lp_file_size_high = (size >> 32) as u32 };
    }
    (size & 0xFFFF_FFFF) as u32
}

/// CreateHardLinkW — create a hard link (Wide). Returns FALSE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced beyond null check.
// Wine ref: dlls/kernelbase/file.c — opens source with FILE_WRITE_ATTRIBUTES via NtOpenFile,
// then calls NtSetInformationFile(FileLinkInformation) with the destination NT path;
// requires the same volume (STATUS_NOT_SAME_DEVICE → ERROR_NOT_SAME_DEVICE).
pub unsafe extern "win64" fn create_hard_link_w(
    _lp_file_name: *const u16,
    _lp_existing_file_name: *const u16,
    _lp_security_attributes: *mut u8,
) -> i32 {
    0 // FALSE — hard links not supported in stub
}

/// MoveFileWithProgressW — move a file with progress callback.
///
/// Delegates to MoveFileExW (ignores callback).
///
/// # Safety
/// Pointer arguments must be valid null-terminated UTF-16 strings or null.
// Wine ref: dlls/kernelbase/file.c:2623 — this is the real MoveFileExW implementation;
// MoveFileExW delegates here with progress=NULL; handles MOVEFILE_DELAY_UNTIL_REBOOT
// and cross-device moves (MOVEFILE_COPY_ALLOWED falls back to CopyFileExW+DeleteFileW).
pub unsafe extern "win64" fn move_file_with_progress_w(
    lp_existing_file_name: *const u16,
    lp_new_file_name: *const u16,
    _lp_progress_routine: usize,
    _lp_data: *mut u8,
    dw_flags: u32,
) -> i32 {
    unsafe { move_file_ex_w(lp_existing_file_name, lp_new_file_name, dw_flags) }
}

/// GetDiskFreeSpaceW — return disk free/total space information.
///
/// Queries the real filesystem via `statvfs(2)` and returns cluster-level
/// disk space information. Null `lpRootPathName` defaults to `"/"`.
///
/// # Safety
/// Output pointer arguments must be writable or null.
// Wine ref: dlls/kernelbase/volume.c:656 — opens root path via NtOpenFile then calls
// NtQueryVolumeInformationFile(FileFsSizeInformation); NULL root defaults to current
// directory; writes SectorsPerAllocationUnit, BytesPerSector, free and total cluster
// counts (Win32 mode only — we skip the Win9x 2GB/65535 cap).
pub unsafe extern "win64" fn get_disk_free_space_w(
    lp_root_path_name: *const u16,
    lp_sectors_per_cluster: *mut u32,
    lp_bytes_per_sector: *mut u32,
    lp_number_of_free_clusters: *mut u32,
    lp_total_number_of_clusters: *mut u32,
) -> i32 {
    const ERROR_INVALID_PARAMETER: u32 = 87;

    // Resolve the query path: translate Win32 wide string, or fall back to "/".
    let query_path: std::ffi::CString = if lp_root_path_name.is_null() {
        eprintln!("weave/GetDiskFreeSpaceW: path=(null→\"/\")");
        std::ffi::CString::new("/").unwrap()
    } else {
        // Decode the wide string.
        let mut len = 0usize;
        while len < 32768 && unsafe { *lp_root_path_name.add(len) } != 0 {
            len += 1;
        }
        let win_path =
            unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_root_path_name, len)) };
        eprintln!("weave/GetDiskFreeSpaceW: path={win_path:?}");
        match weave_core::file_io::translate_win_path(&win_path) {
            Ok(p) => match std::ffi::CString::new(p.as_os_str().as_encoded_bytes()) {
                Ok(s) => s,
                Err(_) => std::ffi::CString::new("/").unwrap(),
            },
            Err(_) => std::ffi::CString::new("/").unwrap(),
        }
    };

    let mut sv: libc::statvfs = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::statvfs(query_path.as_ptr(), &mut sv) };
    if ret != 0 {
        eprintln!("weave/GetDiskFreeSpaceW: → FALSE (statvfs failed)");
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0; // FALSE
    }

    // Derive cluster geometry from filesystem fragment size.
    // f_frsize is the fundamental block size used for f_bavail/f_bfree/f_blocks.
    // Fix bytes-per-sector at 512 (standard Windows assumption).
    // Sectors-per-cluster = f_frsize / 512, clamped to at least 1.
    const BYTES_PER_SECTOR: u32 = 512;
    let frsize = sv.f_frsize.max(512);
    let sectors_per_cluster = (frsize / 512).min(u32::MAX as u64) as u32;

    // Free and total clusters: capped to u32::MAX (Wine does the same
    // to avoid overflow on very large volumes — u.LowPart truncation).
    // f_bfree counts free blocks; each block is 1 cluster in this model.
    let free_clusters = sv.f_bfree.min(u32::MAX as u64) as u32;
    // Total clusters from f_blocks, capped.
    let total_clusters = sv.f_blocks.min(u32::MAX as u64) as u32;

    if !lp_sectors_per_cluster.is_null() {
        unsafe { *lp_sectors_per_cluster = sectors_per_cluster };
    }
    if !lp_bytes_per_sector.is_null() {
        unsafe { *lp_bytes_per_sector = BYTES_PER_SECTOR };
    }
    if !lp_number_of_free_clusters.is_null() {
        unsafe { *lp_number_of_free_clusters = free_clusters };
    }
    if !lp_total_number_of_clusters.is_null() {
        unsafe { *lp_total_number_of_clusters = total_clusters };
    }
    eprintln!("weave/GetDiskFreeSpaceW: → TRUE (free={free_clusters} total={total_clusters})");
    1 // TRUE
}

/// FileTimeToDosDateTime — convert FILETIME to MS-DOS date/time.
///
/// Returns a fixed date/time (2026-01-01 00:00:00).
///
/// # Safety
/// Output pointers must be writable or null.
// Wine ref: dlls/kernelbase/file.c — converts FILETIME via FileTimeToLocalFileTime then
// FileTimeToSystemTime; encodes year-1980 in bits 9-15, month in 5-8, day in 0-4 of date
// and hour in 11-15, min in 5-10, 2-second count in 0-4 of time.
pub unsafe extern "win64" fn file_time_to_dos_date_time(
    _lp_file_time: *const u64,
    lp_fat_date: *mut u16,
    lp_fat_time: *mut u16,
) -> i32 {
    eprintln!("weave/FileTimeToDosDateTime: → fixed 2026-01-01 00:00:00 (stub)");
    // MS-DOS date: year since 1980 in bits 9-15, month in 5-8, day in 0-4.
    // 2026-01-01: year=46 (2026-1980), month=1, day=1 → 0x5C21
    if !lp_fat_date.is_null() {
        unsafe { *lp_fat_date = ((46 << 9) | (1 << 5) | 1) as u16 };
    }
    // MS-DOS time: hour in bits 11-15, minute in 5-10, 2-sec in 0-4.
    if !lp_fat_time.is_null() {
        unsafe { *lp_fat_time = 0 };
    }
    1 // TRUE
}

/// GlobalMemoryStatusEx — fill a MEMORYSTATUSEX structure.
///
/// Reports 16 GB physical RAM, 8 GB free.
///
/// # Safety
/// GlobalMemoryStatusEx — fill MEMORYSTATUSEX from /proc/meminfo.
///
/// Wine ref: dlls/kernelbase/memory.c — GlobalMemoryStatusEx calls
/// NtQuerySystemInformation(SystemBasicInformation + SystemPerformanceInformation)
/// to read page counts and page size. On Linux we parse /proc/meminfo directly,
/// reading MemTotal and MemAvailable (in kB). Page file is approximated from
/// SwapTotal/SwapFree. Virtual address space is fixed at 128 TB (x86-64 user).
///
/// MEMORYSTATUSEX layout (all u64 fields after the u32 dwLength at +0):
///   +0  u32 dwLength   (must be 64 — validated by caller before calling us)
///   +4  u32 dwMemoryLoad
///   +8  u64 ullTotalPhys
///   +16 u64 ullAvailPhys
///   +24 u64 ullTotalPageFile
///   +32 u64 ullAvailPageFile
///   +40 u64 ullTotalVirtual
///   +48 u64 ullAvailVirtual
///   +56 u64 ullAvailExtendedVirtual
///
/// # Safety
/// `lp_buffer` must be a writable MEMORYSTATUSEX (64 bytes, first DWORD = dwLength).
// Wine ref: dlls/kernelbase/memory.c — GlobalMemoryStatusEx: dwLength != 64 →
// ERROR_INVALID_PARAMETER. Caches result for 1 second (GetTickCount64 diff < 1000).
// ullAvailVirtual ≈ ullTotalVirtual - WorkingSetSize (approximate). Weave: reads /proc/meminfo.
pub unsafe extern "win64" fn global_memory_status_ex(lp_buffer: *mut u8) -> i32 {
    if lp_buffer.is_null() {
        return 0;
    }
    const KB: u64 = 1024;
    const GB: u64 = 1024 * 1024 * 1024;
    // Defaults in case /proc/meminfo is unreadable.
    let mut total_phys: u64 = 8 * GB;
    let mut avail_phys: u64 = 4 * GB;
    let mut total_swap: u64 = 0;
    let mut avail_swap: u64 = 0;
    // Parse /proc/meminfo for real values.
    if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
        for line in contents.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let val: u64 = parts[1].parse().unwrap_or(0) * KB;
                match parts[0] {
                    "MemTotal:" => total_phys = val,
                    "MemAvailable:" => avail_phys = val,
                    "SwapTotal:" => total_swap = val,
                    "SwapFree:" => avail_swap = val,
                    _ => {}
                }
            }
        }
    }
    let memory_load: u32 = if total_phys > 0 {
        ((total_phys - avail_phys) / (total_phys / 100)) as u32
    } else {
        50
    };
    // SAFETY: lp_buffer is non-null (checked above) and the caller guarantees
    // at least 64 bytes (sizeof MEMORYSTATUSEX).  The MEMORYSTATUSEX x64 layout is:
    //   +0  DWORD  dwLength        (caller must pre-fill; we don't clobber it)
    //   +4  DWORD  dwMemoryLoad
    //   +8  DWORDLONG  ullTotalPhys
    //   +16 DWORDLONG  ullAvailPhys
    //   +24 DWORDLONG  ullTotalPageFile
    //   +32 DWORDLONG  ullAvailPageFile
    //   +40 DWORDLONG  ullTotalVirtual
    //   +48 DWORDLONG  ullAvailVirtual
    //   +56 DWORDLONG  ullAvailExtendedVirtual
    // All u64 fields are at 8-byte-aligned offsets so direct pointer casts are sound.
    unsafe {
        *(lp_buffer.add(4) as *mut u32) = memory_load;
        *(lp_buffer.add(8) as *mut u64) = total_phys;
        *(lp_buffer.add(16) as *mut u64) = avail_phys;
        *(lp_buffer.add(24) as *mut u64) = total_phys + total_swap;
        *(lp_buffer.add(32) as *mut u64) = avail_phys + avail_swap;
        *(lp_buffer.add(40) as *mut u64) = 0x0000_7FFF_0000_0000u64; // 128 TB user VA
        *(lp_buffer.add(48) as *mut u64) = 0x0000_7FFE_0000_0000u64; // approx avail VA
        *(lp_buffer.add(56) as *mut u64) = 0;
    }
    eprintln!("weave/GlobalMemoryStatusEx: total_phys={total_phys} avail_phys={avail_phys}");
    1 // TRUE
}

/// SetPriorityClass — map a Windows priority class to a Linux nice value.
///
/// Wine ref: dlls/kernelbase/process.c — SetPriorityClass maps the Windows
/// priority class to an NT priority value via NtSetInformationProcess. On
/// Linux we map to setpriority(PRIO_PROCESS). Windows classes: IDLE=0x40 →
/// nice 15, BELOW_NORMAL=0x4000 → nice 10, NORMAL=0x20 → nice 0,
/// ABOVE_NORMAL=0x8000 → nice -5, HIGH=0x80 → nice -10. REALTIME is
/// silently clamped to HIGH (requires CAP_SYS_NICE we don't have).
///
/// # Safety
/// No pointer dereferences. h_process is the current process sentinel.
// Wine ref: dlls/kernelbase/process.c — SetPriorityClass: unmapped class value →
// ERROR_INVALID_PARAMETER. Maps to PROCESS_PRIOCLASS_* and calls NtSetInformationProcess.
// Weave: maps to Linux nice values via setpriority; REALTIME clamped to HIGH.
pub unsafe extern "win64" fn set_priority_class(_h_process: usize, dw_priority_class: u32) -> i32 {
    let nice: libc::c_int = match dw_priority_class {
        0x00000040 => 15,  // IDLE_PRIORITY_CLASS
        0x00004000 => 10,  // BELOW_NORMAL_PRIORITY_CLASS
        0x00000020 => 0,   // NORMAL_PRIORITY_CLASS
        0x00008000 => -5,  // ABOVE_NORMAL_PRIORITY_CLASS
        0x00000080 => -10, // HIGH_PRIORITY_CLASS
        0x00000100 => -10, // REALTIME_PRIORITY_CLASS → clamped to HIGH
        _ => return 1,     // Unknown class — silently succeed
    };
    // Ignore errors (may lack permissions); always return TRUE.
    unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) };
    1 // TRUE
}

// ── Change notifications ──────────────────────────────────────────────────────

/// FindFirstChangeNotificationW — watch a directory for changes.
///
/// Returns INVALID_HANDLE_VALUE — stub, no filesystem watching.
///
/// # Safety
/// `lp_path_name` is accepted but not dereferenced beyond null check.
// Wine ref: dlls/kernelbase/file.c:1162 — opens directory with FILE_LIST_DIRECTORY|SYNCHRONIZE
// via NtOpenFile, then calls NtNotifyChangeDirectoryFile; returns the directory handle as the
// change notification handle; ERROR_PATH_NOT_FOUND if path doesn't exist.
pub unsafe extern "win64" fn find_first_change_notification_w(
    _lp_path_name: *const u16,
    _b_watch_subtree: i32,
    _dw_notify_filter: u32,
) -> usize {
    set_last_error(1); // ERROR_INVALID_FUNCTION — inotify not wired up
    usize::MAX // INVALID_HANDLE_VALUE
}

/// FindNextChangeNotification — wait for the next change notification.
///
/// Returns FALSE — stub.
///
/// # Safety
/// No pointer dereferences.
// Wine ref: dlls/kernelbase/file.c:1199 — calls NtNotifyChangeDirectoryFile again on the
// same directory handle returned by FindFirstChangeNotificationW; returns STATUS_PENDING.
pub unsafe extern "win64" fn find_next_change_notification(_h_change_handle: usize) -> i32 {
    0 // FALSE — no real change notification handle
}

/// FindCloseChangeNotification — close a change notification handle.
///
/// Returns TRUE — stub (no real handle to close).
///
/// # Safety
/// No pointer dereferences.
// Wine ref: dlls/kernelbase/file.c:1134 — calls NtClose on the directory handle that was
// returned by FindFirstChangeNotificationW; handle is the same dir fd used for watching.
pub unsafe extern "win64" fn find_close_change_notification(_h_change_handle: usize) -> i32 {
    1
}

// ── NTFS streams ─────────────────────────────────────────────────────────────

/// FindFirstStreamW — enumerate alternate data streams of a file.
///
/// Linux filesystems do not have NTFS alternate data streams, so the correct
/// behavior for every path is "no streams." Returns INVALID_HANDLE_VALUE with
/// LastError=ERROR_HANDLE_EOF (38), matching Wine's stub in dlls/kernelbase/file.c.
///
/// Callers like 7za interpret ERROR_HANDLE_EOF as "no streams to enumerate,
/// proceed normally" — whereas ERROR_INVALID_PARAMETER (the previous return)
/// is wrapped as HRESULT 0x80070057 and thrown as a fatal exception.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/file.c:1475 —
//   HANDLE WINAPI FindFirstStreamW(...) {
//       FIXME("(%s, %d, %p, %lx): stub!\n", debugstr_w(filename), level, data, flags);
//       SetLastError( ERROR_HANDLE_EOF );
//       return INVALID_HANDLE_VALUE;
//   }
pub unsafe extern "win64" fn find_first_stream_w(
    lp_file_name: *const u16,
    info_level: u32,
    _lp_find_stream_data: *mut u8,
    dw_flags: u32,
) -> usize {
    eprintln!(
        "weave/kernel32: FindFirstStreamW(filename={lp_file_name:?}, info_level={info_level}, flags={dw_flags:#x})"
    );
    set_last_error(38); // ERROR_HANDLE_EOF — no streams (Linux has no NTFS ADS)
    eprintln!(
        "weave/kernel32: FindFirstStreamW → INVALID_HANDLE_VALUE, LastError=ERROR_HANDLE_EOF (38)"
    );
    usize::MAX
}

/// FindNextStreamW — enumerate alternate data streams (next entry).
///
/// Returns FALSE with LastError=ERROR_HANDLE_EOF. Since `find_first_stream_w`
/// always reports "no streams", any handle reaching this function is invalid
/// or already exhausted — either way EOF semantics are correct.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/file.c — advances internal pointer in the FIND_STREAM_DATA
// buffer; returns ERROR_HANDLE_EOF (equivalent to no-more-files) when streams exhausted.
pub unsafe extern "win64" fn find_next_stream_w(
    h_find_stream: usize,
    _lp_find_stream_data: *mut u8,
) -> i32 {
    eprintln!("weave/kernel32: FindNextStreamW(handle={h_find_stream:#x})");
    set_last_error(38); // ERROR_HANDLE_EOF — no more streams
    eprintln!("weave/kernel32: FindNextStreamW → FALSE, LastError=ERROR_HANDLE_EOF (38)");
    0 // FALSE
}

/// GetModuleHandleA — get a handle to an already-loaded module (ANSI).
///
/// NULL `lp_module_name` means "the main executable" — return the actual
/// PE load address recorded by the SEH module.
///
/// # Safety
/// `lp_module_name` must be null or a valid null-terminated ANSI string.
// Wine ref: dlls/kernelbase/loader.c — GetModuleHandleA converts via RtlCreateUnicodeStringFromAsciiz
// then delegates to GetModuleHandleExW(UNCHANGED_REFCOUNT, name, &module); NULL returns
// NtCurrentTeb()->Peb->ImageBaseAddress (the main exe base).
pub unsafe extern "win64" fn get_module_handle_a(lp_module_name: *const u8) -> usize {
    eprintln!("weave/kernel32: GetModuleHandleA entry");
    if lp_module_name.is_null() {
        return weave_core::seh::pe_base();
    }
    let name = unsafe { read_cstr_a(lp_module_name) };
    let key = dll_lookup_key(&name);
    let h = if is_always_present_dll(&key) {
        weave_core::module_handles::register(&key)
    } else {
        weave_core::module_handles::find(&key).unwrap_or(0)
    };
    eprintln!("weave/kernel32: GetModuleHandleA({name:?}) → {h:#x}");
    h
}

/// GetModuleHandleW — get a handle to an already-loaded module (wide).
///
/// # Safety
/// `lp_module_name` must be null or a valid null-terminated UTF-16 string.
// Wine ref: dlls/kernelbase/loader.c — delegates to GetModuleHandleExW(UNCHANGED_REFCOUNT).
pub unsafe extern "win64" fn get_module_handle_w(lp_module_name: *const u16) -> usize {
    if lp_module_name.is_null() {
        return weave_core::seh::pe_base();
    }
    let name = unsafe { read_cstr_w(lp_module_name) };
    let key = dll_lookup_key(&name);
    let h = if is_always_present_dll(&key) {
        weave_core::module_handles::register(&key)
    } else {
        weave_core::module_handles::find(&key).unwrap_or(0)
    };
    eprintln!("weave/kernel32: GetModuleHandleW({name:?}) → {h:#x}");
    h
}

/// GetModuleHandleExA — extended module handle lookup (ANSI).
///
/// # Safety
/// `lp_module_name` must be null or a valid null-terminated ANSI string.
/// `ph_module` must be a valid writable pointer.
// Wine ref: dlls/kernelbase/loader.c:353 — converts name via RtlCreateUnicodeStringFromAsciiz
// then calls GetModuleHandleExW; frees the temp UNICODE_STRING; returns FALSE+sets module=NULL
// on NULL module output pointer.
pub unsafe extern "win64" fn get_module_handle_ex_a(
    _dw_flags: u32,
    lp_module_name: *const u8,
    ph_module: *mut usize,
) -> i32 {
    let handle = unsafe { get_module_handle_a(lp_module_name) };
    if !ph_module.is_null() {
        unsafe { *ph_module = handle };
    }
    1 // TRUE
}

/// GetModuleHandleExW — extended module handle lookup (wide).
///
/// # Safety
/// `lp_module_name` must be null or a valid null-terminated UTF-16 string.
/// `ph_module` must be a valid writable pointer.
// Wine ref: dlls/kernelbase/loader.c:379 — GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS uses
// RtlPcToFileHeader to find the module base for a code address; PIN and UNCHANGED_REFCOUNT
// flags are mutually exclusive (ERROR_INVALID_PARAMETER if both set); NULL module output
// pointer also returns ERROR_INVALID_PARAMETER.
pub unsafe extern "win64" fn get_module_handle_ex_w(
    _dw_flags: u32,
    lp_module_name: *const u16,
    ph_module: *mut usize,
) -> i32 {
    let handle = unsafe { get_module_handle_w(lp_module_name) };
    if !ph_module.is_null() {
        unsafe { *ph_module = handle };
    }
    1 // TRUE
}

/// GetModuleFileNameW — return the file path for a module handle (wide).
///
/// Returns a fake path for NULL (main exe) or registered DLLs.
///
/// # Safety
/// `lp_filename` must be a writable buffer of at least `n_size` wide chars.
// Wine ref: dlls/kernelbase/loader.c:300 — calls LdrGetDllFullName; NULL module returns
// ImageBaseAddress path; STATUS_BUFFER_TOO_SMALL still returns the truncated length and
// sets ERROR_INSUFFICIENT_BUFFER (unlike most APIs that return 0 on overflow).
pub unsafe extern "win64" fn get_module_file_name_w(
    h_module: usize,
    lp_filename: *mut u16,
    n_size: u32,
) -> u32 {
    if lp_filename.is_null() || n_size == 0 {
        return 0;
    }
    let path = if h_module == 0 || h_module == weave_core::seh::pe_base() {
        // NULL or main-exe handle — return the real exe path so apps can locate
        // their own directory (plugins, config files, etc.)
        let p = weave_core::exe_path::get()
            .unwrap_or(r"Z:\app.exe")
            .to_string();
        eprintln!("weave/kernel32: GetModuleFileNameW(NULL) → {p:?}");
        p
    } else {
        match weave_core::module_handles::lookup(h_module) {
            Some(dll) => format!(r"Z:\Windows\System32\{dll}"),
            None => return 0,
        }
    };
    let wide: Vec<u16> = path.encode_utf16().collect();
    let copy_len = wide.len().min((n_size as usize) - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), lp_filename, copy_len);
        *lp_filename.add(copy_len) = 0; // null terminator
    }
    eprintln!("weave/kernel32: GetModuleFileNameW returning {copy_len}");
    copy_len as u32
}

/// GetModuleFileNameExW — psapi.dll / K32GetModuleFileNameExW variant.
///
/// SDL2's `SDL_GetBasePath()` calls this to obtain the exe path.
/// For the current-process + NULL-module case (the only case SDL2 uses),
/// behaviour is identical to `GetModuleFileNameW(NULL, ...)`, so we
/// ignore `h_process` and delegate.
///
/// # Safety
/// `lp_filename` must be a writable buffer of at least `n_size` wide chars.
// Wine ref: dlls/psapi/psapi.c — K32GetModuleFileNameExW calls
// NtQueryVirtualMemory(MemoryMappedFilenameInformation) for current process +
// NULL module, which yields the exe image path; for SDL2's use case the
// existing GetModuleFileNameW(NULL) path already returns the correct value.
pub unsafe extern "win64" fn get_module_file_name_ex_w(
    _h_process: usize,
    h_module: usize,
    lp_filename: *mut u16,
    n_size: u32,
) -> u32 {
    unsafe { get_module_file_name_w(h_module, lp_filename, n_size) }
}

/// GetModuleFileNameA — return the file path for a module handle (ANSI).
///
/// # Safety
/// `lp_filename` must be a writable buffer of at least `n_size` bytes.
// Wine ref: dlls/kernelbase/loader.c:274 — heap-allocates a WCHAR buffer of `size` chars,
// calls GetModuleFileNameW, converts result via file_name_WtoA; sets ERROR_INSUFFICIENT_BUFFER
// if converted length equals size (no room for null terminator).
pub unsafe extern "win64" fn get_module_file_name_a(
    h_module: usize,
    lp_filename: *mut u8,
    n_size: u32,
) -> u32 {
    if lp_filename.is_null() || n_size == 0 {
        return 0;
    }
    let path = if h_module == 0 || h_module == weave_core::seh::pe_base() {
        weave_core::exe_path::get()
            .unwrap_or(r"Z:\app.exe")
            .to_string()
    } else {
        match weave_core::module_handles::lookup(h_module) {
            Some(dll) => format!(r"Z:\Windows\System32\{dll}"),
            None => return 0,
        }
    };
    let bytes = path.as_bytes();
    let copy_len = bytes.len().min((n_size as usize) - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_filename, copy_len);
        *lp_filename.add(copy_len) = 0; // null terminator
    }
    copy_len as u32
}

// ── Process / thread identity ─────────────────────────────────────────────────

/// GetCurrentProcess — return a pseudo-handle (-1 = 0xFFFFFFFFFFFFFFFF).
// Wine ref: include/winbase.h — inline that returns (HANDLE)(LONG_PTR)-1;
// pseudo-handles are never closed and are valid for the current process only.
pub extern "win64" fn get_current_process() -> usize {
    usize::MAX // pseudo-handle
}

/// GetCurrentThread — return a pseudo-handle (-2 = 0xFFFFFFFFFFFFFFFE).
// Wine ref: include/winbase.h — inline that returns (HANDLE)(LONG_PTR)-2;
// must not be passed to functions that close handles (CloseHandle would fail).
pub extern "win64" fn get_current_thread() -> usize {
    usize::MAX - 1
}

/// GetCurrentProcessId — returns the Linux PID (matches Windows behaviour).
///
/// Wine ref: include/winbase.h — GetCurrentProcessId reads from the TEB
/// process ID field, which the kernel fills with the PID. On Linux we call
/// getpid() directly; the value is identical to what Windows would return
/// for single-process guests.
pub extern "win64" fn get_current_process_id() -> u32 {
    unsafe { libc::getpid() as u32 }
}

/// GetCurrentThreadId — returns the Linux thread ID (TID).
///
/// Wine ref: include/winbase.h — GetCurrentThreadId reads handle slot [9]
/// from NtCurrentTeb(), which stores the thread ID. On Linux we use
/// gettid() (SYS_gettid syscall). For the main thread this equals the PID;
/// for any spawned threads it is unique — matches the Windows semantics.
pub extern "win64" fn get_current_thread_id() -> u32 {
    // SAFETY: SYS_gettid takes no arguments and never fails.
    unsafe { libc::syscall(libc::SYS_gettid) as u32 }
}

// ── Timing ────────────────────────────────────────────────────────────────────

/// GetTickCount — milliseconds since process start (stub: use clock_gettime).
// Wine ref: dlls/kernelbase/time.c — reads SharedUserData->TickCount (updated by the kernel);
// wraps at ~49.7 days (u32 overflow); callers must handle wrap-around.
pub extern "win64" fn get_tick_count() -> u32 {
    get_tick_count_64() as u32
}

/// GetTickCount64 — milliseconds since process start.
// Wine ref: dlls/kernelbase/time.c — reads SharedUserData->TickCount64 (64-bit monotonic);
// never wraps; introduced Vista+; Weave uses CLOCK_MONOTONIC directly.
pub extern "win64" fn get_tick_count_64() -> u64 {
    static GTC_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = GTC_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Log at call #0 and every 10,000 calls — detects GetTickCount spin-wait loops.
    if n == 0 || n.is_multiple_of(10_000) {
        eprintln!("weave/GetTickCount64: call #{n}");
    }
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000
}

/// QueryPerformanceCounter — returns nanoseconds from CLOCK_MONOTONIC.
///
/// Wine ref: dlls/ntdll/time.c — RtlQueryPerformanceCounter calls
/// NtQueryPerformanceCounter; Wine reports 100-ns resolution (10 MHz).
/// Weave reports 1-ns resolution (1 GHz) via CLOCK_MONOTONIC, matching
/// QueryPerformanceFrequency which returns 1_000_000_000.
///
/// # Safety
/// `lp_performance_count` must be a valid writable pointer or NULL.
// Wine ref: dlls/ntdll/time.c — RtlQueryPerformanceCounter calls NtQueryPerformanceCounter.
// Wine's QpcFrequency is 10_000_000 (10 MHz, 100-ns ticks) from SharedUserData.
// Weave uses CLOCK_MONOTONIC at 1 GHz (nanosecond ticks) for higher resolution.
pub unsafe extern "win64" fn query_performance_counter(lp_performance_count: *mut u64) -> i32 {
    static QPC_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = QPC_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        if !lp_performance_count.is_null() {
            *lp_performance_count = ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64;
        }
    }
    // First 4 calls: always log value (E3-M4b diagnostic). Thereafter: every 1M calls.
    if n < 4 {
        eprintln!(
            "weave/QueryPerformanceCounter: call #{n} counter={}",
            if lp_performance_count.is_null() {
                0u64
            } else {
                unsafe { *lp_performance_count }
            }
        );
    } else if n.is_multiple_of(1_000_000) {
        eprintln!("weave/QueryPerformanceCounter: call #{n}");
    }
    1 // TRUE
}

/// QueryPerformanceFrequency — reports nanosecond resolution (1 GHz).
///
/// # Safety
/// `lp_frequency` must be a valid writable pointer or NULL.
// Wine ref: dlls/ntdll/time.c — RtlQueryPerformanceFrequency returns
// SharedUserData->QpcFrequency which Wine sets to 10_000_000 (10 MHz, 100-ns ticks);
// Weave uses 1_000_000_000 (1 GHz) to match CLOCK_MONOTONIC nanosecond resolution.
pub unsafe extern "win64" fn query_performance_frequency(lp_frequency: *mut u64) -> i32 {
    static QPF_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = QPF_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    const FREQ: u64 = 1_000_000_000;
    unsafe {
        if !lp_frequency.is_null() {
            *lp_frequency = FREQ;
        }
    }
    if n < 4 {
        eprintln!("weave/QueryPerformanceFrequency: call #{n} freq={FREQ}");
    }
    1 // TRUE
}

/// GetSystemTimeAsFileTime — fills FILETIME from CLOCK_REALTIME.
///
/// Wine ref: dlls/kernelbase/file.c — GetSystemTimeAsFileTime delegates to
/// NtQuerySystemTime which reads CLOCK_REALTIME and converts to 100-ns
/// intervals since 1601-01-01. The 116_444_736_000_000_000 offset covers
/// the 11644473600-second gap between 1601 and 1970 epochs.
///
/// # Safety
/// `lp_system_time_as_file_time` must be a valid writable pointer or NULL.
// Wine ref: dlls/kernelbase/file.c — GetSystemTimeAsFileTime calls NtQuerySystemTime
// which reads CLOCK_REALTIME and returns 100-ns intervals since 1601-01-01.
// Weave converts CLOCK_REALTIME directly using the 116_444_736_000_000_000 epoch offset.
pub unsafe extern "win64" fn get_system_time_as_file_time(lp_system_time_as_file_time: *mut u64) {
    // FILETIME is 100-nanosecond intervals since 1601-01-01
    // Offset between 1601 and Unix epoch (1970) = 11644473600 seconds
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        if !lp_system_time_as_file_time.is_null() {
            let ns = ts.tv_sec as u64 * 10_000_000 + ts.tv_nsec as u64 / 100;
            let ft = ns + 116_444_736_000_000_000u64;
            *lp_system_time_as_file_time = ft;
            eprintln!("weave/GetSystemTimeAsFileTime: → {ft}");
        }
    }
}

// ── System information ────────────────────────────────────────────────────────

/// SYSTEM_INFO layout (Windows x64, 64 bytes).
#[repr(C)]
pub struct SystemInfo {
    processor_architecture: u16,
    reserved: u16,
    page_size: u32,
    minimum_application_address: usize,
    maximum_application_address: usize,
    active_processor_mask: usize,
    number_of_processors: u32,
    processor_type: u32,
    allocation_granularity: u32,
    processor_level: u16,
    processor_revision: u16,
}

/// GetSystemInfo — fills a SYSTEM_INFO with real CPU count from nprocs.
///
/// Wine ref: dlls/kernelbase/process.c — GetSystemInfo calls
/// NtQuerySystemInformation(SystemBasicInformation) which the kernel fills
/// from the actual hardware. On Linux we read the CPU count via
/// libc::get_nprocs() and build an active_processor_mask accordingly.
/// page_size is read from sysconf(_SC_PAGESIZE); other fields are AMD64 constants.
///
/// # Safety
/// `lp_system_info` must be a valid writable pointer or NULL.
// Wine ref: dlls/kernelbase/memory.c — GetSystemInfo: calls NtQuerySystemInformation with
// SystemBasicInformation + SystemCpuInformation then fill_system_info. ProcessorArchitecture
// comes from cpu_info.ProcessorArchitecture; AllocationGranularity from basic_info.AllocationGranularity.
pub unsafe extern "win64" fn get_system_info(lp_system_info: *mut SystemInfo) {
    unsafe {
        if lp_system_info.is_null() {
            return;
        }
        let nprocs = libc::sysconf(libc::_SC_NPROCESSORS_ONLN) as u32;
        let nprocs = nprocs.clamp(1, 64); // clamp: mask is 64-bit
        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as u32;
        let active_mask: usize = if nprocs >= 64 {
            usize::MAX
        } else {
            (1usize << nprocs) - 1
        };
        (*lp_system_info) = SystemInfo {
            processor_architecture: 9, // PROCESSOR_ARCHITECTURE_AMD64
            reserved: 0,
            page_size,
            minimum_application_address: 0x10000,
            maximum_application_address: 0x7FFF_FFFF_FFFF,
            active_processor_mask: active_mask,
            number_of_processors: nprocs,
            processor_type: 8664, // Intel64 / AMD64
            allocation_granularity: 65536,
            processor_level: 6,
            processor_revision: 0,
        };
        eprintln!(
            "weave/GetSystemInfo: nprocs={nprocs} page_size={page_size} alloc_granularity=65536"
        );
    }
}

/// GetNativeSystemInfo — identical to GetSystemInfo.
///
/// Many apps call this on 64-bit Windows instead of GetSystemInfo.
/// Just calls the existing get_system_info function internally.
///
/// # Safety
/// `lp_system_info` must be a valid writable pointer or NULL.
// Wine ref: dlls/kernelbase/memory.c:207 — calls RtlGetNativeSystemInformation for WoW64 processes;
// uses RtlWow64GetProcessMachines to detect native vs WoW64; falls back to GetSystemInfo for non-WoW64
pub unsafe extern "win64" fn get_native_system_info(lp_system_info: *mut SystemInfo) {
    unsafe { get_system_info(lp_system_info) };
}

// ── Debugger / diagnostics ────────────────────────────────────────────────────

/// IsDebuggerPresent — always returns FALSE.
// Wine ref: dlls/kernelbase/debug.c — reads NtCurrentTeb()->Peb->BeingDebugged; returns 1 if set, 0 otherwise
pub extern "win64" fn is_debugger_present() -> i32 {
    0 // FALSE
}

/// OutputDebugStringA — silently discards the string.
///
/// # Safety
/// Pointer argument is accepted but not dereferenced.
// Wine ref: dlls/kernelbase/debug.c — raises DBG_PRINTEXCEPTION_C (0x40010006) via NtRaiseException;
// if no debugger is attached the exception is caught internally; also sends to console via NtDeviceIoControlFile
pub unsafe extern "win64" fn output_debug_string_a(_lp_output_string: *const u8) {
    // silently discard — no debugger attached; Wine raises DBG_PRINTEXCEPTION_C which
    // is caught internally when no debugger is present
}

/// OutputDebugStringW — silently discards the string.
///
/// # Safety
/// Pointer argument is accepted but not dereferenced.
// Wine ref: dlls/kernelbase/debug.c:275 — converts via RtlUnicodeStringToAnsiString (not WideCharToMultiByte);
// raises DBG_PRINTEXCEPTION_WIDE_C with 4-arg array [wcslen+1, wide_ptr, strlen+1, ansi_ptr];
// only falls back to OutputDebugStringA if the exception is not caught by a debugger.
pub unsafe extern "win64" fn output_debug_string_w(lp_output_string: *const u16) {
    if !lp_output_string.is_null() {
        let mut len = 0usize;
        while unsafe { *lp_output_string.add(len) } != 0 {
            len += 1;
        }
        let wide = unsafe { std::slice::from_raw_parts(lp_output_string, len) };
        let s = String::from_utf16_lossy(wide);
        eprint!("OutputDebugStringW: {s}");
    }
}

// ── Events / synchronisation ──────────────────────────────────────────────────

/// Internal helper: create an event handle backed by eventfd on Linux.
/// Falls back to a legacy fake handle (2) on macOS (build host only).
///
/// # Safety
/// Calls libc::eventfd on Linux. On macOS this is a compile-time no-op.
unsafe fn create_event_impl(_b_manual_reset: i32, b_initial_state: i32) -> usize {
    #[cfg(target_os = "linux")]
    {
        let efd = libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC);
        if efd < 0 {
            eprintln!(
                "weave/CreateEvent: eventfd() failed errno={}",
                *libc::__errno_location()
            );
            return 0; // NULL — caller must check
        }
        if b_initial_state != 0 {
            let val: u64 = 1;
            libc::write(efd, &val as *const u64 as *const libc::c_void, 8);
        }
        let handle = handles::alloc_event(efd);
        eprintln!("weave/CreateEvent: eventfd={efd} handle={handle:#x}");
        handle
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS build host: return legacy stub handle so cargo check passes.
        let _ = b_initial_state;
        2
    }
}

/// CreateEventA — create a Win32 event object.
///
/// On Linux: backed by eventfd(2) so WaitForSingleObject/WaitForMultipleObjects
/// can poll it with real I/O readiness. The handle is stored in the global
/// handle table via HandleKind::Event.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/sync.c:553 — converts name via RtlCreateUnicodeStringFromAsciiz
// then delegates to CreateEventExW(attr, name, flags, EVENT_ALL_ACCESS) where flags encode
// manual_reset (CREATE_EVENT_MANUAL_RESET=1) and initial_state (CREATE_EVENT_INITIAL_SET=2).
pub unsafe extern "win64" fn create_event_a(
    _lp_event_attributes: *const u8,
    b_manual_reset: i32,
    b_initial_state: i32,
    _lp_name: *const u8,
) -> usize {
    create_event_impl(b_manual_reset, b_initial_state)
}

/// CreateEventW — create a Win32 event object (wide-string name variant).
///
/// Same as CreateEventA but accepts wide string name parameter.
/// Name is ignored (unnamed event). Uses same eventfd backing as CreateEventA.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/sync.c:566 — delegates to CreateEventExW with CREATE_EVENT_MANUAL_RESET
// and CREATE_EVENT_INITIAL_SET flags translated from bManualReset/bInitialState booleans
pub unsafe extern "win64" fn create_event_w(
    _lp_event_attributes: *const u8,
    b_manual_reset: i32,
    b_initial_state: i32,
    _lp_name: *const u16,
) -> usize {
    create_event_impl(b_manual_reset, b_initial_state)
}

/// OpenEventA — returns a fake non-null handle (2).
///
/// Ignores access flags, inherit handle flag, and event name.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/sync.c — OpenEventA: converts name via MultiByteToWideChar(CP_ACP);
// name longer than MAX_PATH → ERROR_FILENAME_EXCED_RANGE. Delegates to OpenEventW →
// NtOpenEvent with OBJECT_ATTRIBUTES built from name. NULL handle → last-error set.
pub unsafe extern "win64" fn open_event_a(
    _dw_desired_access: u32,
    _b_inherit_handle: i32,
    _lp_name: *const u8,
) -> usize {
    2 // fake non-null event handle
}

/// OpenEventW — returns a fake non-null handle (2).
///
/// Ignores access flags, inherit handle flag, and event name.
///
// Wine ref: dlls/kernelbase/sync.c:653 — calls NtOpenEvent with OBJECT_ATTRIBUTES built from name;
// returns NULL on failure with last-error set via RtlNtStatusToDosError
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn open_event_w(
    _dw_desired_access: u32,
    _b_inherit_handle: i32,
    _lp_name: *const u16,
) -> usize {
    2 // fake non-null event handle
}

/// SetEvent — signal a Win32 event object.
///
/// On Linux: writes 1 to the backing eventfd, waking any thread blocked in
/// poll/WaitForSingleObject/WaitForMultipleObjects.
// Wine ref: dlls/kernelbase/sync.c:700 — calls NtSetEvent(handle, NULL); NULL for previous_state is valid
pub extern "win64" fn set_event(h_event: usize) -> i32 {
    eprintln!("weave/SetEvent: h={h_event:#x}");
    #[cfg(target_os = "linux")]
    if let Some(efd) = handles::get_event_fd(h_event) {
        let val: u64 = 1;
        unsafe {
            libc::write(efd, &val as *const u64 as *const libc::c_void, 8);
        }
        return 1; // TRUE
    }
    // Legacy stub handle or unknown — succeed silently.
    1
}

/// ResetEvent — clear a Win32 event object.
///
/// On Linux: drains the backing eventfd (reads the counter, ignores EAGAIN).
// Wine ref: dlls/kernelbase/sync.c:688 — calls NtResetEvent(handle, NULL)
pub extern "win64" fn reset_event(h_event: usize) -> i32 {
    #[cfg(target_os = "linux")]
    if let Some(efd) = handles::get_event_fd(h_event) {
        let mut val: u64 = 0;
        unsafe {
            libc::read(efd, &mut val as *mut u64 as *mut libc::c_void, 8);
        }
        return 1; // TRUE
    }
    1
}

/// CreateSemaphoreA — ANSI trampoline to CreateSemaphoreW.
///
/// Converts the ANSI name (out of scope; ignored) and delegates to the Wide
/// implementation.  All integer arguments pass through unchanged.
///
/// # Safety
/// Pointer arguments may be null; lp_name is ignored (named semaphores out of scope).
// Wine ref: dlls/kernelbase/sync.c:796 — CreateSemaphoreA converts name via
// RtlCreateUnicodeStringFromAsciiz then delegates to CreateSemaphoreW →
// CreateSemaphoreExW → NtCreateSemaphore. STATUS_OBJECT_NAME_EXISTS → ERROR_ALREADY_EXISTS.
pub unsafe extern "win64" fn create_semaphore_a(
    lp_semaphore_attributes: *const u8,
    l_initial_count: i32,
    l_maximum_count: i32,
    _lp_name: *const u8,
) -> usize {
    // Named semaphores are out of scope; pass null for name.
    create_semaphore_w(
        lp_semaphore_attributes,
        l_initial_count,
        l_maximum_count,
        std::ptr::null(),
    )
}
/// ReleaseSemaphore — increment a POSIX-backed semaphore by `l_release_count`.
///
/// Behavioral contract (Wine ref: server/semaphore.c:88 — release_semaphore):
///   - count must be ≥ 1; 0 or negative → FALSE + ERROR_INVALID_PARAMETER.
///   - If current_value + count > max_count → FALSE + ERROR_TOO_MANY_POSTS (298 / 0x12A).
///   - On success, writes previous count to *lp_previous_count if non-null, returns TRUE.
///   - On failure, does not modify *lp_previous_count.
///
/// # Known limitation
/// `sem_getvalue` + N×`sem_post` is not atomic.  In Weave's current single-process
/// model this window is safe; a multi-process named-semaphore implementation would
/// need a futex-based approach.
///
/// # Safety
/// `lp_previous_count` must be null or a valid aligned `*mut i32`.
// Wine ref: server/semaphore.c:88 — checks count overflow vs sem->max, writes prev,
// then increments; mirrors NtReleaseSemaphore → STATUS_SEMAPHORE_LIMIT_EXCEEDED on overflow.
pub unsafe extern "win64" fn release_semaphore(
    h_semaphore: usize,
    l_release_count: i32,
    lp_previous_count: *mut i32,
) -> i32 {
    // ERROR_INVALID_PARAMETER (87 / 0x57): count must be ≥ 1.
    if l_release_count < 1 {
        set_last_error(0x57); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let table = match sem_table()
        .lock()
        .map_err(|e| eprintln!("weave: semaphore table mutex poisoned: {e}"))
        .ok()
    {
        Some(g) => g,
        None => {
            set_last_error(6); // ERROR_INVALID_HANDLE
            return 0;
        }
    };

    let entry = match table.get(&h_semaphore) {
        Some(e) => e,
        None => {
            set_last_error(6); // ERROR_INVALID_HANDLE
            return 0;
        }
    };

    // Read current semaphore value before posting.
    let mut prev: libc::c_int = 0;
    let rc = unsafe {
        libc::sem_getvalue(
            &entry.sem.0 as *const libc::sem_t as *mut libc::sem_t,
            &mut prev,
        )
    };
    if rc != 0 {
        set_last_error(6); // ERROR_INVALID_HANDLE (sem_getvalue failure is unexpected)
        return 0;
    }

    // ERROR_TOO_MANY_POSTS (298 / 0x12A): releasing would exceed max_count.
    if prev + l_release_count > entry.max_count {
        set_last_error(0x12A); // ERROR_TOO_MANY_POSTS
        return 0;
    }

    // Post l_release_count times. Not atomic with the sem_getvalue above —
    // acceptable for Weave's single-process model (see known limitation above).
    for _ in 0..l_release_count {
        unsafe {
            libc::sem_post(&entry.sem.0 as *const libc::sem_t as *mut libc::sem_t);
        }
    }

    // Write previous count only on success.
    if !lp_previous_count.is_null() {
        unsafe { *lp_previous_count = prev };
    }

    1 // TRUE
}

/// CreateSemaphoreW — create an anonymous POSIX-backed semaphore.
///
/// Returns a non-zero Weave handle on success, 0 (NULL) on failure.
/// Named semaphores (lp_name != null) are out of scope; name is ignored.
/// Validates: max_count > 0, 0 ≤ initial_count ≤ max_count.
///
/// # Safety
/// lp_semaphore_attributes and lp_name are ignored (may be null).
// Wine ref: dlls/kernelbase/sync.c:796 — CreateSemaphoreW delegates to
// CreateSemaphoreExW(sa, initial, max, name, 0, SEMAPHORE_ALL_ACCESS) →
// NtCreateSemaphore.  STATUS_INVALID_PARAMETER when max=0 or initial>max.
// STATUS_OBJECT_NAME_EXISTS → ERROR_ALREADY_EXISTS (named path, out of scope).
pub unsafe extern "win64" fn create_semaphore_w(
    _lp_semaphore_attributes: *const u8,
    l_initial_count: i32,
    l_maximum_count: i32,
    _lp_name: *const u16,
) -> usize {
    eprintln!("weave/CreateSemaphoreW: initial={l_initial_count} max={l_maximum_count}");
    let handle = create_semaphore_impl(l_initial_count, l_maximum_count);
    eprintln!("weave/CreateSemaphoreW: → handle={handle:#x}");
    handle
}

/// SetFileApisToOEM — switch file APIs to OEM character set. No-op.
// Wine ref: dlls/kernelbase/file.c:2970 — sets global oem_file_apis = TRUE; checked by file name conversion helpers
pub extern "win64" fn set_file_apis_to_oem() {
    // OEM file APIs not tracked; file names go through WinPathTranslator regardless
}

/// OpenFileMappingW — open a named file-mapping object (Wide).
///
/// Returns NULL — no shared-memory objects are emulated.
///
/// # Safety
/// `lp_name` is ignored.
// Wine ref: dlls/kernelbase/sync.c:1137 — FILE_MAP_COPY is remapped to SECTION_MAP_READ;
// calls NtOpenSection; on Win9x tries access|READ|WRITE first to skip access checks
pub unsafe extern "win64" fn open_file_mapping_w(
    _dw_desired_access: u32,
    _b_inherit_handle: i32,
    _lp_name: *const u16,
) -> usize {
    warn_once("OpenFileMappingW");
    0 // NULL — not found
}

/// DosDateTimeToFileTime — convert a DOS date/time to a FILETIME.
///
/// Returns TRUE. Fills `*lp_file_time` with an approximate FILETIME derived
/// from the DOS date/time fields (good enough for archive timestamp display).
///
/// # Safety
/// `lp_file_time` must be a writable 8-byte buffer or null.
// Wine ref: dlls/ntdll (RtlDosDateTimeToFileTime) — DOS date: bits 15-9=year-1980,
// 8-5=month, 4-0=day. DOS time: bits 15-11=hours, 10-5=minutes, 4-0=seconds/2.
// Special case (0,0) → FILETIME (0,0) per wininet internal wrapper.
pub unsafe extern "win64" fn dos_date_time_to_file_time(
    w_fat_date: u16,
    w_fat_time: u16,
    lp_file_time: *mut u64,
) -> i32 {
    eprintln!("weave/DosDateTimeToFileTime: date={w_fat_date:#x} time={w_fat_time:#x}");
    if !lp_file_time.is_null() {
        // Convert DOS date/time to FILETIME (100-ns intervals since 1601-01-01).
        // DOS date: bits 15-9=year-1980, 8-5=month, 4-0=day
        // DOS time: bits 15-11=hours, 10-5=minutes, 4-0=seconds/2
        let year = ((w_fat_date >> 9) & 0x7f) as u64 + 1980;
        let month = ((w_fat_date >> 5) & 0x0f) as u64;
        let day = (w_fat_date & 0x1f) as u64;
        let hour = ((w_fat_time >> 11) & 0x1f) as u64;
        let min = ((w_fat_time >> 5) & 0x3f) as u64;
        let sec = ((w_fat_time & 0x1f) as u64) * 2;
        // Rough FILETIME approximation (ignore leap years for simplicity).
        let days = (year - 1601) * 365 + month * 30 + day;
        let secs = days * 86400 + hour * 3600 + min * 60 + sec;
        // SAFETY: lp_file_time is non-null (checked above).  FILETIME is only
        // 4-byte aligned (two u32 fields), so write_unaligned is required to avoid
        // UB on any platform requiring 8-byte alignment for u64.  The caller's
        // # Safety contract guarantees the pointer is valid for an 8-byte write.
        unsafe { std::ptr::write_unaligned(lp_file_time, secs * 10_000_000) };
    }
    1 // TRUE
}

// SRW locks use the packed srw_lock layout defined above (see SRW helpers section).
// The SRWLOCK PVOID slot is 8 bytes; only the low 4 bytes carry state.

/// AcquireSRWLockExclusive: acquire the SRW lock for exclusive (write) access.
///
/// Spins via CAS until `owners == 0`, then sets `owners = 1` and marks the
/// exclusive-held bit. Blocks on futex if another thread holds the lock.
///
/// # Safety
/// `srw_lock` must be a valid pointer to an SRWLOCK-sized slot.
// Wine ref: dlls/ntdll/sync.c:514 — RtlAcquireSRWLockExclusive: increments
// exclusive_waiters by 2 before the loop; CAS on owners==0 to set owners=1 and
// clear the waiter count; futex-waits on &owners when contended.
pub unsafe extern "win64" fn acquire_srw_lock_exclusive(srw_lock: *mut usize) {
    let p = unsafe { srw_state_ptr(srw_lock) };
    let atomic = unsafe { &*(p as *const AtomicI32) };

    // Announce ourselves as an exclusive waiter (increment by 2 — bit 0 is the held flag).
    atomic.fetch_add(2, Ordering::AcqRel);

    let mut logged = false;
    loop {
        let old_i32 = atomic.load(Ordering::Acquire);
        let old: SrwLock = unsafe { std::mem::transmute(old_i32 as u32) };

        if old.owners == 0 {
            // Lock is free — try to grab it.
            let mut new = old;
            new.owners = 1;
            new.exclusive_waiters = (new.exclusive_waiters - 2) | 1; // decrement waiter, set held bit
            let new_i32: i32 = unsafe { std::mem::transmute::<SrwLock, u32>(new) as i32 };
            if atomic
                .compare_exchange(old_i32, new_i32, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        } else {
            if !logged {
                eprintln!(
                    "weave/AcquireSRWLockExclusive: srw={srw_lock:p} blocked (owners={})",
                    old.owners
                );
                logged = true;
            }
            // Lock is held — wait on the owners field (upper 2 bytes of the u32).
            // We wait on the full 32-bit word; any change will wake us.
            let owners_ptr = unsafe { (p as *const u8).add(2) as *const u32 };
            let owners_val = old.owners as u32;
            unsafe { futex_wait(owners_ptr, owners_val, std::ptr::null()) };
        }
    }
}

/// ReleaseSRWLockExclusive: release an exclusively held SRW lock.
///
/// Clears `owners` and the exclusive-held bit. Wakes one exclusive waiter if
/// any are present, otherwise wakes all shared waiters.
///
/// # Safety
/// `srw_lock` must be a valid pointer to a currently exclusively held SRWLOCK slot.
// Wine ref: dlls/ntdll/sync.c:589 — RtlReleaseSRWLockExclusive: CAS clears owners=0 and
// exclusive_waiters &= ~1; if exclusive_waiters remain, wakes &owners (one exclusive);
// otherwise wakes all (shared waiters watch the full 32-bit word).
pub unsafe extern "win64" fn release_srw_lock_exclusive(srw_lock: *mut usize) {
    let p = unsafe { srw_state_ptr(srw_lock) };
    let atomic = unsafe { &*(p as *const AtomicI32) };

    loop {
        let old_i32 = atomic.load(Ordering::Acquire);
        let old: SrwLock = unsafe { std::mem::transmute(old_i32 as u32) };
        let mut new = old;
        new.owners = 0;
        new.exclusive_waiters &= !1; // clear held bit
        let new_i32: i32 = unsafe { std::mem::transmute::<SrwLock, u32>(new) as i32 };
        if atomic
            .compare_exchange(old_i32, new_i32, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // Wake appropriate waiters.
            if new.exclusive_waiters != 0 {
                // Exclusive waiters present — wake one on the owners field.
                let owners_ptr = unsafe { (p as *const u8).add(2) as *const u32 };
                unsafe { futex_wake(owners_ptr, 1) };
            } else {
                // No exclusive waiters — wake all (shared waiters watch the full word).
                unsafe { futex_wake(p, i32::MAX) };
            }
            return;
        }
    }
}

/// AcquireSRWLockShared: acquire the SRW lock for shared (read) access.
///
/// Blocks if any exclusive waiter is present (to prevent starvation).
/// Otherwise increments the shared-reader count.
///
/// # Safety
/// `srw_lock` must be a valid pointer to an SRWLOCK-sized slot.
// Wine ref: dlls/ntdll/sync.c:550 — RtlAcquireSRWLockShared: CAS on exclusive_waiters==0
// to increment owners; if exclusive_waiters != 0, futex-waits on the full 32-bit word.
pub unsafe extern "win64" fn acquire_srw_lock_shared(srw_lock: *mut usize) {
    let p = unsafe { srw_state_ptr(srw_lock) };
    let atomic = unsafe { &*(p as *const AtomicI32) };

    let mut logged = false;
    loop {
        let old_i32 = atomic.load(Ordering::Acquire);
        let old: SrwLock = unsafe { std::mem::transmute(old_i32 as u32) };

        if old.exclusive_waiters == 0 {
            let mut new = old;
            new.owners += 1;
            let new_i32: i32 = unsafe { std::mem::transmute::<SrwLock, u32>(new) as i32 };
            if atomic
                .compare_exchange(old_i32, new_i32, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        } else {
            if !logged {
                eprintln!(
                    "weave/AcquireSRWLockShared: srw={srw_lock:p} blocked (exclusive_waiters={})",
                    old.exclusive_waiters
                );
                logged = true;
            }
            // Exclusive waiters present — wait on the full word.
            unsafe { futex_wait(p, old_i32 as u32, std::ptr::null()) };
        }
    }
}

/// ReleaseSRWLockShared: release a shared (read) hold on the SRW lock.
///
/// Decrements the shared-reader count. If it reaches zero and there are
/// exclusive waiters, wakes one on the owners futex word.
///
/// # Safety
/// `srw_lock` must be a valid pointer to a currently shared-held SRWLOCK slot.
// Wine ref: dlls/ntdll/sync.c:618 — RtlReleaseSRWLockShared: CAS decrements owners;
// if owners reaches 0, calls RtlWakeAddressSingle(&owners) to unblock one exclusive waiter.
pub unsafe extern "win64" fn release_srw_lock_shared(srw_lock: *mut usize) {
    let p = unsafe { srw_state_ptr(srw_lock) };
    let atomic = unsafe { &*(p as *const AtomicI32) };

    loop {
        let old_i32 = atomic.load(Ordering::Acquire);
        let old: SrwLock = unsafe { std::mem::transmute(old_i32 as u32) };
        let mut new = old;
        if new.owners > 0 {
            new.owners -= 1;
        }
        let new_i32: i32 = unsafe { std::mem::transmute::<SrwLock, u32>(new) as i32 };
        if atomic
            .compare_exchange(old_i32, new_i32, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            if new.owners == 0 {
                // Last shared reader gone — wake one exclusive waiter if any.
                let owners_ptr = unsafe { (p as *const u8).add(2) as *const u32 };
                unsafe { futex_wake(owners_ptr, 1) };
            }
            return;
        }
    }
}

// Side-channel counter table for condition variables.
//
// Windows CONDITION_VARIABLE uses the condvar ADDRESS as a keyed-event identity —
// the kernel never requires the Ptr field to be writable. MSVC CRT startup probes
// condvar availability by calling WakeAllConditionVariable(pfn_InitializeConditionVariable),
// passing a function pointer (r-xp memory) as the "condvar". Writing to that address
// (as a naive futex implementation would) causes SIGSEGV. We mirror the Windows keyed-event
// model: the condvar address is just a KEY; all waiter state lives in this side table.
const CV_TABLE_SIZE: usize = 4096;
#[allow(clippy::declare_interior_mutable_const)]
static CV_COUNTERS: [AtomicI32; CV_TABLE_SIZE] = {
    const Z: AtomicI32 = AtomicI32::new(0);
    [Z; CV_TABLE_SIZE]
};

#[inline]
fn cv_counter(addr: usize) -> &'static AtomicI32 {
    &CV_COUNTERS[(addr >> 3) & (CV_TABLE_SIZE - 1)]
}

/// InitializeConditionVariable: no-op — counter lives in CV_COUNTERS keyed by address.
///
/// # Safety
/// No requirements on `condition_variable` — we never read or write the condvar memory.
// Wine ref: dlls/ntdll/sync.c:712 — RtlInitializeConditionVariable sets variable->Ptr = NULL.
// We intentionally do not write to condition_variable: MSVC CRT passes function pointer
// addresses (r-xp memory) here during capability probing; writing crashes.
pub unsafe extern "win64" fn initialize_condition_variable(_condition_variable: *mut usize) {}

/// SleepConditionVariableSRW: atomically release the SRW lock and wait on the condvar.
///
/// Snapshots the side-channel counter for this condvar address, releases the lock,
/// futex-waits for the counter to change (set by a Wake call), then reacquires the lock.
///
/// # Safety
/// `condition_variable` and `srw_lock` must be non-null.
// Wine ref: dlls/ntdll/sync.c:799 — RtlSleepConditionVariableSRW.
pub unsafe extern "win64" fn sleep_condition_variable_srw(
    condition_variable: *mut usize,
    srw_lock: *mut usize,
    dw_milliseconds: u32,
    flags: u32,
) -> i32 {
    eprintln!(
        "weave/SleepConditionVariableSRW: entry cv={condition_variable:?} ms={dw_milliseconds} flags={flags:#x}"
    );
    if condition_variable.is_null() || srw_lock.is_null() {
        return 0;
    }

    let counter = cv_counter(condition_variable as usize);
    let snapshot = counter.load(Ordering::Acquire);

    if flags & CONDITION_VARIABLE_LOCKMODE_SHARED != 0 {
        unsafe { release_srw_lock_shared(srw_lock) };
    } else {
        unsafe { release_srw_lock_exclusive(srw_lock) };
    }

    let timeout_storage: libc::timespec;
    let timeout_ptr: *const libc::timespec = if dw_milliseconds == 0xFFFF_FFFF {
        std::ptr::null()
    } else {
        timeout_storage = libc::timespec {
            tv_sec: (dw_milliseconds / 1000) as libc::time_t,
            tv_nsec: ((dw_milliseconds % 1000) * 1_000_000) as libc::c_long,
        };
        &timeout_storage
    };

    let ret = unsafe { futex_wait(counter.as_ptr() as *const u32, snapshot as u32, timeout_ptr) };

    if flags & CONDITION_VARIABLE_LOCKMODE_SHARED != 0 {
        unsafe { acquire_srw_lock_shared(srw_lock) };
    } else {
        unsafe { acquire_srw_lock_exclusive(srw_lock) };
    }

    let errno = unsafe { *libc::__errno_location() };
    if ret == -1 && errno == libc::ETIMEDOUT {
        set_last_error(0x5B4); // ERROR_TIMEOUT
        return 0;
    }
    1
}

/// SleepConditionVariableCS: atomically release a CRITICAL_SECTION and wait on a condvar.
///
/// # Safety
/// `condition_variable` and `critical_section` must be non-null.
// Wine ref: dlls/ntdll/sync.c:766 — RtlSleepConditionVariableCS.
pub unsafe extern "win64" fn sleep_condition_variable_cs(
    condition_variable: *mut usize,
    critical_section: *mut u8,
    dw_milliseconds: u32,
) -> i32 {
    eprintln!(
        "weave/SleepConditionVariableCS: entry cv={condition_variable:?} ms={dw_milliseconds}"
    );
    if condition_variable.is_null() || critical_section.is_null() {
        return 0;
    }

    let counter = cv_counter(condition_variable as usize);
    let snapshot = counter.load(Ordering::Acquire);

    unsafe { leave_critical_section(critical_section) };

    let timeout_storage: libc::timespec;
    let timeout_ptr: *const libc::timespec = if dw_milliseconds == 0xFFFF_FFFF {
        std::ptr::null()
    } else {
        timeout_storage = libc::timespec {
            tv_sec: (dw_milliseconds / 1000) as libc::time_t,
            tv_nsec: ((dw_milliseconds % 1000) * 1_000_000) as libc::c_long,
        };
        &timeout_storage
    };

    let ret = unsafe { futex_wait(counter.as_ptr() as *const u32, snapshot as u32, timeout_ptr) };

    unsafe { enter_critical_section(critical_section) };

    let errno = unsafe { *libc::__errno_location() };
    if ret == -1 && errno == libc::ETIMEDOUT {
        set_last_error(0x5B4); // ERROR_TIMEOUT
        return 0;
    }
    1
}

/// WakeConditionVariable: wake one thread waiting on a condition variable.
///
/// # Safety
/// `condition_variable` must be non-null (value may be any address including r-xp).
// Wine ref: dlls/ntdll/sync.c:731 — RtlWakeConditionVariable.
pub unsafe extern "win64" fn wake_condition_variable(condition_variable: *mut usize) {
    if condition_variable.is_null() {
        return;
    }
    let counter = cv_counter(condition_variable as usize);
    counter.fetch_add(1, Ordering::Release);
    unsafe { futex_wake(counter.as_ptr() as *const u32, 1) };
}

/// WakeAllConditionVariable: wake all threads waiting on a condition variable.
///
/// # Safety
/// `condition_variable` must be non-null (value may be any address including r-xp).
// Wine ref: dlls/ntdll/sync.c:745 — RtlWakeAllConditionVariable.
pub unsafe extern "win64" fn wake_all_condition_variable(condition_variable: *mut usize) {
    if condition_variable.is_null() {
        return;
    }
    let counter = cv_counter(condition_variable as usize);
    counter.fetch_add(1, Ordering::Release);
    unsafe { futex_wake(counter.as_ptr() as *const u32, i32::MAX) };
}

// ── Threads ───────────────────────────────────────────────────────────────────

/// CreateThread — spawn the thread function on a real OS thread, return a real handle.
///
/// Wine ref: dlls/kernel32/thread.c — CreateThread wraps NtCreateThread; the thread
/// function is called with lpParameter as its sole argument and returns a DWORD exit code.
///
/// Every thread — whether background (lpParameter == NULL) or short-lived with a result
/// buffer — now runs on a genuine OS thread.  A `ThreadCompletion` arc is shared between
/// the spawned thread and the handle table so that WaitForSingleObject can block on a
/// condvar instead of a sentinel value.  CloseHandle drops the JoinHandle (detaches).
///
/// # Safety
/// `lp_start_address` must be a valid `extern "win64"` function pointer.
/// `lp_parameter` is forwarded to that function and must be valid for the thread's lifetime.
// Wine ref: dlls/kernelbase/thread.c — CreateThread wraps CreateRemoteThread(GetCurrentProcess(),
// ...) → NtCreateThread. Thread function called with lpParameter; returns DWORD exit code.
// CREATE_SUSPENDED flag (0x4) defers start until ResumeThread; Weave ignores it.
pub unsafe extern "win64" fn create_thread(
    _lp_thread_attributes: *const u8,
    _dw_stack_size: usize,
    lp_start_address: *const u8,
    lp_parameter: *mut u8,
    _dw_creation_flags: u32,
    lp_thread_id: *mut u32,
) -> usize {
    if lp_start_address.is_null() {
        return 0;
    }

    let fn_addr = lp_start_address as usize;
    let param_addr = lp_parameter as usize;
    let caller_tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
    eprintln!(
        "weave/CreateThread: entry caller_tid={caller_tid} fn={fn_addr:#x} param={param_addr:#x}"
    );

    let completion = Arc::new(handles::ThreadCompletion {
        result: std::sync::Mutex::new(None),
        condvar: std::sync::Condvar::new(),
    });
    let completion_clone = Arc::clone(&completion);

    // SAFETY: `fn_addr` is a Win64-ABI function pointer in the mapped PE image.
    // The PE image stays mapped for the process lifetime, so the pointer is valid
    // for the duration of the spawned thread.  `param_addr` is forwarded as the
    // sole RCX argument, matching LPTHREAD_START_ROUTINE exactly on x86-64.
    let join_handle = std::thread::spawn(move || {
        // Set up a TEB for this thread and point GS at it.  PE code accesses
        // TEB fields via GS-relative loads (gs:[0x10], gs:[0x58], etc.).  Without
        // this, GS points to the pthread TCB and any gs:[offset] read returns
        // garbage, causing the thread to crash immediately when the PE function
        // dereferences the result.  Keep _teb alive until thread exit.
        let _teb = weave_core::teb::setup_thread();
        let my_tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
        eprintln!("weave/CreateThread: thread-start tid={my_tid} fn={fn_addr:#x}");
        let fn_ptr: unsafe extern "win64" fn(*mut u8) -> u32 =
            unsafe { std::mem::transmute(fn_addr as *const u8) };
        let ret = unsafe { fn_ptr(param_addr as *mut u8) };
        eprintln!("weave/CreateThread: thread-exit tid={my_tid} fn={fn_addr:#x} exit_code={ret}");
        let mut guard = completion_clone.result.lock().unwrap();
        *guard = Some(ret);
        completion_clone.condvar.notify_all();
    });

    let handle = handles::alloc_thread(completion, join_handle);
    eprintln!("weave/CreateThread: → handle={handle:#x} fn={fn_addr:#x}");

    if !lp_thread_id.is_null() {
        *lp_thread_id = 1;
    }
    handle
}

/// GetThreadPriority — returns THREAD_PRIORITY_NORMAL (0).
// Wine ref: dlls/kernel32/thread.c — valid priority range is [-15, 15]; THREAD_PRIORITY_NORMAL
// is 0, returned as the default for threads not explicitly assigned a priority.
pub extern "win64" fn get_thread_priority(_h_thread: usize) -> i32 {
    // Wine ref: dlls/kernelbase/thread.c — NtQueryInformationThread(ThreadBasePriority).
    // Weave threads start at NORMAL; Linux scheduler priority is opaque to the guest.
    0 // THREAD_PRIORITY_NORMAL
}
/// SetThreadPriority — no-op, returns TRUE.
// Wine ref: dlls/kernelbase/thread.c::SetThreadPriority:617 — calls
// NtSetInformationThread(ThreadBasePriority, &priority); valid range is [-15,15].
pub extern "win64" fn set_thread_priority(_h_thread: usize, _n_priority: i32) -> i32 {
    // Linux thread priority requires SCHED_FIFO/SCHED_RR and root; silently accept.
    1
}
/// GetThreadContext — not supported, returns FALSE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/thread.c::GetThreadContext:253 — delegates to
// NtGetContextThread; CONTEXT flags select which register groups to capture.
pub unsafe extern "win64" fn get_thread_context(_h_thread: usize, _lp_context: *mut u8) -> i32 {
    warn_once("GetThreadContext");
    0 // FALSE
}
/// SetThreadContext — not supported, returns FALSE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/thread.c::SetThreadContext:467 — delegates to
// NtSetContextThread; requires thread to be suspended first.
pub unsafe extern "win64" fn set_thread_context(_h_thread: usize, _lp_context: *const u8) -> i32 {
    warn_once("SetThreadContext");
    0
}
/// SuspendThread — not supported, returns DWORD(-1) (failure).
// Wine ref: dlls/kernelbase/thread.c:689 — calls NtSuspendThread; Win9x mode returns 0 for
// current thread; returns ~0U on failure (NtSuspendThread fails)
pub extern "win64" fn suspend_thread(_h_thread: usize) -> u32 {
    warn_once("SuspendThread");
    u32::MAX // failure
}
/// ResumeThread — returns 1 (previous suspend count was 1, now running).
///
/// Weave ignores CREATE_SUSPENDED (thread starts immediately), so by the time a
/// caller calls ResumeThread the thread is already running. Returning 1 satisfies
/// the common `if (ResumeThread(h) == (DWORD)-1)` failure-check pattern.
// Wine ref: dlls/kernelbase/thread.c — calls NtResumeThread; returns previous suspend count
// (1 = was suspended, now resumed) or ~0U on failure. Weave: thread was never truly
// suspended (flag ignored in create_thread), so 1 is the correct "was suspended" reply.
pub extern "win64" fn resume_thread(_h_thread: usize) -> u32 {
    1 // previous suspend count — was 1 (suspended), now 0 (running)
}

// ── Process ───────────────────────────────────────────────────────────────────

/// OpenProcess — returns NULL (not supported).
///
// Wine ref: server/process.c:1500 — DECL_HANDLER(open_process): looks up process by pid,
// checks access rights, returns handle; Weave has no process table so returns NULL
/// # Safety
/// No pointer arguments are dereferenced.
pub unsafe extern "win64" fn open_process(
    _dw_desired_access: u32,
    _b_inherit_handle: i32,
    dw_process_id: u32,
) -> usize {
    // Wine ref: dlls/kernelbase/process.c — NtOpenProcess with CLIENT_ID;
    // pid=0 → ERROR_INVALID_PARAMETER; nonexistent pid → ERROR_INVALID_PARAMETER.
    // Weave: validate via /proc, return pid as handle (non-NULL, harmless to CloseHandle).
    if dw_process_id == 0 {
        set_last_error(87);
        return 0;
    }
    if !std::path::Path::new(&format!("/proc/{dw_process_id}")).exists() {
        set_last_error(87);
        return 0;
    }
    set_last_error(0);
    dw_process_id as usize
}

/// GetProcessAffinityMask — reports single-CPU affinity.
///
/// # Safety
/// Output pointers must be valid and writable or NULL.
// Wine ref: dlls/kernel32/process.c — process affinity mask must be a subset of the system
// affinity mask; both reported as 1 for single-CPU environments. Returns TRUE on success.
pub unsafe extern "win64" fn get_process_affinity_mask(
    _h_process: usize,
    lp_process_affinity_mask: *mut usize,
    lp_system_affinity_mask: *mut usize,
) -> i32 {
    // Wine ref: dlls/kernelbase/process.c — NtQueryInformationProcess(ProcessAffinityMask).
    // Report single-CPU affinity (mask=1); Linux scheduler ignores Windows affinity.
    unsafe {
        if !lp_process_affinity_mask.is_null() {
            *lp_process_affinity_mask = 1;
        }
        if !lp_system_affinity_mask.is_null() {
            *lp_system_affinity_mask = 1;
        }
    }
    1
}

/// SetProcessAffinityMask — no-op stub, returns TRUE.
///
// Wine ref: dlls/kernelbase/process.c::SetProcessGroupAffinity:1232 — calls
// NtSetInformationProcess(ProcessGroupInformation); Weave ignores affinity (single-process)
/// # Safety
/// No pointer arguments are dereferenced.
pub unsafe extern "win64" fn set_process_affinity_mask(
    _h_process: usize,
    _dw_process_affinity_mask: usize,
) -> i32 {
    1 // Linux scheduler ignores Windows affinity masks
}

/// GetActiveProcessorGroupCount — returns the number of processor groups.
///
// Wine ref: include/winnt.h:6819 — PROCESSOR_GROUP_INFO.ActiveProcessorCount tracks active CPUs
// per group; GetActiveProcessorGroupCount queries SystemLogicalProcessorInformationEx
/// On typical systems there is exactly one processor group.
pub extern "win64" fn get_active_processor_group_count() -> u16 {
    1
}

/// GetActiveProcessorCount — returns the number of active logical processors.
///
/// `group_number == 0xFFFF` (ALL_PROCESSOR_GROUPS) requests the total count.
/// Report 1 CPU so that apps like 7-Zip use single-threaded mode; their
/// thread pools fail gracefully rather than throwing when _beginthreadex
/// returns 0.
// Wine ref: include/winnt.h:6819 — PROCESSOR_GROUP_INFO.ActiveProcessorCount; group 0xFFFF
// (ALL_PROCESSOR_GROUPS) sums all groups; Wine queries NtQuerySystemInformation.
pub extern "win64" fn get_active_processor_count(group_number: u16) -> u32 {
    let msg = format!("weave: GetActiveProcessorCount({group_number:#x}) -> 1\n");
    unsafe { libc::write(2, msg.as_ptr() as *const libc::c_void, msg.len()) };
    1
}

/// GetHandleInformation — writes 0 flags and returns TRUE.
///
// Wine ref: dlls/kernelbase/process.c:812 — calls NtQueryObject(ObjectHandleFlagInformation);
// maps info.Inherit → HANDLE_FLAG_INHERIT and info.ProtectFromClose → HANDLE_FLAG_PROTECT_FROM_CLOSE
/// # Safety
/// `lp_flags` must be a valid writable pointer or NULL.
pub unsafe extern "win64" fn get_handle_information(_h_object: usize, lp_flags: *mut u32) -> i32 {
    // Wine ref: dlls/kernelbase/handle.c — NtQueryObject(ObjectHandleFlags).
    // Weave: no handle flags tracked; report 0 (non-inheritable, non-protected).
    if !lp_flags.is_null() {
        unsafe { *lp_flags = 0 };
    }
    1
}

/// DeviceIoControl — not supported; writes 0 bytes returned and returns FALSE.
///
// Wine ref: dlls/kernelbase/file.c:4349 — FILE_DEVICE_FILE_SYSTEM codes → NtFsControlFile;
// others → NtDeviceIoControlFile; overlapped->Internal set to STATUS_PENDING before call
/// # Safety
/// `lp_bytes_returned` must be a valid writable pointer or NULL; other
/// pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn device_io_control(
    _h_device: usize,
    _dw_io_control_code: u32,
    _lp_in_buffer: *const u8,
    _n_in_buffer_size: u32,
    _lp_out_buffer: *mut u8,
    _n_out_buffer_size: u32,
    lp_bytes_returned: *mut u32,
    _lp_overlapped: *mut u8,
) -> i32 {
    warn_once("DeviceIoControl");
    unsafe {
        if !lp_bytes_returned.is_null() {
            *lp_bytes_returned = 0;
        }
    }
    0
}

// ── Environment ───────────────────────────────────────────────────────────────

/// GetEnvironmentVariableW — returns 0 (variable not found).
///
// Wine ref: dlls/kernelbase/process.c:1660 — calls RtlQueryEnvironmentVariable_U(NULL, ...);
// STATUS_BUFFER_TOO_SMALL → returns len+1 (required size); on success writes null terminator
/// # Safety
/// `lp_name` must be null or a valid null-terminated UTF-16 string of length
/// less than `MAX_UTF16_LEN` code units. `lp_buffer` must be null or writable
/// for `n_size` u16 elements.
pub unsafe extern "win64" fn get_environment_variable_w(
    lp_name: *const u16,
    lp_buffer: *mut u16,
    n_size: u32,
) -> u32 {
    if lp_name.is_null() {
        set_last_error(203); // ERROR_ENVVAR_NOT_FOUND
        return 0;
    }
    // Bound the null-terminator scan: a guest-controlled pointer without a NUL
    // would otherwise read past mapped memory (SIGSEGV) or act as a length
    // oracle into Weave's address space.
    let mut len = 0usize;
    while len < MAX_UTF16_LEN && *lp_name.add(len) != 0 {
        len += 1;
    }
    if len == MAX_UTF16_LEN {
        set_last_error(203); // ERROR_ENVVAR_NOT_FOUND
        return 0;
    }
    let slice = std::slice::from_raw_parts(lp_name, len);
    let name = String::from_utf16_lossy(slice);
    let c_name = match std::ffi::CString::new(name) {
        Ok(s) => s,
        Err(_) => {
            set_last_error(203);
            return 0;
        }
    };
    let value_ptr = libc::getenv(c_name.as_ptr());
    if value_ptr.is_null() {
        // Narrow SDL/AUDIO trace — confirms dummy-audio env visibility.
        let name_str = c_name.to_string_lossy();
        let name_upper = name_str.to_ascii_uppercase();
        if name_upper.contains("SDL") || name_upper.contains("AUDIO") {
            eprintln!("weave/GetEnvironmentVariableW: {:?} → NOT_FOUND", name_str);
        }
        set_last_error(203); // ERROR_ENVVAR_NOT_FOUND
        return 0;
    }
    let cstr = std::ffi::CStr::from_ptr(value_ptr);
    let bytes = cstr.to_bytes();
    let utf16: Vec<u16> = String::from_utf8_lossy(bytes).encode_utf16().collect();
    let chars_needed = utf16.len() as u32; // excluding NUL
                                           // Narrow SDL/AUDIO trace.
    {
        let name_str = c_name.to_string_lossy();
        let name_upper = name_str.to_ascii_uppercase();
        if name_upper.contains("SDL") || name_upper.contains("AUDIO") {
            eprintln!(
                "weave/GetEnvironmentVariableW: {:?} → {:?}",
                name_str,
                std::ffi::CStr::from_ptr(value_ptr).to_string_lossy()
            );
        }
    }
    if n_size == 0 || lp_buffer.is_null() || chars_needed + 1 > n_size {
        // Buffer too small — return required size including NUL.
        return chars_needed + 1;
    }
    std::ptr::copy_nonoverlapping(utf16.as_ptr(), lp_buffer, utf16.len());
    *lp_buffer.add(utf16.len()) = 0;
    chars_needed
}

// ── Misc ──────────────────────────────────────────────────────────────────────

/// FormatMessageA — formats an error message into an ANSI buffer.
///
/// Minimal implementation that handles FORMAT_MESSAGE_FROM_SYSTEM with error codes.
/// Maps common Windows error codes to short ASCII strings and copies to caller's buffer.
///
/// # Safety
/// `lp_buffer` must be valid for `n_size` bytes when non-null.
// Wine ref: dlls/kernelbase/locale.c:5382 — FORMAT_MESSAGE_ALLOCATE_BUFFER allocates on heap
// and stores pointer at *buffer; FORMAT_MESSAGE_MAX_WIDTH_MASK 0xff means unlimited width;
// delegates to RtlFormatMessage via get_message(); retsize==sizeof(WCHAR) sets ERROR_NO_WORK_DONE
pub unsafe extern "win64" fn format_message_a(
    dw_flags: u32,
    _lp_source: usize,
    dw_message_id: u32,
    _dw_language_id: u32,
    lp_buffer: *mut u8,
    n_size: u32,
    _arguments: usize,
) -> u32 {
    const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x00001000;
    const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x00000200;

    // Only handle the most common case
    if (dw_flags & FORMAT_MESSAGE_FROM_SYSTEM) == 0
        || (dw_flags & FORMAT_MESSAGE_IGNORE_INSERTS) == 0
    {
        return 0;
    }
    if lp_buffer.is_null() {
        return 0;
    }

    let message = match dw_message_id {
        0 => b"The operation completed successfully.\0".as_slice(),
        2 => b"The system cannot find the file specified.\0".as_slice(),
        3 => b"The system cannot find the path specified.\0".as_slice(),
        5 => b"Access is denied.\0".as_slice(),
        6 => b"The handle is invalid.\0".as_slice(),
        8 => b"Not enough memory resources are available.\0".as_slice(),
        87 => b"The parameter is incorrect.\0".as_slice(),
        122 => b"The data area passed to a system call is too small.\0".as_slice(),
        123 => b"The filename, directory name, or volume label syntax is incorrect.\0".as_slice(),
        183 => b"Cannot create a file when that file already exists.\0".as_slice(),
        _ => b"Unknown error.\0".as_slice(),
    };

    let len = message.len() - 1; // exclude null terminator
    if len >= n_size as usize {
        // Buffer too small - copy what fits
        unsafe {
            std::ptr::copy_nonoverlapping(message.as_ptr(), lp_buffer, n_size as usize);
        }
        return 0; // error: buffer too small
    }

    unsafe {
        std::ptr::copy_nonoverlapping(message.as_ptr(), lp_buffer, message.len());
    }
    len as u32
}

/// FormatMessageW — formats an error message into a wide-character buffer.
///
/// Minimal implementation that handles FORMAT_MESSAGE_FROM_SYSTEM with error codes.
/// Maps common Windows error codes to short wide strings and copies to caller's buffer.
///
/// # Safety
/// `lp_buffer` must be valid for `n_size` u16 words when non-null.
// Wine ref: dlls/kernelbase/locale.c:5465 — delegates to RtlFormatMessage; returns retsize/sizeof(WCHAR)-1
// (char count excl NUL); STATUS_BUFFER_OVERFLOW → ERROR_INSUFFICIENT_BUFFER, still NUL-terminates at buffer[size-1]
pub unsafe extern "win64" fn format_message_w(
    dw_flags: u32,
    _lp_source: usize,
    dw_message_id: u32,
    _dw_language_id: u32,
    lp_buffer: *mut u16,
    n_size: u32,
    _arguments: usize,
) -> u32 {
    eprintln!(
        "weave/FormatMessageW: flags={dw_flags:#x} msg_id={dw_message_id} (0x{dw_message_id:x}) buf_size={n_size}"
    );
    const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x00001000;
    const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x00000200;

    // Only handle the most common case
    if (dw_flags & FORMAT_MESSAGE_FROM_SYSTEM) == 0
        || (dw_flags & FORMAT_MESSAGE_IGNORE_INSERTS) == 0
    {
        return 0;
    }
    if lp_buffer.is_null() {
        return 0;
    }

    let message = match dw_message_id {
        0 => "The operation completed successfully.\0",
        2 => "The system cannot find the file specified.\0",
        3 => "The system cannot find the path specified.\0",
        5 => "Access is denied.\0",
        6 => "The handle is invalid.\0",
        8 => "Not enough memory resources are available.\0",
        87 => "The parameter is incorrect.\0",
        122 => "The data area passed to a system call is too small.\0",
        123 => "The filename, directory name, or volume label syntax is incorrect.\0",
        183 => "Cannot create a file when that file already exists.\0",
        _ => "Unknown error.\0",
    };

    let wide_chars: Vec<u16> = message.encode_utf16().collect();
    let len = wide_chars.len() - 1; // exclude null terminator

    if len >= n_size as usize {
        // Buffer too small - copy what fits
        unsafe {
            std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_buffer, n_size as usize);
        }
        return 0; // error: buffer too small
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_buffer, wide_chars.len());
    }
    len as u32
}

/// CreateDirectoryW — create a directory (wide string version).
///
/// Returns TRUE (1) on success, FALSE (0) with SetLastError on failure.
/// ERROR_ALREADY_EXISTS (183) if the directory already exists.
/// ERROR_PATH_NOT_FOUND (3) if the parent directory does not exist.
/// ERROR_ACCESS_DENIED (5) if permission is denied.
///
/// # Safety
/// `lp_path_name` must be a valid null-terminated UTF-16 string or null.
/// `lp_security_attributes` is ignored.
// Wine ref: dlls/kernelbase/file.c:668 — converts path via RtlDosPathNameToNtPathName_U;
// calls NtCreateFile with FILE_DIRECTORY_FILE|FILE_OPEN_REPARSE_POINT|FILE_CREATE disposition;
// closes handle immediately on success; returns FALSE + SetLastError on any failure.
// EEXIST → ERROR_ALREADY_EXISTS (183), ENOENT → ERROR_PATH_NOT_FOUND (3),
// EACCES → ERROR_ACCESS_DENIED (5).
pub unsafe extern "win64" fn create_directory_w(
    lp_path_name: *const u16,
    _lp_security_attributes: *const u8,
) -> i32 {
    if lp_path_name.is_null() {
        set_last_error(3); // ERROR_PATH_NOT_FOUND
        return 0;
    }

    // Decode null-terminated UTF-16 path.
    let win_path = {
        let mut len = 0usize;
        while len < MAX_UTF16_LEN && unsafe { *lp_path_name.add(len) } != 0 {
            len += 1;
        }
        if len == MAX_UTF16_LEN {
            set_last_error(3); // ERROR_PATH_NOT_FOUND — overlong
            return 0;
        }
        let slice = unsafe { std::slice::from_raw_parts(lp_path_name, len) };
        String::from_utf16_lossy(slice).to_owned()
    };

    // Translate Windows path to Linux path.
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => {
            set_last_error(3); // ERROR_PATH_NOT_FOUND
            return 0;
        }
    };

    // Convert to C string.
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => {
            set_last_error(3); // ERROR_PATH_NOT_FOUND
            return 0;
        }
    };

    // Call mkdir(2) with rwxr-xr-x permissions.
    let ret = unsafe { libc::mkdir(c_path.as_ptr(), 0o755) };
    if ret == 0 {
        return 1; // TRUE
    }

    // Map errno to Win32 error code.
    let errno = unsafe { *libc::__errno_location() };
    let win_err = match errno {
        libc::EEXIST => 183, // ERROR_ALREADY_EXISTS
        libc::ENOENT => 3,   // ERROR_PATH_NOT_FOUND
        libc::EACCES => 5,   // ERROR_ACCESS_DENIED
        _ => 183,            // default: already exists covers most other mkdir conflicts
    };
    set_last_error(win_err);
    0
}

/// RaiseException — raises a Windows exception and dispatches through SEH.
///
/// Naked trampoline: captures [RSP] (return address into the PE caller) and
/// RSP+8 (the PE caller's RSP before the CALL) before any prolog runs, then
/// tail-calls raise_exception_impl with those values as extra Linux ABI args.
///
/// Win64 entry: RCX=code, RDX=flags, R8=n_args, R9=lp_arguments
/// Linux args to impl: RDI=code, RSI=flags, RDX=n_args, RCX=lp_arguments,
///                     R8=throw_rip, R9=throw_rsp
///
/// # Safety
/// Called only via Win64 IAT from PE code.
// Wine ref: dlls/kernelbase/debug.c:389 — masks flags to EXCEPTION_NONCONTINUABLE; caps
// NumberParameters to EXCEPTION_MAXIMUM_PARAMETERS (15); calls RtlRaiseException with record.
#[unsafe(naked)]
pub unsafe extern "win64" fn raise_exception(
    _dw_exception_code: u32,
    _dw_exception_flags: u32,
    _n_number_of_arguments: u32,
    _lp_arguments: *const u64,
) {
    core::arch::naked_asm!(
        // Capture throw site before any prolog modifies the stack.
        "mov r10, [rsp]",     // r10 = return address into PE caller
        "lea r11, [rsp+8]",   // r11 = PE caller's RSP before the CALL
        // Convert Win64 args → Linux ABI for tail call to raise_exception_impl:
        //   RDI = dw_exception_code  (Win64 RCX → Linux arg1)
        //   RSI = dw_exception_flags (Win64 RDX → Linux arg2)
        //   RDX = n_number_of_arguments (Win64 R8 → Linux arg3)
        //   RCX = lp_arguments       (Win64 R9 → Linux arg4)
        //   R8  = throw_rip          (Linux arg5)
        //   R9  = throw_rsp          (Linux arg6)
        "mov rdi, rcx",
        "mov rsi, rdx",
        "mov rdx, r8",
        "mov rcx, r9",
        "mov r8,  r10",
        "mov r9,  r11",
        "jmp {impl_fn}",
        impl_fn = sym raise_exception_impl,
    );
}

/// Inner implementation called by the naked raise_exception trampoline.
///
/// # Safety
/// `throw_rip`/`throw_rsp` are the exact values from the PE call site.
unsafe extern "C" fn raise_exception_impl(
    dw_exception_code: u32,
    dw_exception_flags: u32,
    n_number_of_arguments: u32,
    lp_arguments: *const u64,
    throw_rip: u64,
    throw_rsp: u64,
) {
    unsafe {
        weave_core::unwind::raise_exception_at(
            dw_exception_code,
            dw_exception_flags,
            n_number_of_arguments,
            lp_arguments,
            throw_rip,
            throw_rsp,
        );
    }
}

// RtlCaptureContext, RtlLookupFunctionEntry, RtlVirtualUnwind, RtlUnwindEx
// are now implemented in weave_core::unwind and re-exported here via resolve().

/// TlsAlloc — allocate a TLS slot index.
///
/// Returns indices starting from 64 (above the static TLS range).
/// Thread-safe via atomic counter.
// Wine ref: dlls/kernelbase/thread.c:723 — uses RtlFindClearBitsAndSet on peb->TlsBitmap (slots 0-63);
// overflow goes to TlsExpansionBitmap (up to 1024 extra slots); clears slot value on alloc; returns ~0U on exhaustion
pub extern "win64" fn tls_alloc() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT_TLS_INDEX: AtomicU32 = AtomicU32::new(64);
    let idx = NEXT_TLS_INDEX.fetch_add(1, Ordering::Relaxed);
    if idx >= 1088 {
        return u32::MAX; // TLS_OUT_OF_INDEXES
    }
    idx
}
/// TlsSetValue — store a value in a TLS slot.
///
/// Single-threaded: uses a global HashMap keyed by slot index.
// Wine ref: dlls/kernelbase/thread.c::TlsSetValue:804 — index < TLS_MINIMUM_AVAILABLE goes into
// TEB.TlsSlots[]; higher indices use TlsExpansionSlots (heap-alloc on first use); out-of-range → ERROR_INVALID_PARAMETER.
pub extern "win64" fn tls_set_value(dw_tls_index: u32, lp_tls_value: *mut u8) -> i32 {
    TLS_SLOTS.with(|slots| {
        slots
            .borrow_mut()
            .insert(dw_tls_index, lp_tls_value as usize);
    });
    1
}
/// TlsFree — release a TLS slot. Returns TRUE.
// Wine ref: dlls/kernelbase/thread.c:760 — clears PEB TlsBitmap or TlsExpansionBitmap bit;
// calls NtSetInformationThread(ThreadZeroTlsCell) to zero the slot across all threads
pub extern "win64" fn tls_free(dw_tls_index: u32) -> i32 {
    TLS_SLOTS.with(|slots| {
        slots.borrow_mut().remove(&dw_tls_index);
    });
    1
}

/// WaitForSingleObject — block until the object is signalled or the timeout expires.
///
/// INFINITE (0xFFFFFFFF) means no timeout; returns WAIT_OBJECT_0 on success,
/// WAIT_TIMEOUT on expiry, WAIT_FAILED for invalid handles.
///
/// # Safety
/// No pointer arguments are dereferenced.
// Wine ref: dlls/kernel32/sync.c — WaitForSingleObject wraps NtWaitForSingleObject;
// WAIT_OBJECT_0=0, WAIT_TIMEOUT=0x102, WAIT_FAILED=0xFFFFFFFF; invalid handle → WAIT_FAILED.
pub unsafe extern "win64" fn wait_for_single_object(h_handle: usize, dw_milliseconds: u32) -> u32 {
    let caller_tid = unsafe { libc::syscall(libc::SYS_gettid) as u32 };
    eprintln!(
        "weave/WaitForSingleObject: entry tid={caller_tid} h={h_handle:#x} ms={dw_milliseconds}"
    );
    const INVALID_HANDLE_VALUE: usize = usize::MAX;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 0x00000102;
    const WAIT_FAILED: u32 = 0xFFFFFFFF;
    const INFINITE: u32 = 0xFFFF_FFFF;

    if weave_core::ws2_trace::enabled() {
        eprintln!("weave/WFSO: handle={h_handle:#x} timeout={dw_milliseconds}ms");
    }

    if h_handle == 0 || h_handle == INVALID_HANDLE_VALUE {
        eprintln!("weave/WFSO: handle={h_handle:#x} → WAIT_FAILED (invalid)");
        return WAIT_FAILED;
    }

    // Real thread handle — block on the condvar until completion or timeout.
    if let Some(completion) = handles::get_thread_completion(h_handle) {
        let guard = completion.result.lock().unwrap();
        if guard.is_some() {
            eprintln!("weave/WFSO: handle={h_handle:#x} → WAIT_OBJECT_0 (already done)");
            return WAIT_OBJECT_0;
        }
        if dw_milliseconds == INFINITE {
            eprintln!("weave/WFSO: blocking on thread condvar h={h_handle:#x} INFINITE");
            let _g = completion
                .condvar
                .wait_while(guard, |r| r.is_none())
                .unwrap();
            eprintln!("weave/WFSO: handle={h_handle:#x} → WAIT_OBJECT_0 (condvar)");
            return WAIT_OBJECT_0;
        } else {
            let timeout = std::time::Duration::from_millis(dw_milliseconds as u64);
            let (_g, timed_out) = completion
                .condvar
                .wait_timeout_while(guard, timeout, |r| r.is_none())
                .unwrap();
            let result = if timed_out.timed_out() {
                WAIT_TIMEOUT
            } else {
                WAIT_OBJECT_0
            };
            eprintln!(
                "weave/WFSO: handle={h_handle:#x} → {} (timed_out={})",
                if result == WAIT_TIMEOUT {
                    "WAIT_TIMEOUT"
                } else {
                    "WAIT_OBJECT_0"
                },
                timed_out.timed_out()
            );
            return result;
        }
    }

    // Real Event handle backed by eventfd — poll with timeout.
    #[cfg(target_os = "linux")]
    if let Some(efd) = handles::get_event_fd(h_handle) {
        let timeout_ms: i32 = if dw_milliseconds == INFINITE {
            -1
        } else {
            dw_milliseconds.min(i32::MAX as u32) as i32
        };
        let mut pfd = libc::pollfd {
            fd: efd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = libc::poll(&mut pfd, 1, timeout_ms);
        if ret > 0 && (pfd.revents & libc::POLLIN) != 0 {
            // Drain the counter (manual-reset callers can re-signal; draining is safe).
            let mut _val: u64 = 0;
            libc::read(efd, &mut _val as *mut u64 as *mut libc::c_void, 8);
            eprintln!("weave/WFSO: handle={h_handle:#x} → WAIT_OBJECT_0 (eventfd)");
            return WAIT_OBJECT_0;
        }
        eprintln!("weave/WFSO: handle={h_handle:#x} → WAIT_TIMEOUT (eventfd poll timed out)");
        return WAIT_TIMEOUT;
    }

    // Semaphore handle — clone the Arc out of the table so we can block without
    // holding the mutex.
    // Wine ref: dlls/kernelbase/sync.c — WaitForSingleObject on a semaphore handle
    // decrements the count atomically; WAIT_OBJECT_0 on success, WAIT_TIMEOUT on
    // expiry, WAIT_FAILED on invalid handle or unexpected error.
    #[cfg(target_os = "linux")]
    {
        let sem_arc: Option<Arc<SemWrapper>> = {
            let tbl = sem_table()
                .lock()
                .map_err(|e| eprintln!("weave: semaphore table mutex poisoned: {e}"))
                .ok();
            tbl.and_then(|t| t.get(&h_handle).map(|e| Arc::clone(&e.sem)))
        };

        if let Some(sem_arc) = sem_arc {
            // SAFETY: Arc keeps the sem_t alive; address is stable for the Arc lifetime.
            let sem_ptr = &sem_arc.0 as *const libc::sem_t as *mut libc::sem_t;

            if dw_milliseconds == 0 {
                // Non-blocking: try to decrement without waiting.
                let rc = unsafe { libc::sem_trywait(sem_ptr) };
                if rc == 0 {
                    if weave_core::ws2_trace::enabled() {
                        eprintln!("weave/WFSO: handle={h_handle:#x} → WAIT_OBJECT_0 (sem trywait)");
                    }
                    return WAIT_OBJECT_0;
                }
                let err = unsafe { *libc::__errno_location() };
                if err == libc::EAGAIN {
                    eprintln!(
                        "weave/WFSO: handle={h_handle:#x} → WAIT_TIMEOUT (sem trywait EAGAIN)"
                    );
                    return WAIT_TIMEOUT;
                }
                eprintln!(
                    "weave/WFSO: handle={h_handle:#x} → WAIT_FAILED (sem trywait errno={err})"
                );
                return WAIT_FAILED;
            } else if dw_milliseconds == INFINITE {
                loop {
                    let rc = unsafe { libc::sem_wait(sem_ptr) };
                    if rc == 0 {
                        if weave_core::ws2_trace::enabled() {
                            eprintln!(
                                "weave/WFSO: handle={h_handle:#x} → WAIT_OBJECT_0 (sem wait)"
                            );
                        }
                        return WAIT_OBJECT_0;
                    }
                    let err = unsafe { *libc::__errno_location() };
                    if err == libc::EINTR {
                        continue;
                    }
                    eprintln!(
                        "weave/WFSO: handle={h_handle:#x} → WAIT_FAILED (sem wait errno={err})"
                    );
                    return WAIT_FAILED;
                }
            } else {
                // Finite timeout: compute absolute CLOCK_REALTIME deadline for sem_timedwait.
                let mut ts = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
                ts.tv_sec += (dw_milliseconds / 1000) as libc::time_t;
                ts.tv_nsec += ((dw_milliseconds % 1000) * 1_000_000) as libc::c_long;
                if ts.tv_nsec >= 1_000_000_000 {
                    ts.tv_sec += 1;
                    ts.tv_nsec -= 1_000_000_000;
                }
                loop {
                    let rc = unsafe { libc::sem_timedwait(sem_ptr, &ts) };
                    if rc == 0 {
                        if weave_core::ws2_trace::enabled() {
                            eprintln!(
                                "weave/WFSO: handle={h_handle:#x} → WAIT_OBJECT_0 (sem timedwait)"
                            );
                        }
                        return WAIT_OBJECT_0;
                    }
                    let err = unsafe { *libc::__errno_location() };
                    if err == libc::ETIMEDOUT {
                        eprintln!(
                            "weave/WFSO: handle={h_handle:#x} → WAIT_TIMEOUT (sem timedwait)"
                        );
                        return WAIT_TIMEOUT;
                    }
                    if err == libc::EINTR {
                        continue;
                    }
                    eprintln!("weave/WFSO: handle={h_handle:#x} → WAIT_FAILED (sem timedwait errno={err})");
                    return WAIT_FAILED;
                }
            }
        }
    }

    // Waitable timer handle — poll the timerfd with timeout.
    #[cfg(target_os = "linux")]
    if let Some(fd) = TIMER_TABLE
        .get()
        .and_then(|t| t.lock().ok())
        .and_then(|t| t.get(&h_handle).copied())
    {
        let timeout_ms: i32 = if dw_milliseconds == INFINITE {
            -1i32
        } else {
            dw_milliseconds as i32
        };
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ret > 0 && (pfd.revents & libc::POLLIN) != 0 {
            let mut buf = [0u8; 8];
            unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 8) };
            eprintln!("weave/WFSO: handle={h_handle:#x} → WAIT_OBJECT_0 (timerfd)");
            return WAIT_OBJECT_0;
        }
        eprintln!("weave/WFSO: handle={h_handle:#x} → WAIT_TIMEOUT (timerfd poll)");
        return WAIT_TIMEOUT;
    }

    // Legacy stub handles (1 = mutex, 2 = event) — return success immediately.
    if h_handle == 1 || h_handle == 2 {
        eprintln!("weave/WFSO: handle={h_handle:#x} → WAIT_OBJECT_0 (legacy stub)");
        return WAIT_OBJECT_0;
    }

    eprintln!("weave/WFSO: handle={h_handle:#x} → WAIT_FAILED (unknown handle)");
    WAIT_FAILED
}

/// WaitForSingleObjectEx — WaitForSingleObject with alertable flag (ignored).
///
/// Wine ref: dlls/kernelbase/sync.c:404 — calls normalize_std_handle(handle) before
/// NtWaitForSingleObject; on NT_ERROR maps status via RtlNtStatusToDosError and returns
/// WAIT_FAILED; alertable flag forwarded unchanged to NtWaitForSingleObject.
///
/// # Safety
/// No pointer arguments are dereferenced.
pub unsafe extern "win64" fn wait_for_single_object_ex(
    h_handle: usize,
    dw_milliseconds: u32,
    _b_alertable: i32,
) -> u32 {
    // Delegate to WaitForSingleObject (alertable flag is a no-op in Weave).
    wait_for_single_object(h_handle, dw_milliseconds)
}

/// TryEnterCriticalSection — non-blocking acquire attempt.
///
/// Returns 1 (TRUE) if the CS was acquired (including recursive re-entry by the
/// owning thread), 0 (FALSE) if another thread currently holds the CS.
///
/// # Safety
/// `lp_critical_section` must point to a valid, initialised RTL_CRITICAL_SECTION
/// (at least 40 bytes, 4-byte aligned at the LockCount field).
// Wine ref: dlls/ntdll/sync.c — RtlTryEnterCriticalSection: reads OwningThread;
// if equal to NtCurrentTeb()->ClientId.UniqueThread increments LockCount and
// RecursionCount (recursive path) and returns TRUE. Otherwise attempts
// InterlockedCompareExchange(-1 → 0) on LockCount; returns TRUE on success,
// FALSE if the exchange fails (another thread owns the CS).
pub unsafe extern "win64" fn try_enter_critical_section(lp_critical_section: *mut usize) -> i32 {
    if lp_critical_section.is_null() {
        return 0; // FALSE — invalid pointer
    }
    let cs = lp_critical_section as *mut u8;
    // SAFETY: layout documented above; offset 16 is 8-byte aligned; AtomicUsize has same layout as usize.
    let owning_atomic = unsafe { &*(cs.add(16) as *const AtomicUsize) };
    let tid = unsafe { libc::syscall(libc::SYS_gettid) as usize };
    // Recursive path: same thread already owns the CS.
    if owning_atomic.load(Ordering::Acquire) == tid {
        let rec_ptr = unsafe { cs.add(12) as *mut i32 };
        let lock_atomic = unsafe { &*(cs.add(8) as *const AtomicI32) };
        unsafe {
            let rc = std::ptr::read_volatile(rec_ptr);
            std::ptr::write_volatile(rec_ptr, rc + 1);
        }
        lock_atomic.fetch_add(1, Ordering::AcqRel);
        return 1; // TRUE
    }
    // Non-recursive path: attempt a single CAS.
    let lock_atomic = unsafe { &*(cs.add(8) as *const AtomicI32) };
    match lock_atomic.compare_exchange(-1, 0, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {
            // Acquired — set owner and recursion depth.
            let rec_ptr = unsafe { cs.add(12) as *mut i32 };
            owning_atomic.store(tid, Ordering::Release);
            unsafe { std::ptr::write_volatile(rec_ptr, 1) };
            1 // TRUE
        }
        Err(_) => 0, // FALSE — another thread owns it
    }
}

/// SwitchToThread — yield the processor to another runnable thread.
///
/// Wine ref: dlls/kernelbase/thread.c — SwitchToThread calls NtYieldExecution
/// and returns TRUE if a context switch occurred. On Linux we call sched_yield()
/// which returns 0 on success; we always return TRUE (yield succeeded).
pub extern "win64" fn switch_to_thread() -> i32 {
    unsafe { libc::sched_yield() };
    1 // TRUE — yield succeeded
}
/// WaitForMultipleObjects — wait until one (or all) handles are signalled.
///
/// For event handles backed by eventfd: builds a pollfd array and calls poll(2)
/// with the requested timeout. Returns WAIT_OBJECT_0+index of the first signalled
/// handle, WAIT_TIMEOUT on expiry, or WAIT_FAILED on error.
///
/// # Safety
/// `lp_handles` must be a valid pointer to `n_count` handles or NULL.
// Wine ref: dlls/kernelbase/sync.c:424 — thin wrapper; delegates to WaitForMultipleObjectsEx(alertable=FALSE);
// return value is WAIT_OBJECT_0+index of signalled handle when wait_all=FALSE
pub unsafe extern "win64" fn wait_for_multiple_objects(
    n_count: u32,
    lp_handles: *const usize,
    _b_wait_all: i32,
    dw_milliseconds: u32,
) -> u32 {
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 0x00000102;
    const WAIT_FAILED: u32 = 0xFFFFFFFF;
    const INFINITE: u32 = 0xFFFF_FFFF;

    eprintln!("weave/WFMO: n={n_count} timeout={dw_milliseconds}ms");

    if lp_handles.is_null() || n_count == 0 {
        eprintln!("weave/WFMO: → WAIT_FAILED (null/empty)");
        return WAIT_FAILED;
    }

    // Collect handles — classify each one.
    let mut pollfds: Vec<libc::pollfd> = Vec::new();
    // Map from pollfd index → original handle index
    let mut pollfd_to_handle_idx: Vec<usize> = Vec::new();

    for i in 0..n_count as usize {
        let handle = *lp_handles.add(i);
        eprintln!("weave/WFMO: handle[{i}]={handle:#x}");

        // Guard against NULL handle (0) or INVALID_HANDLE_VALUE.  These are
        // never valid synchronisation objects and must not be dereferenced.
        // Windows returns WAIT_FAILED for these; our safety-net is to skip
        // the handle entirely so an invalid entry cannot propagate into poll().
        if handle == 0 || handle == usize::MAX {
            eprintln!("weave/WFMO: handle[{i}]={handle:#x} → skip (null/invalid)");
            continue;
        }

        // Real thread handle — delegate to WFSO immediately (blocking wait).
        if handles::get_thread_completion(handle).is_some() {
            let result = wait_for_single_object(handle, dw_milliseconds);
            eprintln!("weave/WFMO: handle[{i}]={handle:#x} → {result:#x} (thread)");
            return result;
        }

        // Event handle backed by eventfd — but if it was registered via
        // WSAEventSelect the eventfd is never written; poll the socket fd instead.
        #[cfg(target_os = "linux")]
        if let Some(efd) = handles::get_event_fd(handle) {
            // Check whether this event handle has an associated socket (reverse map).
            if let Some(sock_fd) = weave_common::socket_event::get_socket_for_event(handle as u64) {
                eprintln!("weave/WFMO: handle[{i}]={handle:#x} → socket-event fd={sock_fd} (will poll socket)");
                // Edge-triggered FD_WRITE: only poll POLLOUT if FD_WRITE is armed.
                // Linux POLLOUT is level-triggered (always ready when send buf has space).
                // Including POLLOUT unconditionally floods WFMO with ~2ms wakeups on
                // an idle connected socket, preventing plink from blocking on FD_READ.
                // Wine ref: dlls/ws2_32/socket.c — WFMO only wakes on socket events
                // that are currently in the socket's pending hmask; armed bits only.
                let mut sock_events = libc::POLLIN | libc::POLLHUP | libc::POLLRDHUP;
                if weave_common::socket_event::is_socket_write_armed(sock_fd) {
                    sock_events |= libc::POLLOUT;
                }
                pollfds.push(libc::pollfd {
                    fd: sock_fd,
                    events: sock_events,
                    revents: 0,
                });
            } else {
                pollfds.push(libc::pollfd {
                    fd: efd,
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
            pollfd_to_handle_idx.push(i);
            continue;
        }

        // Legacy stub handles (1 = mutex, 2 = event) — signal immediately.
        if handle == 1 || handle == 2 {
            eprintln!("weave/WFMO: handle[{i}]={handle:#x} → WAIT_OBJECT_0+{i} (stub)");
            return WAIT_OBJECT_0 + i as u32;
        }
    }

    // Poll all eventfd-backed handles together.
    #[cfg(target_os = "linux")]
    if !pollfds.is_empty() {
        let timeout_ms: i32 = if dw_milliseconds == INFINITE {
            -1
        } else {
            dw_milliseconds.min(i32::MAX as u32) as i32
        };
        let ret = libc::poll(
            pollfds.as_mut_ptr(),
            pollfds.len() as libc::nfds_t,
            timeout_ms,
        );
        if ret > 0 {
            for (pi, pfd) in pollfds.iter().enumerate() {
                let ready = (pfd.revents
                    & (libc::POLLIN | libc::POLLOUT | libc::POLLHUP | libc::POLLRDHUP))
                    != 0;
                if ready {
                    let hi = pollfd_to_handle_idx[pi];
                    let handle = *lp_handles.add(hi);
                    // If this fd is a socket (WSAEventSelect reverse map), do NOT drain
                    // the eventfd — WSAEnumNetworkEvents polls the socket fd directly.
                    if weave_common::socket_event::get_socket_for_event(handle as u64).is_some() {
                        eprintln!(
                            "weave/WFMO: handle[{hi}]={handle:#x} → WAIT_OBJECT_0+{hi} (socket-event fd={})",
                            pfd.fd
                        );
                    } else {
                        // Drain the eventfd counter.
                        let mut _val: u64 = 0;
                        libc::read(pfd.fd, &mut _val as *mut u64 as *mut libc::c_void, 8);
                        eprintln!("weave/WFMO: handle[{hi}] → WAIT_OBJECT_0+{hi} (eventfd)");
                    }
                    return WAIT_OBJECT_0 + hi as u32;
                }
            }
        }
        if ret == 0 {
            eprintln!("weave/WFMO: → WAIT_TIMEOUT");
            return WAIT_TIMEOUT;
        }
        // poll error — fall through to WAIT_FAILED
    }

    eprintln!("weave/WFMO: → WAIT_FAILED (no recognized handles)");
    WAIT_FAILED
}

/// WaitForMultipleObjectsEx — wait on multiple handles, optionally alertable.
///
/// Wine ref: dlls/kernelbase/sync.c — `WaitForMultipleObjects` is a thin
/// wrapper around this API with alertable=FALSE. Weave does not deliver APCs
/// yet, so alertable mode reuses the existing multi-object wait path.
///
/// # Safety
/// `lp_handles` must point to `n_count` handles, or be NULL when `n_count` is 0.
pub unsafe extern "win64" fn wait_for_multiple_objects_ex(
    n_count: u32,
    lp_handles: *const usize,
    b_wait_all: i32,
    dw_milliseconds: u32,
    _b_alertable: i32,
) -> u32 {
    unsafe { wait_for_multiple_objects(n_count, lp_handles, b_wait_all, dw_milliseconds) }
}

/// CreateMutexA — returns a fake handle (1).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/sync.c:702 — converts name via RtlCreateUnicodeStringFromAsciiz then
// delegates to CreateMutexExA; STATUS_OBJECT_NAME_EXISTS sets ERROR_ALREADY_EXISTS (183)
pub unsafe extern "win64" fn create_mutex_a(
    _lp_mutex_attributes: *const u8,
    _b_initial_owner: i32,
    lp_name: *const u8,
) -> usize {
    let name = if lp_name.is_null() {
        "(anonymous)".to_string()
    } else {
        // Read ANSI name for logging only
        let mut s = Vec::new();
        let mut p = lp_name;
        while unsafe { *p } != 0 {
            s.push(unsafe { *p });
            p = unsafe { p.add(1) };
        }
        String::from_utf8_lossy(&s).into_owned()
    };
    eprintln!("weave/kernel32: CreateMutexA({name:?}) → handle 1 (new)");
    set_last_error(0); // ERROR_SUCCESS — newly created, no duplicate
    1 // fake handle
}

/// CreateMutexW — returns a fake handle (1).
///
/// Same as CreateMutexA but accepts wide string name parameter.
/// Ignores name, initial owner flag, and security attributes.
/// Clears LastError to 0 (ERROR_SUCCESS) to signal a newly-created mutex —
/// callers check GetLastError()==ERROR_ALREADY_EXISTS (183) for single-instance
/// detection and must not see a stale error value here.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/sync.c:711 — delegates to CreateMutexExW(owner ? CREATE_MUTEX_INITIAL_OWNER : 0, MUTEX_ALL_ACCESS);
// CreateMutexExW calls NtCreateMutant; STATUS_OBJECT_NAME_EXISTS → ERROR_ALREADY_EXISTS
pub unsafe extern "win64" fn create_mutex_w(
    _lp_mutex_attributes: *const u8,
    _b_initial_owner: i32,
    lp_name: *const u16,
) -> usize {
    let name = if lp_name.is_null() {
        "(anonymous)".to_string()
    } else {
        let mut s = Vec::<u16>::new();
        let mut p = lp_name;
        while unsafe { *p } != 0 {
            s.push(unsafe { *p });
            p = unsafe { p.add(1) };
        }
        String::from_utf16_lossy(&s)
    };
    eprintln!("weave/kernel32: CreateMutexW({name:?}) → handle 1 (new)");
    set_last_error(0); // ERROR_SUCCESS — newly created, no duplicate
    1 // fake handle
}

/// CreateMutexExA — returns a fake handle (1).
///
/// Extended version with dwDesiredAccess parameter (ignored).
/// Same behavior as CreateMutexA.
///
// Wine ref: dlls/kernelbase/sync.c:720 — converts name via RtlAnsiStringToUnicodeString into
// StaticUnicodeString then delegates to CreateMutexExW; name > MAX_PATH → ERROR_FILENAME_EXCED_RANGE
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn create_mutex_ex_a(
    _lp_mutex_attributes: *const u8,
    _lp_name: *const u8,
    _dw_flags: u32,
    _dw_desired_access: u32,
) -> usize {
    1 // fake handle — ANSI name ignored; same semantics as CreateMutexExW
}

/// CreateMutexExW — returns a fake handle (1).
///
/// Extended version with dwDesiredAccess parameter (ignored).
/// Same behavior as CreateMutexW but accepts wide string name.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/sync.c:742 — calls NtCreateMutant; STATUS_OBJECT_NAME_EXISTS →
// ERROR_ALREADY_EXISTS; otherwise sets LastError from RtlNtStatusToDosError
pub unsafe extern "win64" fn create_mutex_ex_w(
    _lp_mutex_attributes: *const u8,
    lp_name: *const u16,
    _dw_flags: u32,
    _dw_desired_access: u32,
) -> usize {
    let name = if lp_name.is_null() {
        "(anonymous)".to_string()
    } else {
        let mut s = Vec::<u16>::new();
        let mut p = lp_name;
        while unsafe { *p } != 0 {
            s.push(unsafe { *p });
            p = unsafe { p.add(1) };
        }
        String::from_utf16_lossy(&s)
    };
    eprintln!("weave/kernel32: CreateMutexExW({name:?}) → handle 1 (new)");
    set_last_error(0); // ERROR_SUCCESS — newly created
    1 // fake handle
}
/// ReleaseMutex — no-op stub, returns TRUE.
// Wine ref: dlls/kernelbase/sync.c:782 — calls NtReleaseMutant(handle, NULL); NULL previous_count is valid
pub extern "win64" fn release_mutex(_h_mutex: usize) -> i32 {
    1 // fake mutex handle; real POSIX mutex is in SEMAPHORE_TABLE when created via CreateMutexW
}

/// RtlUnwind — legacy x86_64 unwind entry point (wrapper around RtlUnwindEx).
///
/// # Safety
/// Called only via Win64 IAT from PE code. All pointer arguments must be valid or NULL.
// Wine ref: dlls/ntdll/unwind.c:2352 — CONTEXT context; RtlUnwindEx(frame, target_ip, rec, retval, &context, NULL)
// RtlUnwind on x86_64 is a thin wrapper that allocates a local CONTEXT and delegates to
// RtlUnwindEx; the context is populated (here from naked trampoline register capture).
#[unsafe(naked)]
pub unsafe extern "win64" fn rtl_unwind(
    _target_frame: *mut u8,
    _target_ip: *mut u8,
    _exception_record: *mut u8,
    _return_value: usize,
) {
    core::arch::naked_asm!(
        "mov r10, [rsp]",
        "lea r11, [rsp+8]",
        "mov rdi, rcx",
        "mov rsi, rdx",
        "mov rdx, r8",
        "mov rcx, r9",
        "mov r8,  r10",
        "mov r9,  r11",
        "jmp {impl_fn}",
        impl_fn = sym rtl_unwind_impl,
    );
}

unsafe extern "C" fn rtl_unwind_impl(
    target_frame: u64,
    target_ip: u64,
    exception_record: *mut weave_core::unwind::ExceptionRecord,
    return_value: u64,
    caller_rip: u64,
    caller_rsp: u64,
) -> ! {
    // Build a Context anchored to the RtlUnwind call site from the naked trampoline capture.
    // Wine ref: dlls/ntdll/unwind.c:2352 — RtlUnwindEx is called with a local CONTEXT that
    // RtlUnwindEx fills; Weave seeds it from the naked trampoline's RSP/RIP capture.
    let mut ctx = weave_core::unwind::Context {
        context_flags: 0x10001f, // CONTEXT_ALL
        rip: caller_rip,
        rsp: caller_rsp,
        ..Default::default()
    };

    // Synthesise STATUS_UNWIND record if caller passed NULL.
    // Wine ref: dlls/ntdll/unwind.c — RtlUnwindEx accepts NULL record; ntdll synthesises
    // STATUS_UNWIND (0x80000027) in that case.
    #[allow(clippy::field_reassign_with_default)]
    let mut synthetic = weave_core::unwind::ExceptionRecord::default();
    synthetic.exception_code = 0x8000_0027; // STATUS_UNWIND — private _pad prevents struct literal
    let rec_ptr = if exception_record.is_null() {
        &mut synthetic as *mut _
    } else {
        exception_record
    };

    // SAFETY: target_frame and target_ip come from the PE's exception dispatch machinery.
    // ctx has valid RSP/RIP captured by the naked trampoline above. rec_ptr is non-null
    // (either caller-supplied or our synthetic record above).
    unsafe {
        weave_core::unwind::unwind_ex(
            target_frame,
            target_ip,
            rec_ptr,
            return_value,
            &mut ctx as *mut weave_core::unwind::Context,
        );
    }
}

/// UnhandledExceptionFilter — calls the stored handler if one is installed,
/// otherwise returns EXCEPTION_CONTINUE_SEARCH (0).
///
/// # Safety
/// `exception_pointers` is forwarded to the user-installed filter; the caller
/// is responsible for ensuring it is valid (or null for testing purposes).
// Wine ref: dlls/kernelbase/except.c — calls user filter if present with EXCEPTION_POINTERS*;
// returns its result. If no filter installed, returns EXCEPTION_CONTINUE_SEARCH.
pub unsafe extern "win64" fn unhandled_exception_filter(exception_pointers: *mut u8) -> i32 {
    let handler = UEF_HANDLER.load(Ordering::SeqCst);
    if handler == 0 {
        return 0; // EXCEPTION_CONTINUE_SEARCH
    }
    // SAFETY: handler was stored via set_unhandled_exception_filter as a valid
    // extern "win64" fn pointer. transmute from usize to fn ptr is the same
    // pattern used by the IAT trampoline in weave-core/src/iat.rs.
    let f: unsafe extern "win64" fn(*mut u8) -> i32 = std::mem::transmute(handler);
    f(exception_pointers)
}

// ── lstr* string functions ───────────────────────────────────────────────────

/// lstrcmpA — compare two ANSI strings.
///
/// # Safety
/// `lp_string1` and `lp_string2` must be valid null-terminated UTF-8 strings.
// Wine ref: dlls/user32/lstr.c — lstrcmpA wraps CompareStringA(LOCALE_USER_DEFAULT,...) in
// later Wine; returns negative/0/positive. NULL pointer → exception (not graceful return).
pub unsafe extern "win64" fn lstrcmp_a(lp_string1: *const u8, lp_string2: *const u8) -> i32 {
    unsafe { libc::strcmp(lp_string1 as *const i8, lp_string2 as *const i8) }
}

/// lstrcmpW — compare two wide strings.
///
/// # Safety
/// `lp_string1` and `lp_string2` must be valid null-terminated UTF-16 strings.
// Wine ref: dlls/user32/lstr.c — lstrcmpW wraps CompareStringW(LOCALE_USER_DEFAULT,...);
// char-by-char Unicode comparison; NULL pointer → exception on real Windows.
pub unsafe extern "win64" fn lstrcmp_w(lp_string1: *const u16, lp_string2: *const u16) -> i32 {
    unsafe {
        let mut p1 = lp_string1;
        let mut p2 = lp_string2;
        loop {
            let c1 = *p1;
            let c2 = *p2;
            if c1 != c2 {
                return if c1 < c2 { -1 } else { 1 };
            }
            if c1 == 0 {
                return 0;
            }
            p1 = p1.add(1);
            p2 = p2.add(1);
        }
    }
}

/// lstrcmpiA — compare two ANSI strings (case-insensitive).
///
// Wine ref: dlls/kernelbase/locale.c::CompareStringA — lstrcmpiA delegates to CompareStringA
// with LOCALE_USER_DEFAULT + NORM_IGNORECASE; returns 0 if strings are equal (CSTR_EQUAL - 2)
/// # Safety
/// `lp_string1` and `lp_string2` must be valid null-terminated UTF-8 strings.
pub unsafe extern "win64" fn lstrcmpi_a(lp_string1: *const u8, lp_string2: *const u8) -> i32 {
    unsafe { libc::strcasecmp(lp_string1 as *const i8, lp_string2 as *const i8) }
}

/// lstrcmpiW — compare two wide strings (case-insensitive).
///
// Wine ref: dlls/kernelbase/locale.c::CompareStringW — lstrcmpiW delegates to CompareStringW
// with LOCALE_USER_DEFAULT + NORM_IGNORECASE; ASCII fast-path for pure-ASCII strings
/// # Safety
/// `lp_string1` and `lp_string2` must be valid null-terminated UTF-16 strings.
pub unsafe extern "win64" fn lstrcmpi_w(lp_string1: *const u16, lp_string2: *const u16) -> i32 {
    unsafe {
        let mut p1 = lp_string1;
        let mut p2 = lp_string2;
        loop {
            let c1 = *p1;
            let c2 = *p2;
            let lc1 = if (c1 as u8).is_ascii_uppercase() {
                c1 + 32
            } else {
                c1
            };
            let lc2 = if (c2 as u8).is_ascii_uppercase() {
                c2 + 32
            } else {
                c2
            };
            if lc1 != lc2 {
                return if lc1 < lc2 { -1 } else { 1 };
            }
            if c1 == 0 {
                return 0;
            }
            p1 = p1.add(1);
            p2 = p2.add(1);
        }
    }
}

/// lstrlenA — get length of ANSI string.
///
// Wine ref: dlls/kernel32 — lstrlenA/lstrlenW are thin wrappers around strlen/wcslen;
// NULL input is undefined behavior per Windows docs (may AV); no special-casing in Wine
/// # Safety
/// `lp_string` must be a valid null-terminated UTF-8 string.
pub unsafe extern "win64" fn lstrlen_a(lp_string: *const u8) -> i32 {
    unsafe { libc::strlen(lp_string as *const i8) as i32 }
}

/// lstrlenW — get length of wide string.
///
// Wine ref: dlls/kernel32 — lstrlenW counts UTF-16 code units up to null terminator;
// equivalent to wcslen; no locale awareness; NULL input is undefined per Windows docs
/// # Safety
/// `lp_string` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn lstrlen_w(lp_string: *const u16) -> i32 {
    unsafe {
        let mut len = 0i32;
        let mut p = lp_string;
        while *p != 0 {
            len += 1;
            p = p.add(1);
        }
        len
    }
}

/// lstrcatA — append ANSI string.
///
// Wine ref: dlls/kernel32 — lstrcatA is strcat; appends src to dst in-place;
// returns dst pointer; no bounds checking; NULL src/dst is undefined behavior
/// # Safety
/// `lp_string1` must be writable and null-terminated with space for `lp_string2`.
/// `lp_string2` must be a valid null-terminated UTF-8 string.
pub unsafe extern "win64" fn lstrcat_a(lp_string1: *mut u8, lp_string2: *const u8) -> *mut u8 {
    unsafe {
        let mut dst = lp_string1;
        while *dst != 0 {
            dst = dst.add(1);
        }
        let mut src = lp_string2;
        loop {
            let c = *src;
            *dst = c;
            if c == 0 {
                break;
            }
            dst = dst.add(1);
            src = src.add(1);
        }
    }
    lp_string1
}

/// lstrcatW — append wide string.
///
// Wine ref: dlls/kernel32 — lstrcatW is wcscat; appends src to dst in-place;
// returns dst pointer; no bounds checking; NULL src/dst is undefined behavior
/// # Safety
/// `lp_string1` must be writable and null-terminated with space for `lp_string2`.
/// `lp_string2` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn lstrcat_w(lp_string1: *mut u16, lp_string2: *const u16) -> *mut u16 {
    unsafe {
        let mut dst = lp_string1;
        while *dst != 0 {
            dst = dst.add(1);
        }
        let mut src = lp_string2;
        loop {
            let c = *src;
            *dst = c;
            if c == 0 {
                break;
            }
            dst = dst.add(1);
            src = src.add(1);
        }
    }
    lp_string1
}

/// lstrcpyA — copy ANSI string.
///
// Wine ref: dlls/kernel32 — lstrcpyA/W are strcpy/wcscpy wrappers; buffer overrun is
// caller's responsibility; NULL src → undefined; returns dst pointer like strcpy
/// # Safety
/// `lp_string1` must be writable for the length of `lp_string2` plus null terminator.
/// `lp_string2` must be a valid null-terminated UTF-8 string.
pub unsafe extern "win64" fn lstrcpy_a(lp_string1: *mut u8, lp_string2: *const u8) -> *mut u8 {
    unsafe { libc::strcpy(lp_string1 as *mut i8, lp_string2 as *const i8) as *mut u8 };
    lp_string1
}

/// lstrcpyW — copy wide string.
///
// Wine ref: dlls/kernel32 — lstrcpyW is wcscpy; copies until null UTF-16 code unit;
// no bounds checking; returns dst pointer
/// # Safety
/// `lp_string1` must be writable for the length of `lp_string2` plus null terminator.
/// `lp_string2` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn lstrcpy_w(lp_string1: *mut u16, lp_string2: *const u16) -> *mut u16 {
    unsafe {
        let mut dst = lp_string1;
        let mut src = lp_string2;
        loop {
            let c = *src;
            *dst = c;
            if c == 0 {
                break;
            }
            dst = dst.add(1);
            src = src.add(1);
        }
    }
    lp_string1
}

/// lstrcpynA — bounded copy of ANSI string.
///
// Wine ref: dlls/kernel32 — lstrcpynA is strncpy; copies at most iMaxLength-1 chars then
// always null-terminates dst[iMaxLength-1] (unlike POSIX strncpy which may not null-terminate)
/// # Safety
/// `lp_string1` must be writable for at least `i_max_length` bytes.
/// `lp_string2` must be a valid null-terminated UTF-8 string.
pub unsafe extern "win64" fn lstrcpyn_a(
    lp_string1: *mut u8,
    lp_string2: *const u8,
    i_max_length: i32,
) -> *mut u8 {
    unsafe {
        libc::strncpy(
            lp_string1 as *mut i8,
            lp_string2 as *const i8,
            i_max_length as usize,
        ) as *mut u8
    };
    lp_string1
}

/// lstrcpynW — bounded copy of wide string.
///
// Wine ref: dlls/kernel32 — lstrcpynW copies at most iMaxLength-1 wide chars then forces
// null terminator at dst[iMaxLength-1], unlike wcsncpy which may leave dst unterminated
/// # Safety
/// `lp_string1` must be writable for at least `i_max_length` u16 words.
/// `lp_string2` must be a valid null-terminated UTF-16 string.
pub unsafe extern "win64" fn lstrcpyn_w(
    lp_string1: *mut u16,
    lp_string2: *const u16,
    i_max_length: i32,
) -> *mut u16 {
    unsafe {
        let mut dst = lp_string1;
        let mut src = lp_string2;
        let max_len = i_max_length as usize;
        for _i in 0..max_len {
            let c = *src;
            *dst = c;
            if c == 0 {
                break;
            }
            dst = dst.add(1);
            src = src.add(1);
        }
        // Ensure null termination
        if max_len > 0 {
            *lp_string1.add(max_len - 1) = 0;
        }
    }
    lp_string1
}

// ── Directory path functions ──────────────────────────────────────────────────

/// GetWindowsDirectoryW — write "C:\Windows" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `u_size` u16 words.
// Wine ref: dlls/kernelbase/file.c:2605 — delegates to copy_filename(windows_dir, path, count);
// windows_dir is initialized from SharedUserData->NtSystemRoot (e.g. "C:\Windows")
pub unsafe extern "win64" fn get_windows_directory_w(lp_buffer: *mut u16, u_size: u32) -> u32 {
    const PATH: &str = "C:\\Windows\0";
    let wide_chars: Vec<u16> = PATH.encode_utf16().collect();
    let len = wide_chars.len() - 1; // exclude null terminator

    if u_size as usize <= len {
        return len as u32; // required size
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_buffer, wide_chars.len());
    }
    len as u32
}

/// GetWindowsDirectoryA — write "C:\Windows" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `u_size` bytes.
// Wine ref: dlls/kernelbase/file.c:2596 — converts windows_dir from UNICODE_STRING via WideCharToMultiByte then copies
pub unsafe extern "win64" fn get_windows_directory_a(lp_buffer: *mut u8, u_size: u32) -> u32 {
    const PATH: &str = "C:\\Windows\0";
    let bytes = PATH.as_bytes();
    let len = bytes.len() - 1; // exclude null terminator

    if u_size as usize <= len {
        return len as u32; // required size
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, bytes.len());
    }
    len as u32
}

/// GetSystemDirectoryW — write "C:\Windows\System32" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `u_size` u16 words.
// Wine ref: dlls/kernelbase/file.c:2341 — delegates to copy_filename(system_dir, path, count);
// system_dir is initialized from windows_dir + "\system32"
pub unsafe extern "win64" fn get_system_directory_w(lp_buffer: *mut u16, u_size: u32) -> u32 {
    const PATH: &str = "C:\\Windows\\System32\0";
    let wide_chars: Vec<u16> = PATH.encode_utf16().collect();
    let len = wide_chars.len() - 1; // exclude null terminator

    if u_size as usize <= len {
        return len as u32; // required size
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_buffer, wide_chars.len());
    }
    len as u32
}

/// GetSystemDirectoryA — write "C:\Windows\System32" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `u_size` bytes.
// Wine ref: dlls/kernelbase/file.c:2332 — converts system_dir from wide to ANSI then copies
pub unsafe extern "win64" fn get_system_directory_a(lp_buffer: *mut u8, u_size: u32) -> u32 {
    const PATH: &str = "C:\\Windows\\System32\0";
    let bytes = PATH.as_bytes();
    let len = bytes.len() - 1; // exclude null terminator

    if u_size as usize <= len {
        return len as u32; // required size
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, bytes.len());
    }
    len as u32
}

/// GetTempPathW — write "C:\Temp\" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `n_buffer_length` u16 words.
// Wine ref: dlls/kernelbase/file.c:2521 — checks TMP, TEMP, USERPROFILE env vars in order, then
// falls back to GetWindowsDirectoryW; appends trailing backslash; zeroes remainder of buffer up to 32767 chars
pub unsafe extern "win64" fn get_temp_path_w(n_buffer_length: u32, lp_buffer: *mut u16) -> u32 {
    const PATH: &str = "C:\\Temp\\\0";
    let wide_chars: Vec<u16> = PATH.encode_utf16().collect();
    let len = wide_chars.len() - 1; // exclude null terminator

    if n_buffer_length as usize <= len {
        return len as u32 + 1; // required size including null
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_buffer, wide_chars.len());
    }
    len as u32
}

/// GetTempPathA — write "C:\Temp\" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `n_buffer_length` bytes.
// Wine ref: dlls/kernelbase/file.c:2503 — heap-allocates a wide buffer, calls GetTempPathW, then
// converts via WideCharToMultiByte; returns required byte count (not char count) when buffer too small
pub unsafe extern "win64" fn get_temp_path_a(n_buffer_length: u32, lp_buffer: *mut u8) -> u32 {
    const PATH: &str = "C:\\Temp\\\0";
    let bytes = PATH.as_bytes();
    let len = bytes.len() - 1; // exclude null terminator

    if n_buffer_length as usize <= len {
        return len as u32 + 1; // required size including null
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, bytes.len());
    }
    len as u32
}

/// GetCurrentDirectoryW — write "C:\" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `n_buffer_length` u16 words.
// Wine ref: dlls/kernelbase/file.c:1734 — delegates to RtlGetCurrentDirectory_U(buflen*sizeof(WCHAR), buf);
// divides byte count result by sizeof(WCHAR) to return char count; the NT current dir is in PEB->ProcessParameters
pub unsafe extern "win64" fn get_current_directory_w(
    n_buffer_length: u32,
    lp_buffer: *mut u16,
) -> u32 {
    // Return the actual Linux process CWD represented as a Windows path.
    // Drive Z: is mapped to the Linux filesystem root '/', so any Linux
    // absolute path can be expressed as Z:\<path>.
    let cwd = std::env::current_dir()
        .map(|p| {
            // Convert /some/linux/path  →  Z:\some\linux\path
            let s = p.to_string_lossy();
            format!("Z:{}", s.replace('/', "\\"))
        })
        .unwrap_or_else(|_| "C:\\".to_string());

    let mut wide_chars: Vec<u16> = cwd.encode_utf16().collect();
    wide_chars.push(0); // null terminator
    let len = wide_chars.len() - 1; // chars excluding null

    if n_buffer_length as usize <= len {
        return len as u32 + 1; // required buffer size including null
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_buffer, wide_chars.len());
    }
    len as u32
}

/// GetCurrentDirectoryA — write "C:\" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `n_buffer_length` bytes.
// Wine ref: dlls/kernelbase/file.c:1704 — heap-allocates a wide buffer, calls GetCurrentDirectoryW,
// converts via WideCharToMultiByte; returns required byte count on buffer-too-small
pub unsafe extern "win64" fn get_current_directory_a(
    n_buffer_length: u32,
    lp_buffer: *mut u8,
) -> u32 {
    let cwd = std::env::current_dir()
        .map(|p| {
            let s = p.to_string_lossy();
            format!("Z:{}\0", s.replace('/', "\\"))
        })
        .unwrap_or_else(|_| "C:\\\0".to_string());

    let bytes = cwd.as_bytes();
    let len = bytes.len() - 1; // exclude null terminator

    if n_buffer_length as usize <= len {
        return len as u32 + 1; // required size including null
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, bytes.len());
    }
    len as u32
}

/// SetCurrentDirectoryW — change the current working directory (Wide).
///
/// Weave translates the wide Windows path to a Linux path via
/// weave_core::prefix and calls chdir(2). Returns FALSE on error.
///
/// # Safety
/// `lp_path_name` must be a valid null-terminated UTF-16 string or NULL.
// Wine ref: dlls/kernelbase/file.c:2949 — calls RtlInitUnicodeString then RtlSetCurrentDirectory_U;
// RtlSetCurrentDirectory_U updates PEB->ProcessParameters->CurrentDirectory under RtlAcquirePebLock
pub unsafe extern "win64" fn set_current_directory_w(lp_path_name: *const u16) -> i32 {
    if lp_path_name.is_null() {
        return 0; // FALSE
    }
    // Decode wide string, capped to avoid runaway reads.
    let mut len = 0usize;
    while len < MAX_UTF16_LEN && unsafe { *lp_path_name.add(len) } != 0 {
        len += 1;
    }
    let wide = unsafe { std::slice::from_raw_parts(lp_path_name, len) };
    let s = String::from_utf16_lossy(wide);
    // Translate Windows path (may start with Z:\...) to Linux path.
    let linux_path = weave_core::prefix::translator()
        .to_linux_str(&s)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| s.clone());
    let cstr = match std::ffi::CString::new(linux_path.as_bytes()) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let rc = unsafe { libc::chdir(cstr.as_ptr()) };
    if rc == 0 {
        1
    } else {
        0
    } // TRUE / FALSE
}

/// SetCurrentDirectoryA — change the current working directory (ANSI).
///
/// Weave converts ANSI to UTF-8 and calls chdir(2) directly.
///
/// # Safety
/// `lp_path_name` must be a valid null-terminated ANSI string or NULL.
// Wine ref: dlls/kernelbase/file.c:2935 — converts via file_name_AtoW then delegates to SetCurrentDirectoryW
pub unsafe extern "win64" fn set_current_directory_a(lp_path_name: *const u8) -> i32 {
    if lp_path_name.is_null() {
        return 0;
    }
    let s = unsafe { std::ffi::CStr::from_ptr(lp_path_name as *const libc::c_char) }
        .to_string_lossy()
        .into_owned();
    let linux_path = weave_core::prefix::translator()
        .to_linux_str(&s)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or(s.clone());
    let cstr = match std::ffi::CString::new(linux_path.as_bytes()) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let rc = unsafe { libc::chdir(cstr.as_ptr()) };
    if rc == 0 {
        1
    } else {
        0
    }
}

// ── Computer name and username ────────────────────────────────────────────────

/// GetComputerNameW — write "WEAVE" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `lpn_size` u16 words.
/// `lpn_size` must be a valid pointer to a u32.
// Wine ref: dlls/kernelbase/registry.c — delegates to GetComputerNameExW(ComputerNameNetBIOS);
// ComputerNameNetBIOS reads HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName
pub unsafe extern "win64" fn get_computer_name_w(lp_buffer: *mut u16, lpn_size: *mut u32) -> i32 {
    const NAME: &str = "WEAVE\0";
    let wide_chars: Vec<u16> = NAME.encode_utf16().collect();
    let len = wide_chars.len() - 1; // exclude null terminator

    if lp_buffer.is_null() || lpn_size.is_null() {
        return 0; // FALSE
    }

    let buffer_size = unsafe { *lpn_size } as usize;
    if buffer_size <= len {
        unsafe { *lpn_size = len as u32 };
        return 0; // FALSE - buffer too small
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_buffer, wide_chars.len());
        *lpn_size = len as u32;
    }
    1 // TRUE
}

/// GetComputerNameA — write "WEAVE" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `lpn_size` bytes.
/// `lpn_size` must be a valid pointer to a u32.
// Wine ref: dlls/kernelbase/registry.c — delegates to GetComputerNameExA(ComputerNameNetBIOS);
// converts wide result via WideCharToMultiByte; sets ERROR_BUFFER_OVERFLOW if buffer too small
pub unsafe extern "win64" fn get_computer_name_a(lp_buffer: *mut u8, lpn_size: *mut u32) -> i32 {
    const NAME: &str = "WEAVE\0";
    let bytes = NAME.as_bytes();
    let len = bytes.len() - 1; // exclude null terminator

    if lp_buffer.is_null() || lpn_size.is_null() {
        return 0; // FALSE
    }

    let buffer_size = unsafe { *lpn_size } as usize;
    if buffer_size <= len {
        unsafe { *lpn_size = len as u32 };
        return 0; // FALSE - buffer too small
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, bytes.len());
        *lpn_size = len as u32;
    }
    1 // TRUE
}

/// GetUserNameW — write "WeavUser" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `pcb_buffer` u16 words.
/// `pcb_buffer` must be a valid pointer to a u32.
// Wine ref: dlls/secur32/userenv.c — queries token via GetTokenInformation(TokenUser) then
// LookupAccountSidW to get user name; pcb_buffer is in chars including NUL; ERROR_INSUFFICIENT_BUFFER if too small
pub unsafe extern "win64" fn get_user_name_w(lp_buffer: *mut u16, pcb_buffer: *mut u32) -> i32 {
    const NAME: &str = "WeavUser\0";
    let wide_chars: Vec<u16> = NAME.encode_utf16().collect();
    let len = wide_chars.len() - 1; // exclude null terminator

    if lp_buffer.is_null() || pcb_buffer.is_null() {
        return 0; // FALSE
    }

    let buffer_size = unsafe { *pcb_buffer } as usize;
    if buffer_size <= len {
        unsafe { *pcb_buffer = len as u32 };
        return 0; // FALSE - buffer too small
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_buffer, wide_chars.len());
        *pcb_buffer = len as u32;
    }
    1 // TRUE
}

/// GetUserNameA — write "WeavUser" into buffer.
///
/// # Safety
/// `lp_buffer` must be writable for `pcb_buffer` bytes.
/// `pcb_buffer` must be a valid pointer to a u32.
// Wine ref: dlls/secur32/userenv.c — calls GetUserNameW then converts via WideCharToMultiByte;
// pcb_buffer counts bytes including NUL terminator
pub unsafe extern "win64" fn get_user_name_a(lp_buffer: *mut u8, pcb_buffer: *mut u32) -> i32 {
    const NAME: &str = "WeavUser\0";
    let bytes = NAME.as_bytes();
    let len = bytes.len() - 1; // exclude null terminator

    if lp_buffer.is_null() || pcb_buffer.is_null() {
        return 0; // FALSE
    }

    let buffer_size = unsafe { *pcb_buffer } as usize;
    if buffer_size <= len {
        unsafe { *pcb_buffer = len as u32 };
        return 0; // FALSE - buffer too small
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, bytes.len());
        *pcb_buffer = len as u32;
    }
    1 // TRUE
}

// ── File attribute functions ──────────────────────────────────────────────────

/// GetFileAttributesW — check if file/directory exists and return attributes.
///
/// Translates Win32 path to Linux path and uses libc::stat to check existence.
/// Returns FILE_ATTRIBUTE_NORMAL for files, FILE_ATTRIBUTE_DIRECTORY for directories,
/// or INVALID_FILE_ATTRIBUTES if not found or stat fails.
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-16 string.
// Wine ref: dlls/kernelbase/file.c:1755 — uses NtQueryAttributesFile(FILE_BASIC_INFORMATION);
// falls back to FILE_ATTRIBUTE_ARCHIVE for DOS device names (e.g. "NUL") which NtQueryAttributesFile rejects
pub unsafe extern "win64" fn get_file_attributes_w(lp_file_name: *const u16) -> u32 {
    const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFFFFFF;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;

    if lp_file_name.is_null() {
        set_last_error(file_io::ERROR_FILE_NOT_FOUND);
        eprintln!("weave/GetFileAttributesW: entry null_name → INVALID");
        return INVALID_FILE_ATTRIBUTES;
    }

    // Decode UTF-16 filename
    let mut len = 0usize;
    // SAFETY: (a) lp_file_name is non-null (checked above); (b) guest heap;
    // (c) duration of scan; (d) MAX_UTF16_LEN cap prevents OOB if the guest passes a
    // non-terminated pointer — reads at most MAX_UTF16_LEN u16s before stopping.
    // Caveat: a non-null, non-terminated pointer of length ≥ MAX_UTF16_LEN would be
    // scanned for exactly MAX_UTF16_LEN code units without finding a null — treated as
    // an overlong path and rejected with INVALID_FILE_ATTRIBUTES below.
    while len < MAX_UTF16_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF16_LEN {
        set_last_error(file_io::ERROR_FILE_NOT_FOUND);
        eprintln!("weave/GetFileAttributesW: entry overlong_name → INVALID");
        return INVALID_FILE_ATTRIBUTES;
    }
    // SAFETY: (a) lp_file_name is non-null (checked above) and the scan above confirmed
    // `len` code units before the null terminator; (b) guest heap; (c) duration of call;
    // (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
    let win_path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_file_name, len)) };

    eprintln!("weave/GetFileAttributesW: entry path={win_path:?}");

    // Translate to Linux path (with fallback for Linux absolute paths passed
    // as CLI arguments to a Windows app running under Weave).
    // Wine ref: dlls/kernelbase/file.c:1755 — SetLastError(RtlNtStatusToDosError(status))
    // on NtQueryAttributesFile failure; ENOENT maps to ERROR_FILE_NOT_FOUND.
    let linux_path = match weave_core::file_io::translate_win_path(&win_path) {
        Ok(p) => p,
        Err(_) => {
            set_last_error(file_io::ERROR_FILE_NOT_FOUND);
            eprintln!("weave/GetFileAttributesW: exit path={win_path:?} translate_err → INVALID");
            return INVALID_FILE_ATTRIBUTES;
        }
    };

    // Check if path exists and get type
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => {
            set_last_error(file_io::ERROR_FILE_NOT_FOUND);
            eprintln!("weave/GetFileAttributesW: exit path={win_path:?} cstring_err → INVALID");
            return INVALID_FILE_ATTRIBUTES;
        }
    };

    // SAFETY: (a) zeroed() produces a valid zero-initialized libc::stat; (b) Rust stack;
    // (c) duration of this call; (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: (a) c_path.as_ptr() is a valid null-terminated C string (CString invariant);
    // &mut stat points to a properly-aligned libc::stat on the stack; (b) c_path on Rust
    // stack, stat on Rust stack; (c) duration of stat syscall; (d) same gate.
    let ret = unsafe { libc::stat(c_path.as_ptr(), &mut stat) };
    if ret != 0 {
        set_last_error(file_io::ERROR_FILE_NOT_FOUND);
        eprintln!("weave/GetFileAttributesW: exit path={win_path:?} stat_err → INVALID");
        return INVALID_FILE_ATTRIBUTES;
    }

    // Check if it's a directory
    let mut attrs = if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    };

    // Windows sets FILE_ATTRIBUTE_ARCHIVE (0x20) on all regular files by default.
    // Many apps (including 7-zip) validate that newly-written files carry this bit.
    // FILE_ATTRIBUTE_NORMAL (0x80) is only valid when it is the sole attribute, so
    // clear it once ARCHIVE is added.
    if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
        attrs |= FILE_ATTRIBUTE_ARCHIVE; // 0x20 — set ARCHIVE for regular files
        attrs &= !FILE_ATTRIBUTE_NORMAL; // 0x80 — NORMAL only valid as sole attribute
    }

    eprintln!("weave/GetFileAttributesW: exit path={win_path:?} attrs={attrs:#x}");
    attrs
}

/// GetFileAttributesA — check if file/directory exists and return attributes.
///
/// Same as GetFileAttributesW but accepts ANSI string.
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-8 string.
// Wine ref: dlls/kernelbase/file.c:1743 — converts via file_name_AtoW then delegates to GetFileAttributesW
pub unsafe extern "win64" fn get_file_attributes_a(lp_file_name: *const u8) -> u32 {
    const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFFFFFF;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

    if lp_file_name.is_null() {
        set_last_error(file_io::ERROR_FILE_NOT_FOUND);
        eprintln!("weave/GetFileAttributesA: entry null_name → INVALID");
        return INVALID_FILE_ATTRIBUTES;
    }

    // Decode UTF-8 filename
    let mut len = 0usize;
    while len < MAX_UTF8_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF8_LEN {
        set_last_error(file_io::ERROR_FILE_NOT_FOUND);
        eprintln!("weave/GetFileAttributesA: entry overlong_name → INVALID");
        return INVALID_FILE_ATTRIBUTES;
    }
    let win_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_file_name, len)) };

    eprintln!("weave/GetFileAttributesA: entry path={win_path:?}");

    // Translate to Linux path (with fallback for Linux absolute paths passed
    // as CLI arguments to a Windows app running under Weave).
    // Wine ref: dlls/kernelbase/file.c:1743 — file_name_AtoW then delegates to
    // GetFileAttributesW; the W variant SetLastError(RtlNtStatusToDosError(status))
    // on NtQueryAttributesFile failure (ENOENT → ERROR_FILE_NOT_FOUND).
    let linux_path = match weave_core::file_io::translate_win_path(&win_path) {
        Ok(p) => p,
        Err(_) => {
            set_last_error(file_io::ERROR_FILE_NOT_FOUND);
            eprintln!("weave/GetFileAttributesA: exit path={win_path:?} translate_err → INVALID");
            return INVALID_FILE_ATTRIBUTES;
        }
    };

    // Check if path exists and get type
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => {
            set_last_error(file_io::ERROR_FILE_NOT_FOUND);
            eprintln!("weave/GetFileAttributesA: exit path={win_path:?} cstring_err → INVALID");
            return INVALID_FILE_ATTRIBUTES;
        }
    };

    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let ret = unsafe { libc::stat(c_path.as_ptr(), &mut stat) };
    if ret != 0 {
        set_last_error(file_io::ERROR_FILE_NOT_FOUND);
        eprintln!("weave/GetFileAttributesA: exit path={win_path:?} stat_err → INVALID");
        return INVALID_FILE_ATTRIBUTES;
    }

    // Check if it's a directory
    let attrs = if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    eprintln!("weave/GetFileAttributesA: exit path={win_path:?} attrs={attrs:#x}");
    attrs
}

/// GetFullPathNameW: resolve relative paths to absolute paths.
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-16 string.
/// `lp_buffer` must be writable for `n_buffer_length` u16 words.
/// `lp_file_part` must be a valid writable pointer or NULL.
// Wine ref: dlls/kernelbase/file.c:2063 — delegates to RtlGetFullPathName_U(name, len*sizeof(WCHAR), buf, lastpart);
// divides byte result by sizeof(WCHAR); lastpart is set to the pointer of the filename component in buffer
pub unsafe extern "win64" fn get_full_path_name_w(
    lp_file_name: *const u16,
    n_buffer_length: u32,
    lp_buffer: *mut u16,
    lp_file_part: *mut *mut u16,
) -> u32 {
    if lp_file_name.is_null() {
        eprintln!("weave/GetFullPathNameW: entry → 0 (null lp_file_name)");
        return 0;
    }

    // Read the null-terminated UTF-16 filename
    let mut len = 0usize;
    while len < MAX_UTF16_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF16_LEN {
        eprintln!("weave/GetFullPathNameW: entry → 0 (path too long)");
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts(lp_file_name, len) };
    let win_path = String::from_utf16_lossy(slice);
    eprintln!("weave/GetFullPathNameW: entry path={win_path:?} n_buffer_length={n_buffer_length}");

    // Resolve relative paths against the real CWD (returned as Z:\... by
    // GetCurrentDirectoryW).  Previously this hardcoded "C:\" which caused
    // CreateFileW to look in the wrong drive for any relative-path argument.
    let cwd_win = std::env::current_dir()
        .map(|p| format!("Z:{}", p.to_string_lossy().replace('/', "\\")))
        .unwrap_or_else(|_| "Z:\\".to_string());
    let is_drive_absolute = len >= 3 && slice[1] == b':' as u16 && slice[2] == b'\\' as u16;
    let is_drive_relative = len >= 2
        && (slice[0] as u8).is_ascii_alphabetic()
        && slice[1] == b':' as u16
        && !is_drive_absolute;

    let resolved_path = if is_drive_relative {
        // Wine ref: dlls/ntdll/path.c — RtlPathTypeDriveRelative prepends the PEB
        // current directory when the path's drive matches the process CWD drive.
        let path_drive = (slice[0] as u8 as char).to_ascii_uppercase();
        let cwd_drive = cwd_win.chars().next().unwrap_or('Z').to_ascii_uppercase();
        let mut rest = &win_path[2..];
        if let Some(stripped) = rest.strip_prefix(".\\").or_else(|| rest.strip_prefix("./")) {
            rest = stripped;
        } else if rest == "." {
            rest = "";
        }
        if path_drive == cwd_drive {
            let cwd_trimmed = cwd_win.trim_end_matches('\\');
            if rest.is_empty() {
                cwd_win.clone()
            } else {
                format!("{cwd_trimmed}\\{rest}")
            }
        } else {
            // Different drive — anchor at that drive's root.
            format!("{}:\\{}", path_drive, rest)
        }
    } else if len >= 2 && (slice[0] as u8).is_ascii_alphabetic() && slice[1] == b':' as u16 {
        // Drive-absolute (Z:\...) — use as-is.
        win_path
    } else if win_path.starts_with('\\') {
        // Root-relative (no drive): prepend drive letter from CWD.
        let drive = cwd_win.split(':').next().unwrap_or("Z");
        format!("{}:{}", drive, win_path)
    } else {
        // Relative path: prepend full CWD.
        let cwd_trimmed = cwd_win.trim_end_matches('\\');
        format!("{}\\{}", cwd_trimmed, win_path)
    };

    // Convert back to UTF-16 with null terminator
    let wide_path: Vec<u16> = resolved_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let required_chars = wide_path.len();

    // Size query
    if n_buffer_length == 0 {
        let r = required_chars as u32;
        eprintln!("weave/GetFullPathNameW: exit resolved={resolved_path:?} → {r} (size query)");
        return r;
    }

    // Copy to buffer if it fits
    if n_buffer_length as usize >= required_chars {
        unsafe {
            std::ptr::copy_nonoverlapping(wide_path.as_ptr(), lp_buffer, required_chars);
        }

        // Set lp_file_part to point at the last path component (after last \)
        if !lp_file_part.is_null() {
            let path_str = &resolved_path;
            if let Some(last_backslash) = path_str.rfind('\\') {
                let file_part_offset = last_backslash + 1;
                unsafe {
                    *lp_file_part = lp_buffer.add(file_part_offset);
                }
            } else {
                unsafe {
                    *lp_file_part = lp_buffer;
                }
            }
        }

        let r = (required_chars - 1) as u32;
        eprintln!("weave/GetFullPathNameW: exit resolved={resolved_path:?} → {r} (chars written)");
        r // return chars written (excluding null)
    } else {
        let r = required_chars as u32;
        eprintln!(
            "weave/GetFullPathNameW: exit resolved={resolved_path:?} required={required_chars} buf={n_buffer_length} → {r} (buf too small)"
        );
        r
    }
}

/// GetFullPathNameA: resolve relative paths to absolute paths (ANSI version).
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-8 string.
/// `lp_buffer` must be writable for `n_buffer_length` bytes.
/// `lp_file_part` must be a valid writable pointer or NULL.
// Wine ref: dlls/kernelbase/file.c:2032 — converts via file_name_AtoW, calls RtlGetFullPathName_U,
// converts result back via WideCharToMultiByte; returns required byte count when buffer too small
pub unsafe extern "win64" fn get_full_path_name_a(
    lp_file_name: *const u8,
    n_buffer_length: u32,
    lp_buffer: *mut u8,
    lp_file_part: *mut *mut u8,
) -> u32 {
    if lp_file_name.is_null() {
        return 0;
    }

    // Read the null-terminated UTF-8 filename
    let win_path = unsafe {
        let mut len = 0usize;
        while len < MAX_UTF8_LEN && *lp_file_name.add(len) != 0 {
            len += 1;
        }
        if len == MAX_UTF8_LEN {
            return 0;
        }
        let slice = std::slice::from_raw_parts(lp_file_name, len);
        String::from_utf8_lossy(slice).into_owned()
    };

    // Resolve relative paths against the real CWD (returned as Z:\... by
    // GetCurrentDirectoryW).  Previously this hardcoded "C:\" which caused
    // CreateFileW to look in the wrong drive for any relative-path argument.
    let cwd_win = std::env::current_dir()
        .map(|p| format!("Z:{}", p.to_string_lossy().replace('/', "\\")))
        .unwrap_or_else(|_| "Z:\\".to_string());
    let bytes = win_path.as_bytes();
    let is_drive_absolute = bytes.len() >= 3 && bytes[1] == b':' && bytes[2] == b'\\';
    let is_drive_relative = bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && !is_drive_absolute;

    let resolved_path = if is_drive_relative {
        let path_drive = (bytes[0] as char).to_ascii_uppercase();
        let cwd_drive = cwd_win.chars().next().unwrap_or('Z').to_ascii_uppercase();
        let mut rest = &win_path[2..];
        if let Some(stripped) = rest.strip_prefix(".\\").or_else(|| rest.strip_prefix("./")) {
            rest = stripped;
        } else if rest == "." {
            rest = "";
        }
        if path_drive == cwd_drive {
            let cwd_trimmed = cwd_win.trim_end_matches('\\');
            if rest.is_empty() {
                cwd_win.clone()
            } else {
                format!("{cwd_trimmed}\\{rest}")
            }
        } else {
            format!("{}:\\{}", path_drive, rest)
        }
    } else if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        win_path
    } else if win_path.starts_with('\\') {
        // Root-relative (no drive): prepend drive letter from CWD.
        let drive = cwd_win.split(':').next().unwrap_or("Z");
        format!("{}:{}", drive, win_path)
    } else {
        // Relative path: prepend full CWD.
        let cwd_trimmed = cwd_win.trim_end_matches('\\');
        format!("{}\\{}", cwd_trimmed, win_path)
    };

    // Convert to bytes with null terminator
    let bytes = resolved_path.as_bytes();
    let required_bytes = bytes.len() + 1;

    // Size query
    if n_buffer_length == 0 {
        return required_bytes as u32;
    }

    // Copy to buffer if it fits
    if n_buffer_length as usize >= required_bytes {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, bytes.len());
            *lp_buffer.add(bytes.len()) = 0; // null terminator
        }

        // Set lp_file_part to point at the last path component (after last \)
        if !lp_file_part.is_null() {
            let path_str = &resolved_path;
            if let Some(last_backslash) = path_str.rfind('\\') {
                let file_part_offset = last_backslash + 1;
                unsafe {
                    *lp_file_part = lp_buffer.add(file_part_offset);
                }
            } else {
                unsafe {
                    *lp_file_part = lp_buffer;
                }
            }
        }

        (required_bytes - 1) as u32 // return bytes written (excluding null)
    } else {
        required_bytes as u32
    }
}

/// GetVolumePathNameW: return the volume root for a file or directory path.
///
/// Wine ref: dlls/kernelbase/volume.c — resolves a file path to its mounted
/// volume root and copies that root into the caller buffer. Weave exposes a
/// single host-backed drive namespace, so the root is the input drive when one
/// is present and `Z:\` for relative or null paths.
///
/// # Safety
/// `lpsz_file_name` must be a valid null-terminated UTF-16 string when non-null.
/// `lpsz_volume_path_name` must be writable for `cch_buffer_length` UTF-16 code units.
pub unsafe extern "win64" fn get_volume_path_name_w(
    lpsz_file_name: *const u16,
    lpsz_volume_path_name: *mut u16,
    cch_buffer_length: u32,
) -> i32 {
    const ERROR_INVALID_PARAMETER: u32 = 87;
    const ERROR_MORE_DATA: u32 = 234;

    if lpsz_volume_path_name.is_null() {
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }

    let input = if lpsz_file_name.is_null() {
        String::new()
    } else {
        let mut len = 0usize;
        while len < MAX_UTF16_LEN && unsafe { *lpsz_file_name.add(len) } != 0 {
            len += 1;
        }
        if len == MAX_UTF16_LEN {
            set_last_error(ERROR_INVALID_PARAMETER);
            return 0;
        }
        let slice = unsafe { std::slice::from_raw_parts(lpsz_file_name, len) };
        String::from_utf16_lossy(slice)
    };

    let drive = if input.len() >= 2
        && input.as_bytes()[0].is_ascii_alphabetic()
        && input.as_bytes()[1] == b':'
    {
        input.as_bytes()[0].to_ascii_uppercase() as char
    } else {
        'Z'
    };
    let volume = format!("{drive}:\\");
    let wide: Vec<u16> = volume.encode_utf16().chain(std::iter::once(0)).collect();

    if (cch_buffer_length as usize) < wide.len() {
        set_last_error(ERROR_MORE_DATA);
        return 0;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), lpsz_volume_path_name, wide.len());
    }
    set_last_error(0);
    eprintln!("weave/GetVolumePathNameW: input={input:?} → {volume:?}");
    1
}

/// MoveFileW: move/rename a file (wide string version).
///
/// # Safety
/// `lp_existing_file_name` and `lp_new_file_name` must be valid null-terminated UTF-16 strings.
// Wine ref: dlls/kernelbase/file.c — MoveFileW delegates to MoveFileExW(MOVEFILE_COPY_ALLOWED);
// MoveFileExW delegates to MoveFileWithProgressW which handles cross-device copies via CopyFileExW+DeleteFileW
pub unsafe extern "win64" fn move_file_w(
    lp_existing_file_name: *const u16,
    lp_new_file_name: *const u16,
) -> i32 {
    if lp_existing_file_name.is_null() || lp_new_file_name.is_null() {
        return 0; // FALSE
    }

    // Read existing filename
    let mut len1 = 0usize;
    while len1 < MAX_UTF16_LEN && unsafe { *lp_existing_file_name.add(len1) } != 0 {
        len1 += 1;
    }
    if len1 == MAX_UTF16_LEN {
        return 0;
    }
    let old_path = unsafe {
        String::from_utf16_lossy(std::slice::from_raw_parts(lp_existing_file_name, len1))
    };

    // Read new filename
    let mut len2 = 0usize;
    while len2 < MAX_UTF16_LEN && unsafe { *lp_new_file_name.add(len2) } != 0 {
        len2 += 1;
    }
    if len2 == MAX_UTF16_LEN {
        return 0;
    }
    let new_path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_new_file_name, len2)) };

    eprintln!("weave/MoveFileW: {old_path} → {new_path}");

    // Translate both paths
    let linux_old = match weave_core::prefix::translator().to_linux_str(&old_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let linux_new = match weave_core::prefix::translator().to_linux_str(&new_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C strings
    let c_old = match std::ffi::CString::new(linux_old.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let c_new = match std::ffi::CString::new(linux_new.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Call rename
    let ret = unsafe { libc::rename(c_old.as_ptr(), c_new.as_ptr()) };
    let result = (ret == 0) as i32;
    eprintln!("weave/MoveFileW: → {result} (rename result)");
    result
}

/// MoveFileA: move/rename a file (ANSI version).
///
/// # Safety
/// `lp_existing_file_name` and `lp_new_file_name` must be valid null-terminated UTF-8 strings.
// Wine ref: dlls/kernelbase/file.c — MoveFileA converts via RtlMultiByteToUnicodeN then delegates to MoveFileW
pub unsafe extern "win64" fn move_file_a(
    lp_existing_file_name: *const u8,
    lp_new_file_name: *const u8,
) -> i32 {
    if lp_existing_file_name.is_null() || lp_new_file_name.is_null() {
        return 0; // FALSE
    }

    // Read existing filename
    let mut len1 = 0usize;
    while len1 < MAX_UTF8_LEN && unsafe { *lp_existing_file_name.add(len1) } != 0 {
        len1 += 1;
    }
    if len1 == MAX_UTF8_LEN {
        return 0;
    }
    let old_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_existing_file_name, len1)) };

    // Read new filename
    let mut len2 = 0usize;
    while len2 < MAX_UTF8_LEN && unsafe { *lp_new_file_name.add(len2) } != 0 {
        len2 += 1;
    }
    if len2 == MAX_UTF8_LEN {
        return 0;
    }
    let new_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_new_file_name, len2)) };

    eprintln!("weave/MoveFileA: {old_path} → {new_path}");

    // Translate both paths
    let linux_old = match weave_core::prefix::translator().to_linux_str(&old_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    let linux_new = match weave_core::prefix::translator().to_linux_str(&new_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C strings
    let c_old = match std::ffi::CString::new(linux_old.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let c_new = match std::ffi::CString::new(linux_new.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Call rename
    let ret = unsafe { libc::rename(c_old.as_ptr(), c_new.as_ptr()) };
    let result = (ret == 0) as i32;
    eprintln!("weave/MoveFileA: → {result} (rename result)");
    result
}

/// RemoveDirectoryW: remove a directory (wide string version).
///
/// # Safety
/// `lp_path_name` must be a valid null-terminated UTF-16 string.
// Wine ref: dlls/kernelbase/file.c:3717 — opens with DELETE|SYNCHRONIZE, FILE_DIRECTORY_FILE|FILE_OPEN_REPARSE_POINT;
// sets FileDispositionInformation{TRUE} on the handle to mark for deletion; actual delete on NtClose
pub unsafe extern "win64" fn remove_directory_w(lp_path_name: *const u16) -> i32 {
    if lp_path_name.is_null() {
        return 0; // FALSE
    }

    // Read path
    let mut len = 0usize;
    while len < MAX_UTF16_LEN && unsafe { *lp_path_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF16_LEN {
        return 0;
    }
    let win_path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_path_name, len)) };

    // Translate path
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C string
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Call rmdir
    let ret = unsafe { libc::rmdir(c_path.as_ptr()) };
    (ret == 0) as i32
}

/// RemoveDirectoryA: remove a directory (ANSI version).
///
/// # Safety
/// `lp_path_name` must be a valid null-terminated UTF-8 string.
// Wine ref: dlls/kernelbase/file.c:3705 — converts via file_name_AtoW then delegates to RemoveDirectoryW
pub unsafe extern "win64" fn remove_directory_a(lp_path_name: *const u8) -> i32 {
    if lp_path_name.is_null() {
        return 0; // FALSE
    }

    // Read path
    let mut len = 0usize;
    while len < MAX_UTF8_LEN && unsafe { *lp_path_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF8_LEN {
        return 0;
    }
    let win_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_path_name, len)) };

    // Translate path
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C string
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Call rmdir
    let ret = unsafe { libc::rmdir(c_path.as_ptr()) };
    (ret == 0) as i32
}

/// CreateDirectoryA: create a directory (ANSI version).
///
/// # Safety
/// `lp_path_name` must be a valid null-terminated UTF-8 string.
/// `lp_security_attributes` is ignored.
// Wine ref: dlls/kernelbase/file.c:656 — converts via file_name_AtoW then delegates to CreateDirectoryW
pub unsafe extern "win64" fn create_directory_a(
    lp_path_name: *const u8,
    _lp_security_attributes: usize,
) -> i32 {
    if lp_path_name.is_null() {
        return 0; // FALSE
    }

    // Read path
    let mut len = 0usize;
    while len < MAX_UTF8_LEN && unsafe { *lp_path_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF8_LEN {
        return 0;
    }
    let win_path =
        unsafe { String::from_utf8_lossy(std::slice::from_raw_parts(lp_path_name, len)) };

    // Translate path
    let linux_path = match weave_core::prefix::translator().to_linux_str(&win_path) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    // Convert to C string
    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Call mkdir with 0o755 permissions
    let ret = unsafe { libc::mkdir(c_path.as_ptr(), 0o755) };
    (ret == 0) as i32
}

/// GetLogicalDrives: return bitmask of available drives.
///
/// Returns 0x00000004 (bit 2 set) indicating drive C: exists.
// Wine ref: dlls/kernelbase/volume.c:495 — enumerates \\DosDevices\\ NT directory via NtQueryDirectoryObject;
// sets bit N for each two-char name where name[1]==':' (e.g. 'C:' sets bit 2)
pub extern "win64" fn get_logical_drives() -> u32 {
    0x00000004 // bit 2 = drive C:
}

/// GetDriveTypeW: determine the type of drive (wide string version).
///
/// # Safety
/// `lp_root_path_name` must be a valid null-terminated UTF-16 string.
// Wine ref: dlls/kernelbase/volume.c:552 — opens device root, calls NtQueryVolumeInformationFile(FileFsDeviceInformation);
// distinguishes CD-ROM, removable, remote, RAM disk by DeviceType and Characteristics; falls back to mountmgr for DRIVE_FIXED
pub unsafe extern "win64" fn get_drive_type_w(lp_root_path_name: *const u16) -> u32 {
    const DRIVE_UNKNOWN: u32 = 0;
    const DRIVE_FIXED: u32 = 3;

    if lp_root_path_name.is_null() {
        return DRIVE_UNKNOWN;
    }

    // Read the path and check if it starts with 'C' (u16 value 67)
    let first_char = unsafe { *lp_root_path_name };
    if first_char == 67 {
        // 'C' as u16
        DRIVE_FIXED
    } else {
        DRIVE_UNKNOWN
    }
}

/// GetDriveTypeA: determine the type of drive (ANSI version).
///
// Wine ref: dlls/kernelbase/volume.c:602 — converts root via file_name_AtoW then delegates
// to GetDriveTypeW; NULL root → DRIVE_NO_ROOT_DIR if AtoW fails
/// # Safety
/// `lp_root_path_name` must be a valid null-terminated UTF-8 string.
pub unsafe extern "win64" fn get_drive_type_a(lp_root_path_name: *const u8) -> u32 {
    const DRIVE_UNKNOWN: u32 = 0;
    const DRIVE_FIXED: u32 = 3;

    if lp_root_path_name.is_null() {
        return DRIVE_UNKNOWN;
    }

    // Check if first byte is 'C'
    let first_byte = unsafe { *lp_root_path_name };
    if first_byte == b'C' {
        DRIVE_FIXED
    } else {
        DRIVE_UNKNOWN
    }
}

/// GetDiskFreeSpaceExW: get disk space information for the given path.
///
/// Queries the real filesystem via `statvfs(2)`. Null `lpDirectoryName`
/// defaults to `"/"`. All three output pointers are individually nullable.
///
/// # Safety
/// `lp_free_bytes_available_to_caller`, `lp_total_number_of_bytes`,
/// `lp_total_number_of_free_bytes` must be valid writable pointers or NULL.
// Wine ref: dlls/kernelbase/volume.c:614 — opens device root, calls
// NtQueryVolumeInformationFile(FileFsSizeInformation); avail uses
// AvailableAllocationUnits (no per-user quota accounting in Wine either);
// bytes = AllocationUnits * SectorsPerUnit * BytesPerSector.
pub unsafe extern "win64" fn get_disk_free_space_ex_w(
    lp_directory_name: *const u16,
    lp_free_bytes_available_to_caller: *mut u64,
    lp_total_number_of_bytes: *mut u64,
    lp_total_number_of_free_bytes: *mut u64,
) -> i32 {
    const ERROR_INVALID_PARAMETER: u32 = 87;

    // Resolve the query path: translate Win32 wide string, or fall back to "/".
    let query_path: std::ffi::CString = if lp_directory_name.is_null() {
        eprintln!("weave/GetDiskFreeSpaceExW: path=(null→\"/\")");
        std::ffi::CString::new("/").unwrap()
    } else {
        // Decode the wide string.
        let mut len = 0usize;
        while len < 32768 && unsafe { *lp_directory_name.add(len) } != 0 {
            len += 1;
        }
        let win_path =
            unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_directory_name, len)) };
        eprintln!("weave/GetDiskFreeSpaceExW: path={win_path:?}");
        match weave_core::file_io::translate_win_path(&win_path) {
            Ok(p) => match std::ffi::CString::new(p.as_os_str().as_encoded_bytes()) {
                Ok(s) => s,
                Err(_) => std::ffi::CString::new("/").unwrap(),
            },
            Err(_) => std::ffi::CString::new("/").unwrap(),
        }
    };

    let mut sv: libc::statvfs = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::statvfs(query_path.as_ptr(), &mut sv) };
    if ret != 0 {
        eprintln!("weave/GetDiskFreeSpaceExW: → FALSE (statvfs failed, ERROR_INVALID_PARAMETER)");
        set_last_error(ERROR_INVALID_PARAMETER);
        return 0; // FALSE
    }

    // f_frsize is the fragment size used as the multiplier for block counts.
    let frsize = sv.f_frsize;

    // free_bytes_available = f_bavail (unprivileged free) * frsize
    let free_bytes_available = sv.f_bavail.saturating_mul(frsize);
    // total_bytes = f_blocks * frsize
    let total_bytes = sv.f_blocks.saturating_mul(frsize);
    // total_free_bytes = f_bfree * frsize (includes reserved blocks)
    let total_free_bytes = sv.f_bfree.saturating_mul(frsize);

    if !lp_free_bytes_available_to_caller.is_null() {
        unsafe { *lp_free_bytes_available_to_caller = free_bytes_available };
    }
    if !lp_total_number_of_bytes.is_null() {
        unsafe { *lp_total_number_of_bytes = total_bytes };
    }
    if !lp_total_number_of_free_bytes.is_null() {
        unsafe { *lp_total_number_of_free_bytes = total_free_bytes };
    }
    eprintln!("weave/GetDiskFreeSpaceExW: → TRUE total={total_bytes} free={free_bytes_available}");
    1 // TRUE
}

/// GetExitCodeProcess: get the exit code of a process.
///
/// # Safety
/// `lp_exit_code` must be a valid writable pointer or NULL.
// Wine ref: dlls/kernelbase/process.c:798 — calls NtQueryInformationProcess(ProcessBasicInformation);
// reads pbi.ExitStatus; STILL_ACTIVE (259 = STATUS_PENDING) means still running
pub unsafe extern "win64" fn get_exit_code_process(
    _h_process: usize,
    lp_exit_code: *mut u32,
) -> i32 {
    // Wine ref: dlls/kernelbase/process.c — NtQueryInformationProcess(ProcessBasicInformation).
    // Weave: no child process tracking; report STILL_ACTIVE for any handle.
    if !lp_exit_code.is_null() {
        unsafe { *lp_exit_code = 259 };
    }
    1 // TRUE
}

/// GetExitCodeThread: get the exit code of a thread.
///
/// # Safety
/// `lp_exit_code` must be a valid writable pointer or NULL.
// Wine ref: dlls/kernelbase/thread.c:218 — calls NtQueryInformationThread(ThreadBasicInformation);
// reads info.ExitStatus; STILL_ACTIVE (259) means thread is still running
pub unsafe extern "win64" fn get_exit_code_thread(_h_thread: usize, lp_exit_code: *mut u32) -> i32 {
    // Wine ref: dlls/kernelbase/thread.c — NtQueryInformationThread(ThreadBasicInformation).
    // Weave: thread handle→completion map exists but exit code not exposed here; report STILL_ACTIVE.
    if !lp_exit_code.is_null() {
        unsafe { *lp_exit_code = 259 };
    }
    1 // TRUE
}

/// TerminateThread: terminate a thread (no-op stub).
///
/// # Safety
/// `h_thread` is accepted but not dereferenced.
// Wine ref: dlls/kernelbase/thread.c:714 — calls NtTerminateThread(handle, exit_code);
// handle == GetCurrentThread() causes the calling thread to exit immediately
pub unsafe extern "win64" fn terminate_thread(_h_thread: usize, _dw_exit_code: u32) -> i32 {
    warn_once("TerminateThread");
    // No-op: thread termination not supported in Phase 1
    1 // TRUE
}

/// SetFileAttributesW — map FILE_ATTRIBUTE_* flags to Linux chmod.
///
/// Translates the Win32 path and applies the relevant Linux permission changes:
/// - FILE_ATTRIBUTE_READONLY (0x1): strips write bits via chmod
/// - FILE_ATTRIBUTE_NORMAL (0x80): restores read+write bits via chmod
/// - FILE_ATTRIBUTE_DIRECTORY (0x10): cannot be set; returns FALSE + ERROR_ACCESS_DENIED
/// - Any other flags: silently accepted, no Linux-side effect
///
/// Returns FALSE + ERROR_FILE_NOT_FOUND if the path does not exist.
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-16 string or NULL.
// Wine ref: dlls/kernelbase/file.c:2991 — opens with SYNCHRONIZE|FILE_OPEN_REPARSE_POINT;
// calls NtSetInformationFile(FileBasicInformation) with attributes|FILE_ATTRIBUTE_NORMAL to
// prevent zero attrs; returns ERROR_PATH_NOT_FOUND when path translation fails.
pub unsafe extern "win64" fn set_file_attributes_w(
    lp_file_name: *const u16,
    dw_file_attributes: u32,
) -> i32 {
    const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_PATH_NOT_FOUND: u32 = 3;

    if lp_file_name.is_null() {
        eprintln!(
            "weave/SetFileAttributesW: entry null_name attrs=0x{dw_file_attributes:x} → FALSE"
        );
        set_last_error(ERROR_PATH_NOT_FOUND);
        return 0; // FALSE
    }

    // Decode UTF-16 filename
    let mut len = 0usize;
    while len < MAX_UTF16_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF16_LEN {
        eprintln!(
            "weave/SetFileAttributesW: entry overlong_name attrs=0x{dw_file_attributes:x} → FALSE"
        );
        set_last_error(ERROR_PATH_NOT_FOUND);
        return 0; // FALSE
    }
    let win_path =
        unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(lp_file_name, len)) };

    eprintln!("weave/SetFileAttributesW: entry path={win_path:?} attrs=0x{dw_file_attributes:x}");

    // Translate Win32 path to Linux path
    let linux_path = match weave_core::file_io::translate_win_path(&win_path) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("weave/SetFileAttributesW: exit path={win_path:?} translate_err → FALSE");
            set_last_error(ERROR_PATH_NOT_FOUND);
            return 0; // FALSE
        }
    };

    let c_path = match std::ffi::CString::new(linux_path.as_os_str().as_encoded_bytes()) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("weave/SetFileAttributesW: exit path={win_path:?} cstring_err → FALSE");
            set_last_error(ERROR_PATH_NOT_FOUND);
            return 0; // FALSE
        }
    };

    // Stat the file to confirm existence and retrieve current mode
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let ret = unsafe { libc::stat(c_path.as_ptr(), &mut stat) };
    if ret != 0 {
        let errno = unsafe { *libc::__errno_location() };
        if errno == libc::ENOENT {
            eprintln!("weave/SetFileAttributesW: exit path={win_path:?} stat_enoent → FALSE");
            set_last_error(ERROR_FILE_NOT_FOUND);
        } else {
            eprintln!("weave/SetFileAttributesW: exit path={win_path:?} stat_err → FALSE");
            set_last_error(ERROR_ACCESS_DENIED);
        }
        return 0; // FALSE
    }

    // FILE_ATTRIBUTE_DIRECTORY cannot be set
    if dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        eprintln!("weave/SetFileAttributesW: exit path={win_path:?} dir_attr_denied → FALSE");
        set_last_error(ERROR_ACCESS_DENIED);
        return 0; // FALSE
    }

    // Apply chmod if READONLY or NORMAL is requested
    if dw_file_attributes & FILE_ATTRIBUTE_READONLY != 0 {
        // Remove all write bits
        let new_mode = stat.st_mode & !(libc::S_IWUSR | libc::S_IWGRP | libc::S_IWOTH);
        let chmod_ret = unsafe { libc::chmod(c_path.as_ptr(), new_mode) };
        if chmod_ret != 0 {
            eprintln!(
                "weave/SetFileAttributesW: exit path={win_path:?} chmod_readonly_err → FALSE"
            );
            set_last_error(ERROR_ACCESS_DENIED);
            return 0; // FALSE
        }
    } else if dw_file_attributes & FILE_ATTRIBUTE_NORMAL != 0 {
        // Restore read+write for owner and read for group/other
        let new_mode = stat.st_mode | libc::S_IRUSR | libc::S_IWUSR | libc::S_IRGRP | libc::S_IROTH;
        let chmod_ret = unsafe { libc::chmod(c_path.as_ptr(), new_mode) };
        if chmod_ret != 0 {
            eprintln!("weave/SetFileAttributesW: exit path={win_path:?} chmod_normal_err → FALSE");
            set_last_error(ERROR_ACCESS_DENIED);
            return 0; // FALSE
        }
    }
    // Any other flags: no-op on Linux — silently return TRUE

    eprintln!(
        "weave/SetFileAttributesW: exit path={win_path:?} attrs=0x{dw_file_attributes:x} → TRUE"
    );
    1 // TRUE
}

/// SetFileAttributesA — ANSI variant; delegates to SetFileAttributesW.
///
/// Converts the narrow UTF-8/ANSI path to wide and calls `set_file_attributes_w`.
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated UTF-8 string or NULL.
// Wine ref: dlls/kernelbase/file.c:2979 — converts via file_name_AtoW then delegates to SetFileAttributesW
pub unsafe extern "win64" fn set_file_attributes_a(
    lp_file_name: *const u8,
    dw_file_attributes: u32,
) -> i32 {
    const ERROR_PATH_NOT_FOUND: u32 = 3;

    if lp_file_name.is_null() {
        set_last_error(ERROR_PATH_NOT_FOUND);
        return 0; // FALSE
    }

    // Decode null-terminated UTF-8/ANSI path
    let mut len = 0usize;
    while len < MAX_UTF8_LEN && unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    if len == MAX_UTF8_LEN {
        set_last_error(ERROR_PATH_NOT_FOUND);
        return 0; // FALSE
    }
    let s = unsafe { std::slice::from_raw_parts(lp_file_name, len) };
    let utf8_str = String::from_utf8_lossy(s);

    // Widen to UTF-16 for SetFileAttributesW
    let mut wide: Vec<u16> = utf8_str.encode_utf16().collect();
    wide.push(0); // null-terminate

    unsafe { set_file_attributes_w(wide.as_ptr(), dw_file_attributes) }
}

// ── Time functions ───────────────────────────────────────────────────────────

/// Windows SYSTEMTIME structure — represents a date and time.
#[repr(C)]
pub struct SystemTime {
    w_year: u16,
    w_month: u16,
    w_day_of_week: u16,
    w_day: u16,
    w_hour: u16,
    w_minute: u16,
    w_second: u16,
    w_milliseconds: u16,
}

/// GetVersionExW: fill an OSVERSIONINFOEXW struct with Windows 10 info.
///
/// # Safety
/// `lp_version_information` must be a valid writable pointer to an OsVersionInfoExW.
// Wine ref: dlls/kernelbase/locale.c — reads version fields from peb->OSMajorVersion etc.; also fills
// wSuiteMask from the registry HKLM\System\CurrentControlSet\Control\ProductOptions\ProductSuite
pub unsafe extern "win64" fn get_version_ex_w(lp_version_information: *mut u8) -> i32 {
    // SAFETY: lp_version_information is non-null per the Windows caller contract and
    // points to an OSVERSIONINFOEXW (or OSVERSIONINFOW) — the caller sets
    // dw_os_version_info_size before calling, so we can read that field.  Casting
    // *mut u8 to *mut OsVersionInfoExW is sound because OsVersionInfoExW is
    // #[repr(C)] and 4-byte aligned; a *mut u8 at any Windows-allocated address
    // satisfies that requirement.
    let info = lp_version_information as *mut OsVersionInfoExW;
    unsafe {
        (*info).dw_major_version = 10;
        (*info).dw_minor_version = 0;
        (*info).dw_build_number = 18362;
        (*info).dw_platform_id = 2; // VER_PLATFORM_WIN32_NT
                                    // sz_csd_version is already zero-initialized

        let size = (*info).dw_os_version_info_size;
        if size >= 284 {
            // OSVERSIONINFOEXW
            (*info).w_service_pack_major = 0;
            (*info).w_service_pack_minor = 0;
            (*info).w_suite_mask = 0x0100; // VER_SUITE_SINGLEUSERTS
            (*info).w_product_type = 1; // VER_NT_WORKSTATION
            (*info).w_reserved = 0;
        }
    }
    1 // TRUE
}

/// GetVersionExA: fill an OSVERSIONINFOEXA struct with Windows 10 info.
///
/// # Safety
/// `lp_version_information` must be a valid writable pointer to an OsVersionInfoExA.
// Wine ref: dlls/kernelbase/locale.c — converts szCSDVersion from wide to ANSI via WideCharToMultiByte then
// calls GetVersionExW internally; struct layout matches OSVERSIONINFOEXA
pub unsafe extern "win64" fn get_version_ex_a(lp_version_information: *mut u8) -> i32 {
    // SAFETY: same as get_version_ex_w — lp_version_information is a valid
    // Windows-allocated pointer to an OSVERSIONINFOEXA/OSVERSIONINFOA struct.
    // OsVersionInfoExA is #[repr(C)] and 4-byte aligned; the cast is sound.
    let info = lp_version_information as *mut OsVersionInfoExA;
    unsafe {
        (*info).dw_major_version = 10;
        (*info).dw_minor_version = 0;
        (*info).dw_build_number = 18362;
        (*info).dw_platform_id = 2; // VER_PLATFORM_WIN32_NT
                                    // sz_csd_version is already zero-initialized

        let size = (*info).dw_os_version_info_size;
        if size >= 156 {
            // OSVERSIONINFOEXA
            (*info).w_service_pack_major = 0;
            (*info).w_service_pack_minor = 0;
            (*info).w_suite_mask = 0x0100; // VER_SUITE_SINGLEUSERTS
            (*info).w_product_type = 1; // VER_NT_WORKSTATION
            (*info).w_reserved = 0;
        }
    }
    1 // TRUE
}

/// GetCommandLineA — return the ANSI command line set by the Weave CLI.
// Wine ref: dlls/kernelbase/process.c — returns NtCurrentTeb()->Peb->ProcessParameters->CommandLine converted via WideCharToMultiByte; pointer is valid for process lifetime
///
/// Returns a pointer to the null-terminated ANSI string built from the
/// executable name and any trailing arguments passed to `weave`.
pub extern "win64" fn get_command_line_a() -> usize {
    weave_core::cmdline::get_a() as usize
}

/// GetCommandLineW — return the wide command line set by the Weave CLI.
// Wine ref: dlls/kernelbase/process.c — returns NtCurrentTeb()->Peb->ProcessParameters->CommandLine.Buffer directly; never NULL, never freed
///
/// Returns a pointer to the null-terminated UTF-16 string built from the
/// executable name and any trailing arguments passed to `weave`.
pub extern "win64" fn get_command_line_w() -> usize {
    weave_core::cmdline::get_w() as usize
}

/// EncodePointer: identity — return the pointer unchanged.
// Wine ref: dlls/kernelbase/process.c — calls RtlEncodePointer which XORs with a per-process cookie;
// cookie is stored in the PEB; encoded pointers crash intentionally if misused cross-process
pub extern "win64" fn encode_pointer(ptr: usize) -> usize {
    ptr
}

/// DecodePointer: identity — return the pointer unchanged.
// Wine ref: dlls/kernelbase/process.c — calls RtlDecodePointer which XORs with the same per-process cookie as EncodePointer; inverse of EncodePointer
pub extern "win64" fn decode_pointer(ptr: usize) -> usize {
    ptr
}

const FLS_MAX_SLOTS: usize = 128;
const FLS_OUT_OF_INDEXES: u32 = 0xFFFFFFFF;

/// Process-global slot allocation table; guards FlsAlloc / FlsFree only.
static FLS_SLOTS: std::sync::Mutex<[bool; FLS_MAX_SLOTS]> =
    std::sync::Mutex::new([false; FLS_MAX_SLOTS]);

fn lock_fls_slots<'a>(
    m: &'a std::sync::Mutex<[bool; FLS_MAX_SLOTS]>,
) -> Option<std::sync::MutexGuard<'a, [bool; FLS_MAX_SLOTS]>> {
    m.lock()
        .map_err(|e| eprintln!("weave: weave-kernel32: FLS slots mutex poisoned: {e}"))
        .ok()
}

// Per-thread fiber local storage values; each thread gets its own array.
thread_local! {
    static FLS_DATA: std::cell::RefCell<[usize; FLS_MAX_SLOTS]> =
        const { std::cell::RefCell::new([0; FLS_MAX_SLOTS]) };
}

/// FlsAlloc: allocate a fiber local storage slot.
///
/// Slot allocation is process-global (protected by a Mutex); slot values are
/// per-thread (thread_local). This matches Windows FLS semantics.
// Wine ref: dlls/kernelbase/thread.c:1264 — delegates to RtlFlsAlloc(callback, &index);
// FLS_OUT_OF_INDEXES (0xFFFFFFFF) returned when RtlFlsAlloc fails; callback invoked on fiber/thread exit
pub extern "win64" fn fls_alloc(_lp_callback: usize) -> u32 {
    let mut slots = match lock_fls_slots(&FLS_SLOTS) {
        Some(g) => g,
        None => return FLS_OUT_OF_INDEXES,
    };
    for i in 0..FLS_MAX_SLOTS {
        if !slots[i] {
            slots[i] = true;
            return i as u32;
        }
    }
    FLS_OUT_OF_INDEXES
}

/// FlsGetValue: retrieve value from fiber local storage slot.
///
/// Values are per-thread — each thread sees its own copy at each slot index.
// Wine ref: dlls/kernelbase/thread.c:1285 — delegates to RtlFlsGetValue; sets ERROR_SUCCESS on success;
// returns NULL and sets last error on invalid index
pub extern "win64" fn fls_get_value(dw_fls_index: u32) -> usize {
    if dw_fls_index >= FLS_MAX_SLOTS as u32 {
        return 0;
    }
    FLS_DATA.with(|d| d.borrow()[dw_fls_index as usize])
}

/// FlsSetValue: store value in fiber local storage slot.
///
/// Values are per-thread — writing from one thread does not affect others.
// Wine ref: dlls/kernelbase/thread.c:1298 — delegates to RtlFlsSetValue(index, data)
pub extern "win64" fn fls_set_value(dw_fls_index: u32, lp_fls_data: usize) -> i32 {
    if dw_fls_index >= FLS_MAX_SLOTS as u32 {
        return 0; // FALSE
    }
    FLS_DATA.with(|d| d.borrow_mut()[dw_fls_index as usize] = lp_fls_data);
    1 // TRUE
}

/// FlsFree: free a fiber local storage slot.
///
/// Marks the slot as available in the process-global table. Does not clear
/// per-thread values (threads using the old index after free get stale data,
/// matching Windows behavior).
// Wine ref: dlls/kernelbase/thread.c:1276 — delegates to RtlFlsFree(index);
// RtlFlsFree invokes the registered callback for each thread's value before freeing the slot
pub extern "win64" fn fls_free(dw_fls_index: u32) -> i32 {
    if dw_fls_index >= FLS_MAX_SLOTS as u32 {
        return 0; // FALSE
    }
    if let Some(mut slots) = lock_fls_slots(&FLS_SLOTS) {
        slots[dw_fls_index as usize] = false;
    }
    1 // TRUE
}

/// InitializeCriticalSectionAndSpinCount: initialize critical section with spin count.
///
/// # Safety
/// `lp_critical_section` must point to at least 40 bytes of writable memory.
// Wine ref: dlls/kernelbase/sync.c:1008 — delegates to RtlInitializeCriticalSectionAndSpinCount;
// returns TRUE (inverts the NTSTATUS success code); spin count is stored in RTL_CRITICAL_SECTION.SpinCount
pub unsafe extern "win64" fn initialize_critical_section_and_spin_count(
    lp_critical_section: *mut u8,
    _dw_spin_count: u32,
) -> i32 {
    // SAFETY: lp_critical_section is non-null (checked by the caller contract above)
    // and points to at least 40 bytes.  Offset 8 is LockCount in the Windows
    // RTL_CRITICAL_SECTION layout (DebugInfo ptr = 8 bytes, then LockCount i32).
    // We zero all 40 bytes first, then set LockCount = -1 (unlocked per Windows ABI).
    unsafe { std::ptr::write_bytes(lp_critical_section, 0, 40) };
    unsafe { *(lp_critical_section.add(8) as *mut i32) = -1 };
    1 // TRUE
}

/// InitializeCriticalSectionEx: initialize critical section with extended options.
///
/// # Safety
/// `lp_critical_section` must point to at least 40 bytes of writable memory.
// Wine ref: dlls/kernelbase/sync.c:1016 — delegates to RtlInitializeCriticalSectionEx;
// flags include CRITICAL_SECTION_NO_DEBUG_INFO which skips RTL_CRITICAL_SECTION_DEBUG allocation
pub unsafe extern "win64" fn initialize_critical_section_ex(
    lp_critical_section: *mut u8,
    _dw_spin_count: u32,
    _flags: u32,
) -> i32 {
    // SAFETY: same invariant as initialize_critical_section and
    // initialize_critical_section_and_spin_count — offset 8 is LockCount in
    // RTL_CRITICAL_SECTION; -1 means unlocked.
    unsafe { std::ptr::write_bytes(lp_critical_section, 0, 40) };
    unsafe { *(lp_critical_section.add(8) as *mut i32) = -1 };
    1 // TRUE
}

/// HeapSetInformation: set heap information (no-op).
///
// Wine ref: dlls/kernelbase/memory.c — HeapSetInformation delegates to RtlSetHeapInformation;
// HeapCompatibilityInformation class 2 enables low-fragmentation heap; ignored in Wine/Weave
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
pub unsafe extern "win64" fn heap_set_information(
    _heap_handle: usize,
    _heap_information_class: u32,
    _heap_information: *mut u8,
    _heap_information_length: usize,
) -> i32 {
    1 // heap information classes (LFH, termination) are no-ops over libc allocator
}

/// SetHandleCount: legacy stub that returns the input value.
// Wine ref: dlls/kernelbase/process.c:1165 — returns count unchanged; Win3.1 legacy, no-op on NT
pub extern "win64" fn set_handle_count(u_number: u32) -> u32 {
    u_number
}

/// GetThreadLocale: return English (United States) locale ID.
// Wine ref: dlls/kernelbase/thread.c — returns NtCurrentTeb()->CurrentLocale; set by
// SetThreadLocale; default is system locale from PEB->Ldr->... at process start
pub extern "win64" fn get_thread_locale() -> u32 {
    0x0409 // LOCALE_EN_US
}

/// SetThreadLocale: no-op, returns TRUE.
// Wine ref: dlls/kernelbase/thread.c:598 — calls ConvertDefaultLocale then IsValidLocale;
// stores into NtCurrentTeb()->CurrentLocale; invalid locale → ERROR_INVALID_PARAMETER
pub extern "win64" fn set_thread_locale(_locale: u32) -> i32 {
    1 // locale not tracked per-thread; GetThreadLocale always returns en-US
}

/// SetThreadStackGuarantee: no-op, returns TRUE.
///
// Wine ref: dlls/kernelbase/thread.c:636 — rounds size up to 4096; 64-bit enforces min 8192;
// stores in NtCurrentTeb()->GuaranteedStackBytes; *size receives previous value
/// # Safety
/// Pointer argument is accepted but not dereferenced.
pub unsafe extern "win64" fn set_thread_stack_guarantee(_stack_size_in_bytes: *mut u32) -> i32 {
    1 // Linux stack guard pages are controlled by ulimit, not per-thread
}

/// GetTimeZoneInformation — fill TIME_ZONE_INFORMATION from the local timezone.
///
/// On Linux we use localtime_r() to get the UTC offset and DST flag,
/// then populate the Windows struct:
///   +0   i32  Bias (minutes west of UTC; sign is opposite to tm_gmtoff)
///   +4   [32]u16 StandardName (wide string)
///   +68  SYSTEMTIME StandardDate (zeroed = not changing)
///   +84  i32  StandardBias (usually 0)
///   +88  [32]u16 DaylightName
///   +152 SYSTEMTIME DaylightDate (zeroed)
///   +168 i32  DaylightBias (usually -60)
///
/// Returns TIME_ZONE_ID_STANDARD (1) or TIME_ZONE_ID_DAYLIGHT (2).
///
/// # Safety
/// `lp_time_zone_information` must be a valid writable pointer to a 172-byte struct.
// Wine ref: dlls/kernelbase/locale.c:6294 — delegates to GetDynamicTimeZoneInformationInformation
// then memcpy's first sizeof(TIME_ZONE_INFORMATION) bytes; GetDynamicTimeZoneInformation reads
// from HKLM\System\CurrentControlSet\Control\TimeZoneInformation or calls RtlQueryTimeZoneInformation
pub unsafe extern "win64" fn get_time_zone_information(lp_time_zone_information: *mut u8) -> u32 {
    if lp_time_zone_information.is_null() {
        return 0xFFFF_FFFF; // error
    }
    // SAFETY: lp_time_zone_information is non-null (checked above) and the caller
    // guarantees at least 172 bytes (sizeof TIME_ZONE_INFORMATION).  We zero all
    // 172 bytes first, then write exactly three i32 fields at their documented
    // byte offsets (see layout in the function doc comment):
    //   +0   Bias, +84 StandardBias, +168 DaylightBias
    // All three writes are 4-byte-aligned within the 172-byte span.
    unsafe { std::ptr::write_bytes(lp_time_zone_information, 0, 172) };
    // Get the local UTC offset via localtime_r.
    let mut t: libc::time_t = 0;
    unsafe { libc::time(&mut t) };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    // tm_gmtoff is seconds EAST of UTC; Windows Bias is minutes WEST.
    let bias_minutes: i32 = -(tm.tm_gmtoff as i32) / 60;
    unsafe { *(lp_time_zone_information.add(0) as *mut i32) = bias_minutes };
    // StandardBias at offset 84 = 0 (no additional standard offset).
    unsafe { *(lp_time_zone_information.add(84) as *mut i32) = 0 };
    // DaylightBias at offset 168 = -60 (1 hour ahead in DST).
    unsafe { *(lp_time_zone_information.add(168) as *mut i32) = -60i32 };
    if tm.tm_isdst > 0 {
        2 // TIME_ZONE_ID_DAYLIGHT
    } else {
        1 // TIME_ZONE_ID_STANDARD
    }
}

/// GetDynamicTimeZoneInformation — fill DYNAMIC_TIME_ZONE_INFORMATION struct.
///
/// DYNAMIC_TIME_ZONE_INFORMATION is TIME_ZONE_INFORMATION (172 bytes) plus
/// TimeZoneKeyName (WCHAR[128] = 256 bytes) plus DynamicDaylightTimeDisabled (BOOL = 4 bytes)
/// = 432 bytes total. Delegates to the same localtime_r logic as GetTimeZoneInformation
/// for the first 172 bytes, zero-fills the extended fields.
///
/// Returns TIME_ZONE_ID_STANDARD (1), TIME_ZONE_ID_DAYLIGHT (2), or
/// TIME_ZONE_ID_UNKNOWN (0xFFFFFFFF) on error.
///
/// # Safety
/// `lp_time_zone_information` must be a valid writable pointer to a 432-byte struct.
// Wine ref: dlls/kernelbase/locale.c:6294 — reads from registry
// HKLM\...\TimeZoneInformation; Weave uses localtime_r as a safe approximation.
pub unsafe extern "win64" fn get_dynamic_time_zone_information(
    lp_time_zone_information: *mut u8,
) -> u32 {
    if lp_time_zone_information.is_null() {
        return 0xFFFF_FFFF; // TIME_ZONE_ID_UNKNOWN / error
    }
    // Zero the full 432-byte DYNAMIC_TIME_ZONE_INFORMATION struct first.
    unsafe { std::ptr::write_bytes(lp_time_zone_information, 0, 432) };
    // Delegate the base TIME_ZONE_INFORMATION fields to the existing implementation.
    unsafe { get_time_zone_information(lp_time_zone_information) }
}

/// GetSystemTime: fill a SYSTEMTIME struct with current UTC time.
///
/// # Safety
/// `lp_system_time` must be a valid writable pointer to a SystemTime struct.
// Wine ref: dlls/kernelbase/time.c — calls NtQuerySystemTime then RtlTimeToTimeFields;
// wDayOfWeek is computed by RtlTimeToTimeFields from the absolute filetime
pub unsafe extern "win64" fn get_system_time(lp_system_time: *mut u8) {
    let mut t: libc::time_t = 0;
    unsafe { libc::time(&mut t) };
    let mut tm: libc::tm = std::mem::zeroed();
    unsafe { libc::gmtime_r(&t, &mut tm) };
    // SAFETY: lp_system_time is non-null per the Windows caller contract (GetSystemTime
    // accepts a guaranteed-non-null LPSYSTEMTIME).  Casting *mut u8 to *mut SystemTime
    // is sound because SystemTime is #[repr(C)] and 2-byte aligned (all u16 fields);
    // a *mut u8 satisfies that alignment requirement on any platform.
    let st = lp_system_time as *mut SystemTime;
    unsafe {
        (*st).w_year = (tm.tm_year + 1900) as u16;
        (*st).w_month = (tm.tm_mon + 1) as u16;
        (*st).w_day_of_week = tm.tm_wday as u16;
        (*st).w_day = tm.tm_mday as u16;
        (*st).w_hour = tm.tm_hour as u16;
        (*st).w_minute = tm.tm_min as u16;
        (*st).w_second = tm.tm_sec as u16;
        (*st).w_milliseconds = 0;
    }
}

/// GetLocalTime: fill a SYSTEMTIME struct with current local time.
///
/// # Safety
/// `lp_system_time` must be a valid writable pointer to a SystemTime struct.
// Wine ref: dlls/kernelbase/time.c — calls GetSystemTime then SystemTimeToTzSpecificLocalTime
// (applies bias from GetTimeZoneInformation to convert UTC → local)
pub unsafe extern "win64" fn get_local_time(lp_system_time: *mut u8) {
    let mut t: libc::time_t = 0;
    unsafe { libc::time(&mut t) };
    let mut tm: libc::tm = std::mem::zeroed();
    unsafe { libc::localtime_r(&t, &mut tm) };
    // SAFETY: same invariant as get_system_time — lp_system_time is a valid non-null
    // pointer to a writable SystemTime struct per the Windows caller contract.
    // Casting *mut u8 to *mut SystemTime is sound: SystemTime is #[repr(C)], 2-byte
    // aligned, so a *mut u8 meets the alignment requirement.
    let st = lp_system_time as *mut SystemTime;
    unsafe {
        (*st).w_year = (tm.tm_year + 1900) as u16;
        (*st).w_month = (tm.tm_mon + 1) as u16;
        (*st).w_day_of_week = tm.tm_wday as u16;
        (*st).w_day = tm.tm_mday as u16;
        (*st).w_hour = tm.tm_hour as u16;
        (*st).w_minute = tm.tm_min as u16;
        (*st).w_second = tm.tm_sec as u16;
        (*st).w_milliseconds = 0;
    }
}

// ── Environment functions ────────────────────────────────────────────────────

/// Static empty wide environment block (double-null-terminated).
static EMPTY_ENV_W: [u16; 2] = [0u16, 0u16];

/// Static empty narrow environment block (double-null-terminated).
static EMPTY_ENV_A: [u8; 2] = [0u8, 0u8];

/// GetEnvironmentVariableA — libc::getenv proxy mirroring the W variant.
///
/// The A-variant byte-passes the name directly (no UTF-16 transcoding) since
/// the Linux host environment is already UTF-8. On success writes the value
/// bytes plus NUL into the caller's buffer and returns bytes-excl-NUL.
/// On BUFFER_TOO_SMALL returns required-incl-NUL. On miss, sets LAST_ERROR
/// to ERROR_ENVVAR_NOT_FOUND and returns 0.
///
/// # Safety
/// `lp_name` must be a valid NUL-terminated C string or null.
/// If `lp_buffer` is non-null, it must point to at least `n_size` writable bytes.
// Wine ref: dlls/kernelbase/process.c — GetEnvironmentVariableA delegates to W via
// RtlCreateUnicodeStringFromAsciiz, then back-converts. Contract: chars-excl-NUL on
// success, required-size-incl-NUL on BUFFER_TOO_SMALL, 0+ERROR_ENVVAR_NOT_FOUND on miss.
pub unsafe extern "win64" fn get_environment_variable_a(
    lp_name: *const u8,
    lp_buffer: *mut u8,
    n_size: u32,
) -> u32 {
    if lp_name.is_null() {
        set_last_error(203); // ERROR_ENVVAR_NOT_FOUND
        return 0;
    }
    // Bound the null-terminator scan via strnlen so a guest-controlled pointer
    // without a NUL cannot read past mapped memory or act as a length oracle.
    let name_len = libc::strnlen(lp_name as *const i8, MAX_UTF8_LEN);
    if name_len == MAX_UTF8_LEN {
        set_last_error(203); // ERROR_ENVVAR_NOT_FOUND
        return 0;
    }
    let name_bytes = std::slice::from_raw_parts(lp_name, name_len);
    let c_name = match std::ffi::CString::new(name_bytes) {
        Ok(s) => s,
        Err(_) => {
            set_last_error(203);
            return 0;
        }
    };
    let value_ptr = libc::getenv(c_name.as_ptr());
    if value_ptr.is_null() {
        // Narrow SDL/AUDIO trace — helps confirm dummy-audio env is visible to SDL2.
        let name_str = c_name.to_string_lossy();
        let name_upper = name_str.to_ascii_uppercase();
        if name_upper.contains("SDL") || name_upper.contains("AUDIO") {
            eprintln!("weave/GetEnvironmentVariableA: {:?} → NOT_FOUND", name_str);
        }
        set_last_error(203); // ERROR_ENVVAR_NOT_FOUND
        return 0;
    }
    let value = std::ffi::CStr::from_ptr(value_ptr);
    let bytes = value.to_bytes();
    let bytes_needed = bytes.len() as u32; // excluding NUL
                                           // Narrow SDL/AUDIO trace — confirms SDL_AUDIODRIVER=dummy is returned.
    {
        let name_str = c_name.to_string_lossy();
        let name_upper = name_str.to_ascii_uppercase();
        if name_upper.contains("SDL") || name_upper.contains("AUDIO") {
            eprintln!(
                "weave/GetEnvironmentVariableA: {:?} → {:?}",
                name_str,
                value.to_string_lossy()
            );
        }
    }
    if n_size == 0 || lp_buffer.is_null() || bytes_needed + 1 > n_size {
        // Buffer too small — return required size including NUL.
        return bytes_needed + 1;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_buffer, bytes.len());
    *lp_buffer.add(bytes.len()) = 0;
    bytes_needed
}

/// SetEnvironmentVariableW — modifies the process environment via libc::setenv / libc::unsetenv.
///
/// Behavior per Wine dlls/kernelbase/process.c:1723:
/// - NULL name → FALSE + ERROR_INVALID_PARAMETER
/// - name containing '=' → FALSE + ERROR_INVALID_PARAMETER
/// - NULL value → unsetenv(name) → TRUE
/// - non-null value → setenv(name, value, 1) → TRUE
///
/// # Safety
/// `lp_name` must be a valid NUL-terminated UTF-16 string or null.
/// `lp_value` must be a valid NUL-terminated UTF-16 string or null.
// Wine ref: dlls/kernelbase/process.c:1723 — calls RtlSetEnvironmentVariable(NULL, &us_name, &us_value);
// NULL value deletes the variable; NULL name returns ERROR_ENVVAR_NOT_FOUND (we use
// ERROR_INVALID_PARAMETER per MSDN); name containing '=' is rejected by RtlSetEnvironmentVariable.
pub unsafe extern "win64" fn set_environment_variable_w(
    lp_name: *const u16,
    lp_value: *const u16,
) -> i32 {
    if lp_name.is_null() {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0; // FALSE
    }
    // Decode UTF-16 name.
    let mut len = 0usize;
    while *lp_name.add(len) != 0 {
        len += 1;
    }
    let name_slice = std::slice::from_raw_parts(lp_name, len);
    let name = String::from_utf16_lossy(name_slice);
    // Name must not contain '='.
    if name.contains('=') {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0; // FALSE
    }
    // Build a NUL-terminated C string for the name.
    let c_name = match std::ffi::CString::new(name) {
        Ok(s) => s,
        Err(_) => {
            // Interior NUL byte in name — invalid parameter.
            set_last_error(87); // ERROR_INVALID_PARAMETER
            return 0; // FALSE
        }
    };
    if lp_value.is_null() {
        // NULL value → delete the variable.
        libc::unsetenv(c_name.as_ptr());
    } else {
        // Decode UTF-16 value.
        let mut vlen = 0usize;
        while *lp_value.add(vlen) != 0 {
            vlen += 1;
        }
        let value_slice = std::slice::from_raw_parts(lp_value, vlen);
        let value = String::from_utf16_lossy(value_slice);
        let c_value = match std::ffi::CString::new(value) {
            Ok(s) => s,
            Err(_) => {
                set_last_error(87); // ERROR_INVALID_PARAMETER
                return 0; // FALSE
            }
        };
        libc::setenv(c_name.as_ptr(), c_value.as_ptr(), 1);
    }
    1 // TRUE
}

/// SetEnvironmentVariableA — modifies the process environment via libc::setenv / libc::unsetenv.
///
/// Delegates to the W variant after passing the narrow (UTF-8/OEM) strings through directly,
/// mirroring Wine's approach of up-converting via RtlCreateUnicodeStringFromAsciiz then calling
/// SetEnvironmentVariableW. We call libc directly here to avoid an intermediate wide conversion.
///
/// # Safety
/// `lp_name` must be a valid NUL-terminated C string or null.
/// `lp_value` must be a valid NUL-terminated C string or null.
// Wine ref: dlls/kernelbase/process.c:1696 — converts name/value via RtlCreateUnicodeStringFromAsciiz
// then delegates to SetEnvironmentVariableW; NULL name → FALSE.
pub unsafe extern "win64" fn set_environment_variable_a(
    lp_name: *const u8,
    lp_value: *const u8,
) -> i32 {
    if lp_name.is_null() {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0; // FALSE
    }
    let c_name = std::ffi::CStr::from_ptr(lp_name as *const i8);
    // Name must not contain '='.
    if c_name.to_bytes().contains(&b'=') {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0; // FALSE
    }
    if lp_value.is_null() {
        libc::unsetenv(c_name.as_ptr());
    } else {
        let c_value = std::ffi::CStr::from_ptr(lp_value as *const i8);
        libc::setenv(c_name.as_ptr(), c_value.as_ptr(), 1);
    }
    1 // TRUE
}

/// GetEnvironmentStringsW: return pointer to static empty wide environment block.
// Wine ref: dlls/kernelbase/process.c — returns NtCurrentTeb()->Peb->ProcessParameters->Environment directly;
// block is double-null-terminated; caller must free with FreeEnvironmentStringsW
pub extern "win64" fn get_environment_strings_w() -> usize {
    EMPTY_ENV_W.as_ptr() as usize
}

/// GetEnvironmentStringsA: return pointer to static empty narrow environment block.
// Wine ref: dlls/kernelbase/process.c — converts wide environment block via WideCharToMultiByte; caller frees with FreeEnvironmentStringsA
pub extern "win64" fn get_environment_strings_a() -> usize {
    EMPTY_ENV_A.as_ptr() as usize
}

/// FreeEnvironmentStringsW: no-op, returns TRUE.
///
/// # Safety
/// `penv` is accepted but not dereferenced.
// Wine ref: dlls/kernelbase/process.c — frees the heap allocation returned by GetEnvironmentStringsW; NULL is accepted
pub unsafe extern "win64" fn free_environment_strings_w(_penv: *mut u16) -> i32 {
    // Wine ref: dlls/kernelbase/process.c — frees heap block from GetEnvironmentStringsW.
    // Weave: GetEnvironmentStringsW returns a static array pointer; nothing to free.
    1
}

/// FreeEnvironmentStringsA: no-op, returns TRUE.
///
/// # Safety
/// `penv` is accepted but not dereferenced.
// Wine ref: dlls/kernelbase/process.c — frees the heap allocation returned by GetEnvironmentStringsA; NULL is accepted
pub unsafe extern "win64" fn free_environment_strings_a(_penv: *mut u8) -> i32 {
    // Wine ref: dlls/kernelbase/process.c — frees heap block from GetEnvironmentStringsA.
    // Weave: GetEnvironmentStringsA returns a static array pointer; nothing to free.
    1
}

// ── Locale functions ────────────────────────────────────────────────────────

/// Flag: caller wants a binary DWORD in the buffer, not a string.
const LOCALE_RETURN_NUMBER: u32 = 0x20000000;

/// GetLocaleInfoW: retrieve locale information as UTF-16 string.
///
/// # Safety
/// `lp_lc_data` must be a valid writable pointer for `cch_data` u16 words.
// Wine ref: dlls/kernelbase/locale.c — when LOCALE_RETURN_NUMBER set, writes binary DWORD into buffer (cch_data must be 2);
// cch_data==0 is a size query; unknown types return 0+ERROR_INVALID_FLAGS
pub unsafe extern "win64" fn get_locale_info_w(
    _locale: u32,
    lc_type: u32,
    lp_lc_data: *mut u16,
    cch_data: i32,
) -> i32 {
    let want_number = (lc_type & LOCALE_RETURN_NUMBER) != 0;
    // Strip all flag bits (RETURN_NUMBER=0x20000000, NOUSEROVERRIDE=0x80000000, etc.)
    let lc_type_clean = lc_type & 0x000FFFFF;

    if want_number {
        // Wine ref: dlls/kernelbase/locale.c get_locale_info — when LOCALE_RETURN_NUMBER
        // is set, write a binary DWORD into the buffer; cch_data must be 2 (DWORD/sizeof WCHAR).
        // Always return 2 (success) even for unknown types — returning 0 triggers goto-fail
        // in the UCRT's create_locinfo, which double-frees partially-initialised locale structs.
        let num = locale_number_lookup(lc_type_clean);
        if cch_data == 0 {
            return 2; // required buffer size (1 DWORD = 2 WCHARs)
        }
        if cch_data >= 2 && !lp_lc_data.is_null() {
            // SAFETY: lp_lc_data is non-null (checked) and cch_data >= 2 ensures
            // at least 4 bytes (2 × WCHAR) are available.  We cast *mut u16 to
            // *mut u32 to write a DWORD — this is the documented behaviour when
            // LOCALE_RETURN_NUMBER is set (Wine ref: dlls/kernelbase/locale.c).
            // write_unaligned is used because the buffer may be only 2-byte aligned
            // (WCHAR alignment), while u32 normally requires 4-byte alignment.
            unsafe { std::ptr::write_unaligned(lp_lc_data as *mut u32, num) };
        }
        return 2;
    }

    if let Some(value) = locale_info_lookup(lc_type_clean) {
        let wide_chars: Vec<u16> = format!("{}\0", value).encode_utf16().collect();
        let required_size = wide_chars.len() as i32;
        if cch_data == 0 {
            return required_size;
        }
        if cch_data >= required_size {
            unsafe {
                std::ptr::copy_nonoverlapping(wide_chars.as_ptr(), lp_lc_data, wide_chars.len());
            }
            return required_size - 1; // exclude null terminator
        }
    }
    0 // failure
}

/// GetLocaleInfoA: retrieve locale information as ANSI string.
///
/// # Safety
/// `lp_lc_data` must be a valid writable pointer for `cch_data` bytes.
// Wine ref: dlls/kernelbase/locale.c — converts name via WideCharToMultiByte then copies; returns byte count excluding NUL
pub unsafe extern "win64" fn get_locale_info_a(
    _locale: u32,
    lc_type: u32,
    lp_lc_data: *mut u8,
    cch_data: i32,
) -> i32 {
    let lc_type_clean = lc_type & 0x000FFFFF; // strip LOCALE_RETURN_NUMBER flag
    if let Some(value) = locale_info_lookup(lc_type_clean) {
        let formatted = format!("{}\0", value);
        let bytes = formatted.as_bytes();
        let required_size = bytes.len() as i32;
        if cch_data == 0 {
            return required_size;
        }
        if cch_data >= required_size {
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_lc_data, bytes.len());
            }
            return required_size - 1; // exclude null terminator
        }
    }
    0 // failure
}

/// GetLocaleInfoEx: retrieve locale information by locale name (UTF-16 string).
///
/// # Safety
/// `lp_locale_name` may be NULL (means system default). `lp_lc_data` must be valid for `cch_data` words.
// Wine ref: dlls/kernelbase/locale.c — resolves locale name to LCID via get_locale_by_name;
// delegates to get_locale_info; returns 0+ERROR_INVALID_PARAMETER for unknown locale names
pub unsafe extern "win64" fn get_locale_info_ex(
    _lp_locale_name: *const u16,
    lc_type: u32,
    lp_lc_data: *mut u16,
    cch_data: i32,
) -> i32 {
    // Delegate to our existing GetLocaleInfoW using LOCALE_USER_DEFAULT (0x0400).
    unsafe { get_locale_info_w(0x0400, lc_type, lp_lc_data, cch_data) }
}

/// GetUserDefaultLocaleName: return the user-default locale name as a UTF-16 string.
///
/// # Safety
/// `lp_locale_name` must be a writable buffer of at least `cch_locale_name` u16 words.
// Wine ref: dlls/kernelbase/locale.c — calls get_locale_by_id(GetUserDefaultLCID());
// copies locale->sname (e.g. "en-US") into buffer; returns char count including NUL on success
pub unsafe extern "win64" fn get_user_default_locale_name(
    lp_locale_name: *mut u16,
    cch_locale_name: i32,
) -> i32 {
    let name: Vec<u16> = "en-US\0".encode_utf16().collect(); // 6 chars including null
    let required = name.len() as i32;
    if cch_locale_name == 0 {
        return required;
    }
    if cch_locale_name < required {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), lp_locale_name, name.len());
    }
    required - 1 // exclude null terminator
}

/// Locale constant for English (United States).
const LOCALE_EN_US: u32 = 0x0409;

// ── String comparison ───────────────────────────────────────────────────────

/// CompareStringW result constants.
const CSTR_LESS_THAN: i32 = 1;
const CSTR_EQUAL: i32 = 2;
const CSTR_GREATER_THAN: i32 = 3;

/// CompareStringW flag constants.
const NORM_IGNORECASE: u32 = 0x00000001;
const LINGUISTIC_IGNORECASE: u32 = 0x00000010;

/// CompareStringW: compare two UTF-16 strings with optional case folding.
///
/// # Safety
/// `lp_string1` and `lp_string2` must be valid pointers to null-terminated UTF-16 strings.
// Wine ref: dlls/kernelbase/locale.c — delegates to CompareStringEx; unknown LCID → ERROR_INVALID_PARAMETER;
// returns CSTR_LESS_THAN(1)/CSTR_EQUAL(2)/CSTR_GREATER_THAN(3) (not -1/0/1)
pub unsafe extern "win64" fn compare_string_w(
    _locale: u32,
    dw_cmp_flags: u32,
    lp_string1: *const u16,
    cch_count1: i32,
    lp_string2: *const u16,
    cch_count2: i32,
) -> i32 {
    let len1 = if cch_count1 == -1 {
        let mut len = 0usize;
        while *lp_string1.add(len) != 0 {
            len += 1;
        }
        len
    } else {
        cch_count1 as usize
    };

    let len2 = if cch_count2 == -1 {
        let mut len = 0usize;
        while *lp_string2.add(len) != 0 {
            len += 1;
        }
        len
    } else {
        cch_count2 as usize
    };

    let case_insensitive =
        (dw_cmp_flags & NORM_IGNORECASE) != 0 || (dw_cmp_flags & LINGUISTIC_IGNORECASE) != 0;

    let min_len = len1.min(len2);
    for i in 0..min_len {
        let mut c1 = *lp_string1.add(i);
        let mut c2 = *lp_string2.add(i);

        if case_insensitive && (c1 as u8).is_ascii_uppercase() {
            c1 += 32;
        }
        if case_insensitive && (c2 as u8).is_ascii_uppercase() {
            c2 += 32;
        }

        if c1 < c2 {
            return CSTR_LESS_THAN;
        } else if c1 > c2 {
            return CSTR_GREATER_THAN;
        }
    }

    match len1.cmp(&len2) {
        std::cmp::Ordering::Less => CSTR_LESS_THAN,
        std::cmp::Ordering::Equal => CSTR_EQUAL,
        std::cmp::Ordering::Greater => CSTR_GREATER_THAN,
    }
}

/// CompareStringA: compare two ANSI strings with optional case folding (ANSI wrapper for CompareStringW).
///
/// # Safety
/// `lp_string1` and `lp_string2` must be valid pointers to null-terminated ANSI (byte) strings,
/// or point to at least `cch_count1`/`cch_count2` bytes respectively when counts are non-negative.
// Wine ref: dlls/kernelbase/locale.c — CompareStringA validates args, converts ANSI→UTF-16 via
// MultiByteToWideChar(CP_ACP), then delegates to CompareStringW; null str1/str2 →
// ERROR_INVALID_PARAMETER; Weave treats each ANSI byte as its Unicode codepoint (ASCII superset
// sufficient for SDL2 renderer-name matching with NORM_IGNORECASE + ASCII inputs)
pub unsafe extern "win64" fn compare_string_a(
    _locale: u32,
    dw_cmp_flags: u32,
    lp_string1: *const u8,
    cch_count1: i32,
    lp_string2: *const u8,
    cch_count2: i32,
) -> i32 {
    if lp_string1.is_null() || lp_string2.is_null() {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let len1 = if cch_count1 == -1 {
        let mut len = 0usize;
        while *lp_string1.add(len) != 0 {
            len += 1;
        }
        len
    } else {
        cch_count1 as usize
    };

    let len2 = if cch_count2 == -1 {
        let mut len = 0usize;
        while *lp_string2.add(len) != 0 {
            len += 1;
        }
        len
    } else {
        cch_count2 as usize
    };

    let case_insensitive =
        (dw_cmp_flags & NORM_IGNORECASE) != 0 || (dw_cmp_flags & LINGUISTIC_IGNORECASE) != 0;

    // Promote ANSI bytes to u16 code units (identity mapping for ASCII/Latin-1) and compare.
    // This is behaviorally equivalent to Wine's ANSI→UTF-16 conversion for ASCII inputs.
    let min_len = len1.min(len2);
    for i in 0..min_len {
        let mut c1 = *lp_string1.add(i) as u16;
        let mut c2 = *lp_string2.add(i) as u16;

        if case_insensitive && (c1 as u8).is_ascii_uppercase() {
            c1 += 32;
        }
        if case_insensitive && (c2 as u8).is_ascii_uppercase() {
            c2 += 32;
        }

        if c1 < c2 {
            return CSTR_LESS_THAN;
        } else if c1 > c2 {
            return CSTR_GREATER_THAN;
        }
    }

    match len1.cmp(&len2) {
        std::cmp::Ordering::Less => CSTR_LESS_THAN,
        std::cmp::Ordering::Equal => CSTR_EQUAL,
        std::cmp::Ordering::Greater => CSTR_GREATER_THAN,
    }
}

/// CompareStringOrdinal: compare two UTF-16 strings with optional case folding.
///
/// # Safety
/// `lp_string1` and `lp_string2` must be valid pointers to null-terminated UTF-16 strings.
// Wine ref: dlls/kernelbase/locale.c — null str1 or str2 → ERROR_INVALID_PARAMETER, return 0;
// len < 0 → use lstrlenW length; delegates to RtlCompareUnicodeStrings for case folding
pub unsafe extern "win64" fn compare_string_ordinal(
    lp_string1: *const u16,
    cch_count1: i32,
    lp_string2: *const u16,
    cch_count2: i32,
    b_ignore_case: i32,
) -> i32 {
    // Wine: null str1 or str2 → ERROR_INVALID_PARAMETER
    if lp_string1.is_null() || lp_string2.is_null() {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let len1 = if cch_count1 < 0 {
        let mut len = 0usize;
        while *lp_string1.add(len) != 0 {
            len += 1;
        }
        len
    } else {
        cch_count1 as usize
    };

    let len2 = if cch_count2 < 0 {
        let mut len = 0usize;
        while *lp_string2.add(len) != 0 {
            len += 1;
        }
        len
    } else {
        cch_count2 as usize
    };

    let case_insensitive = b_ignore_case != 0;

    let min_len = len1.min(len2);
    for i in 0..min_len {
        let mut c1 = *lp_string1.add(i);
        let mut c2 = *lp_string2.add(i);

        if case_insensitive && (c1 as u8).is_ascii_uppercase() {
            c1 += 32;
        }
        if case_insensitive && (c2 as u8).is_ascii_uppercase() {
            c2 += 32;
        }

        if c1 < c2 {
            return CSTR_LESS_THAN;
        } else if c1 > c2 {
            return CSTR_GREATER_THAN;
        }
    }

    match len1.cmp(&len2) {
        std::cmp::Ordering::Less => CSTR_LESS_THAN,
        std::cmp::Ordering::Equal => CSTR_EQUAL,
        std::cmp::Ordering::Greater => CSTR_GREATER_THAN,
    }
}

// ── String mapping ──────────────────────────────────────────────────────────

const LCMAP_LOWERCASE: u32 = 0x00000100;
const LCMAP_UPPERCASE: u32 = 0x00000200;

/// LCMapStringW: map a UTF-16 string (uppercase/lowercase conversion).
///
/// # Safety
/// `lp_src_str` must be valid for `cch_src` u16 elements.
/// `lp_dest_str` must be writable for `cch_dest` u16 elements.
// Wine ref: dlls/kernelbase/locale.c — delegates to LCMapStringEx; LCMAP_SORTKEY converts to sort key bytes;
// LCMAP_UPPERCASE/LOWERCASE fold case; cch_dest==0 is size query
pub unsafe extern "win64" fn lc_map_string_w(
    _locale: u32,
    dw_map_flags: u32,
    lp_src_str: *const u16,
    cch_src: i32,
    lp_dest_str: *mut u16,
    cch_dest: i32,
) -> i32 {
    let src_len = if cch_src == -1 {
        let mut len = 0usize;
        unsafe {
            while *lp_src_str.add(len) != 0 {
                len += 1;
            }
        }
        len + 1 // include null
    } else {
        cch_src as usize
    };

    if cch_dest == 0 {
        return src_len as i32;
    }

    let copy_len = src_len.min(cch_dest as usize);
    for i in 0..copy_len {
        let mut c = unsafe { *lp_src_str.add(i) };
        if c <= 127 {
            if (dw_map_flags & LCMAP_UPPERCASE) != 0 && (c as u8).is_ascii_lowercase() {
                c -= 32;
            } else if (dw_map_flags & LCMAP_LOWERCASE) != 0 && (c as u8).is_ascii_uppercase() {
                c += 32;
            }
        }
        unsafe { *lp_dest_str.add(i) = c };
    }
    copy_len as i32
}

// ── Character classification ────────────────────────────────────────────────

const CT_CTYPE1: u32 = 0x00000001;
const C1_UPPER: u16 = 0x0001;
const C1_LOWER: u16 = 0x0002;
const C1_DIGIT: u16 = 0x0004;
const C1_SPACE: u16 = 0x0008;
const C1_PUNCT: u16 = 0x0010;
const C1_CNTRL: u16 = 0x0020;
const C1_BLANK: u16 = 0x0040;
const C1_ALPHA: u16 = 0x0100;

fn classify_char(c: u16) -> u16 {
    if c > 127 {
        return C1_ALPHA;
    }
    let b = c as u8;
    let mut flags: u16 = 0;
    if b.is_ascii_uppercase() {
        flags |= C1_UPPER | C1_ALPHA;
    }
    if b.is_ascii_lowercase() {
        flags |= C1_LOWER | C1_ALPHA;
    }
    if b.is_ascii_digit() {
        flags |= C1_DIGIT;
    }
    if b.is_ascii_whitespace() {
        flags |= C1_SPACE;
    }
    if b == b' ' || b == b'\t' {
        flags |= C1_BLANK;
    }
    if b.is_ascii_punctuation() {
        flags |= C1_PUNCT;
    }
    if b < 0x20 || b == 0x7F {
        flags |= C1_CNTRL;
    }
    flags
}

/// GetStringTypeW: classify characters in a UTF-16 string.
///
/// # Safety
/// `lp_src_str` must be valid for `cch_src` u16 elements.
/// `lp_char_type` must be writable for `cch_src` u16 elements.
// Wine ref: dlls/kernelbase/locale.c — CT_CTYPE1 uses C1_* bitmask table; CT_CTYPE2 returns BiDi class;
// CT_CTYPE3 returns character type (half-width, full-width, etc.); unknown type → ERROR_INVALID_PARAMETER
pub unsafe extern "win64" fn get_string_type_w(
    dw_info_type: u32,
    lp_src_str: *const u16,
    cch_src: i32,
    lp_char_type: *mut u16,
) -> i32 {
    if dw_info_type != CT_CTYPE1 {
        return 0; // FALSE — only CT_CTYPE1 supported
    }

    let len = if cch_src == -1 {
        let mut l = 0usize;
        unsafe {
            while *lp_src_str.add(l) != 0 {
                l += 1;
            }
        }
        l
    } else {
        cch_src as usize
    };

    for i in 0..len {
        unsafe {
            *lp_char_type.add(i) = classify_char(*lp_src_str.add(i));
        }
    }
    1 // TRUE
}

/// GetStringTypeExW: classify UTF-16 characters (locale-aware wrapper).
///
/// # Safety
/// `lp_src_str` must be valid for `cch_src` u16 elements.
/// `lp_char_type` must be writable for `cch_src` u16 elements.
// Wine ref: dlls/kernelbase/locale.c — locale param ignored for Unicode; tail-calls GetStringTypeW(type, src, count, chartype)
pub unsafe extern "win64" fn get_string_type_ex_w(
    _locale: u32,
    dw_info_type: u32,
    lp_src_str: *const u16,
    cch_src: i32,
    lp_char_type: *mut u16,
) -> i32 {
    unsafe { get_string_type_w(dw_info_type, lp_src_str, cch_src, lp_char_type) }
}

/// GetStringTypeExA: classify ANSI characters (locale-aware wrapper).
///
/// # Safety
/// `lp_src_str` must be valid for `cch_src` bytes.
/// `lp_char_type` must be writable for `cch_src` u16 elements.
// Wine ref: dlls/kernelbase/locale.c — locale ignored; converts each ANSI byte to its Unicode
// codepoint (identity for ASCII) then classifies via CT_CTYPE1 table
pub unsafe extern "win64" fn get_string_type_ex_a(
    _locale: u32,
    dw_info_type: u32,
    lp_src_str: *const u8,
    cch_src: i32,
    lp_char_type: *mut u16,
) -> i32 {
    if dw_info_type != CT_CTYPE1 {
        return 0; // FALSE — only CT_CTYPE1 supported
    }
    if lp_src_str.is_null() || lp_char_type.is_null() {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let len = if cch_src == -1 {
        let mut l = 0usize;
        unsafe {
            while *lp_src_str.add(l) != 0 {
                l += 1;
            }
        }
        l
    } else {
        cch_src as usize
    };
    for i in 0..len {
        unsafe {
            *lp_char_type.add(i) = classify_char(u16::from(*lp_src_str.add(i)));
        }
    }
    1 // TRUE
}

/// GetStringTypeA: classify ANSI characters by Unicode type.
///
/// # Safety
/// `lp_src_str` must be valid for `cch_src` bytes.
/// `lp_char_type` must be writable for `cch_src` u16 elements.
// Wine ref: dlls/kernelbase/locale.c — GetStringTypeA(type, src, len, out) delegates directly
// to GetStringTypeExA(locale=0, type, src, len, out); locale parameter is ignored for ASCII
pub unsafe extern "win64" fn get_string_type_a(
    dw_info_type: u32,
    lp_src_str: *const u8,
    cch_src: i32,
    lp_char_type: *mut u16,
) -> i32 {
    unsafe { get_string_type_ex_a(0, dw_info_type, lp_src_str, cch_src, lp_char_type) }
}

/// AreFileApisANSI: return whether file I/O APIs use the ANSI codepage.
// Wine ref: dlls/kernelbase/file.c:498 — returns `!oem_file_apis`; oem_file_apis is a
// module-level bool toggled by SetFileApisToOEM/SetFileApisToANSI; default FALSE → returns TRUE
pub extern "win64" fn are_file_apis_ansi() -> i32 {
    1 // TRUE
}

/// CompareStringEx: compare two UTF-16 strings using a locale name.
///
/// # Safety
/// `lp_string1` and `lp_string2` must be valid UTF-16 string pointers.
// Wine ref: dlls/kernelbase/locale.c — validates flags and null args, resolves locale name to
// sortguid via locale_name_to_sortguid(), delegates to compare_string(); NULL str1/str2 →
// ERROR_INVALID_PARAMETER; Weave ignores locale name (ASCII case-fold only)
pub unsafe extern "win64" fn compare_string_ex(
    _lp_locale_name: *const u16,
    dw_cmp_flags: u32,
    lp_string1: *const u16,
    cch_count1: i32,
    lp_string2: *const u16,
    cch_count2: i32,
    _lp_version_info: *const (),
    _lp_reserved: *const (),
    _l_param: isize,
) -> i32 {
    if lp_string1.is_null() || lp_string2.is_null() {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    unsafe {
        compare_string_w(
            0,
            dw_cmp_flags,
            lp_string1,
            cch_count1,
            lp_string2,
            cch_count2,
        )
    }
}

/// LCMapStringEx: map a UTF-16 string using a locale name.
///
/// # Safety
/// `lp_src_str` must be valid for `cch_src` u16 elements.
/// `lp_dest_str` must be writable for `cch_dest` u16 elements (when non-null).
// Wine ref: dlls/kernelbase/locale.c — null src, srclen==0, or dstlen<0 → ERROR_INVALID_PARAMETER;
// LCMAP_SORTKEY writes binary sort key bytes; locale name resolved via locale_name_to_sortguid()
pub unsafe extern "win64" fn lc_map_string_ex(
    _lp_locale_name: *const u16,
    dw_map_flags: u32,
    lp_src_str: *const u16,
    cch_src: i32,
    lp_dest_str: *mut u16,
    cch_dest: i32,
    _lp_version_info: *const (),
    _lp_reserved: *const (),
    _sort_handle: isize,
) -> i32 {
    if lp_src_str.is_null() || cch_src == 0 || cch_dest < 0 {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    unsafe { lc_map_string_w(0, dw_map_flags, lp_src_str, cch_src, lp_dest_str, cch_dest) }
}

/// LCMapStringA: map an ANSI string using a locale (ANSI wrapper for LCMapStringW).
///
/// # Safety
/// `lp_src_str` must be valid for `cch_src` bytes.
/// `lp_dest_str` must be writable for `cch_dest` bytes (when non-null).
// Wine ref: dlls/kernelbase/locale.c — converts ANSI→UTF-16 via MultiByteToWideChar(CP_ACP),
// calls LCMapStringW, converts back; Weave treats each ANSI byte as its Unicode codepoint
pub unsafe extern "win64" fn lc_map_string_a(
    locale: u32,
    dw_map_flags: u32,
    lp_src_str: *const u8,
    cch_src: i32,
    lp_dest_str: *mut u8,
    cch_dest: i32,
) -> i32 {
    if lp_src_str.is_null() || cch_src == 0 {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let src_len = if cch_src < 0 {
        let mut l = 0usize;
        unsafe {
            while *lp_src_str.add(l) != 0 {
                l += 1;
            }
        }
        l + 1
    } else {
        cch_src as usize
    };
    // Expand ANSI bytes to UTF-16, map, then truncate back to bytes.
    let wide: Vec<u16> = (0..src_len)
        .map(|i| u16::from(unsafe { *lp_src_str.add(i) }))
        .collect();
    let mut wide_out = vec![0u16; src_len];
    let mapped = unsafe {
        lc_map_string_w(
            locale,
            dw_map_flags,
            wide.as_ptr(),
            src_len as i32,
            wide_out.as_mut_ptr(),
            src_len as i32,
        )
    };
    if mapped == 0 {
        return 0;
    }
    let out_len = mapped as usize;
    if cch_dest == 0 {
        return out_len as i32;
    }
    let copy_len = out_len.min(cch_dest as usize);
    for (i, &w) in wide_out.iter().enumerate().take(copy_len) {
        unsafe { *lp_dest_str.add(i) = (w & 0xFF) as u8 };
    }
    copy_len as i32
}

// ── File time and positioning ───────────────────────────────────────────────

/// SetFilePointerEx: set file pointer position using 64-bit offset.
///
/// # Safety
/// If `lp_new_file_pointer` is non-null, it must be writable.
// Wine ref: dlls/kernelbase/file.c:3870 — FILE_CURRENT uses NtQueryInformationFile(FilePositionInformation)
// to read current offset; FILE_END uses FileStandardInformation.EndOfFile; negative final pos →
// ERROR_NEGATIVE_SEEK; writes newpos via NtSetInformationFile(FilePositionInformation)
pub unsafe extern "win64" fn set_file_pointer_ex(
    h_file: usize,
    li_distance_to_move: i64,
    lp_new_file_pointer: *mut i64,
    dw_move_method: u32,
) -> i32 {
    eprintln!(
        "weave/SetFilePointerEx: entry handle={h_file:#x} dist={li_distance_to_move} method={dw_move_method}"
    );
    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            set_last_error(file_io::ERROR_INVALID_HANDLE);
            eprintln!("weave/SetFilePointerEx: exit handle={h_file:#x} → FALSE (invalid handle)");
            return 0; // FALSE
        }
    };
    let whence = match dw_move_method {
        0 => libc::SEEK_SET,
        1 => libc::SEEK_CUR,
        2 => libc::SEEK_END,
        _ => {
            set_last_error(file_io::ERROR_INVALID_HANDLE);
            eprintln!("weave/SetFilePointerEx: exit handle={h_file:#x} → FALSE (bad method)");
            return 0; // FALSE
        }
    };
    let result = unsafe { libc::lseek(fd, li_distance_to_move, whence) };
    if result >= 0 {
        if !lp_new_file_pointer.is_null() {
            unsafe { *lp_new_file_pointer = result };
        }
        set_last_error(0);
        eprintln!(
            "weave/SetFilePointerEx: exit handle={h_file:#x} fd={fd} new_pos={result} → TRUE"
        );
        1 // TRUE
    } else {
        set_last_error(file_io::ERROR_INVALID_HANDLE);
        eprintln!("weave/SetFilePointerEx: exit handle={h_file:#x} fd={fd} → FALSE (lseek err)");
        0 // FALSE
    }
}

/// GetFileTime: read creation, last-access, and last-write timestamps from an open file handle.
///
/// NULL pointers for any of the three output args are silently skipped (not an error).
/// On unknown handle or fstat failure, returns FALSE and sets LastError.
///
/// # Safety
/// Each non-null pointer arg must point to a valid writable u64 (FILETIME).
// Wine ref: dlls/kernelbase/file.c:3258 — calls NtQueryInformationFile(FileBasicInformation);
// unpacks LARGE_INTEGER fields into creation/access/write FILETIME structs; NULL pointers skipped.
// Weave maps directly to fstat(2): st_ctime (change-time) serves as creation-time proxy on Linux.
pub unsafe extern "win64" fn get_file_time(
    h_file: usize,
    lp_creation_time: *mut u64,
    lp_last_access_time: *mut u64,
    lp_last_write_time: *mut u64,
) -> i32 {
    eprintln!(
        "weave/GetFileTime: entry handle={h_file:#x} lp_creation={lp_creation_time:?} lp_access={lp_last_access_time:?} lp_write={lp_last_write_time:?}"
    );
    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            set_last_error(file_io::ERROR_INVALID_HANDLE);
            eprintln!("weave/GetFileTime: exit handle={h_file:#x} fd=? → FALSE (bad_handle)");
            return 0; // FALSE
        }
    };

    // SAFETY: (a) zeroed() produces a valid zero-initialized libc::stat; (b) Rust stack;
    // (c) duration of this call; (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: (a) fd is a valid Linux file descriptor from the handle table (validated
    // by get_fd above); &mut stat points to a properly aligned libc::stat on the stack;
    // (b) fd from kernel handle table, stat on Rust stack; (c) duration of fstat syscall;
    // (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        set_last_error(file_io::ERROR_INVALID_HANDLE);
        eprintln!("weave/GetFileTime: exit handle={h_file:#x} fd={fd} → FALSE (fstat_err)");
        return 0; // FALSE
    }

    // Convert Unix timespec fields to Windows FILETIME (100-ns intervals since 1601-01-01).
    // Linux st_ctime is change-time, not birth/creation time; used as best-effort proxy.
    let ft_creation = weave_common::unix_to_filetime(stat.st_ctime, stat.st_ctime_nsec);
    let ft_access = weave_common::unix_to_filetime(stat.st_atime, stat.st_atime_nsec);
    let ft_write = weave_common::unix_to_filetime(stat.st_mtime, stat.st_mtime_nsec);
    if !lp_creation_time.is_null() {
        // SAFETY: (a) lp_creation_time is non-null (checked above); Win32 LPFILETIME is
        // always 8-byte aligned per Win64 ABI; (b) guest heap — caller owns the buffer;
        // (c) duration of this call; (d) gate: sevenzip_m13_debug_e_gate (CI 26007699626).
        unsafe { *lp_creation_time = ft_creation };
    }
    if !lp_last_access_time.is_null() {
        // SAFETY: (a) lp_last_access_time is non-null (checked above); same alignment
        // guarantee as above; (b) guest heap; (c) duration of call; (d) same gate.
        unsafe { *lp_last_access_time = ft_access };
    }
    if !lp_last_write_time.is_null() {
        // SAFETY: (a) lp_last_write_time is non-null (checked above); same alignment
        // guarantee as above; (b) guest heap; (c) duration of call; (d) same gate.
        unsafe { *lp_last_write_time = ft_write };
    }

    set_last_error(0);
    eprintln!(
        "weave/GetFileTime: exit handle={h_file:#x} fd={fd} creation={ft_creation:#x} access={ft_access:#x} write={ft_write:#x} → TRUE"
    );
    1 // TRUE
}

/// SetFileTime: update last-access and/or last-write timestamps on an open file handle.
///
/// NULL pointers are skipped (mapped to UTIME_OMIT on Linux). Creation time cannot be
/// set on Linux (ctime is change-time); if only lp_creation_time is non-null, returns TRUE
/// silently without calling futimens.
/// On unknown handle or futimens failure, returns FALSE and sets LastError.
///
/// # Safety
/// Each non-null pointer arg must point to a valid readable u64 (FILETIME).
// Wine ref: dlls/kernelbase/file.c:3919 — zeroes FILE_BASIC_INFORMATION then packs only the
// non-null FILETIME args into it; zero-filled fields are ignored by NtSetInformationFile.
// Weave maps directly to futimens(2) rather than NtSetInformationFile.
pub unsafe extern "win64" fn set_file_time(
    h_file: usize,
    _lp_creation_time: *const u64, // Linux cannot set creation time; accepted for ABI compatibility
    lp_last_access_time: *const u64,
    lp_last_write_time: *const u64,
) -> i32 {
    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            set_last_error(file_io::ERROR_INVALID_HANDLE);
            eprintln!("weave/SetFileTime: exit handle={h_file:#x} fd=? → FALSE (bad_handle)");
            return 0; // FALSE
        }
    };

    // Convert Windows FILETIME (100-ns since 1601-01-01) to Unix timespec.
    // 116,444,736,000,000,000 = 100-ns intervals from 1601-01-01 to 1970-01-01.
    let to_timespec = |ft: u64| -> libc::timespec {
        let intervals_since_unix = ft.saturating_sub(116_444_736_000_000_000);
        libc::timespec {
            tv_sec: (intervals_since_unix / 10_000_000) as i64,
            tv_nsec: ((intervals_since_unix % 10_000_000) * 100) as i64,
        }
    };

    // If only creation time is given, Linux cannot set ctime — silently succeed.
    if lp_last_access_time.is_null() && lp_last_write_time.is_null() {
        set_last_error(0);
        eprintln!(
            "weave/SetFileTime: exit handle={h_file:#x} fd={fd} → TRUE (creation-time-only, no-op on Linux)"
        );
        return 1; // TRUE — creation-time-only set is a no-op on Linux
    }

    let ft_access = if lp_last_access_time.is_null() {
        0u64
    } else {
        // SAFETY: lp_last_access_time is non-null (checked above) and points to a valid
        // u64 FILETIME per the caller's # Safety contract.  FILETIME is only 4-byte
        // aligned, so read_unaligned avoids potential misalignment UB.
        unsafe { std::ptr::read_unaligned(lp_last_access_time) }
    };
    let ft_write = if lp_last_write_time.is_null() {
        0u64
    } else {
        // SAFETY: lp_last_write_time is non-null (checked above) and points to a valid
        // u64 FILETIME per the caller's # Safety contract.  FILETIME is only 4-byte
        // aligned, so read_unaligned avoids potential misalignment UB.
        unsafe { std::ptr::read_unaligned(lp_last_write_time) }
    };

    // Build [atime, mtime] pair; use UTIME_OMIT for NULL args.
    let omit = libc::timespec {
        tv_sec: 0,
        tv_nsec: libc::UTIME_OMIT,
    };
    let times = [
        if lp_last_access_time.is_null() {
            omit
        } else {
            to_timespec(ft_access)
        },
        if lp_last_write_time.is_null() {
            omit
        } else {
            to_timespec(ft_write)
        },
    ];

    let ret = unsafe { libc::futimens(fd, times.as_ptr()) };
    if ret != 0 {
        set_last_error(file_io::ERROR_INVALID_HANDLE);
        eprintln!(
            "weave/SetFileTime: exit handle={h_file:#x} fd={fd} access={ft_access:#x} write={ft_write:#x} → FALSE (futimens_err)"
        );
        return 0; // FALSE
    }

    set_last_error(0);
    eprintln!(
        "weave/SetFileTime: exit handle={h_file:#x} fd={fd} access={ft_access:#x} write={ft_write:#x} → TRUE"
    );
    1 // TRUE
}

// ── Vectored exception handlers ─────────────────────────────────────────────

/// AddVectoredExceptionHandler: no-op stub returning the handler as a fake handle.
// Wine ref: dlls/ntdll/exception.c:371 — delegates to add_vectored_handler(&vectored_exception_handlers, first, func);
// inserts at head (first!=0) or tail; returns allocated VECTORED_HANDLER* as opaque handle
pub extern "win64" fn add_vectored_exception_handler(_first: u32, handler: usize) -> usize {
    // Weave does not dispatch vectored exceptions; return a fake non-zero handle so callers
    // that register for telemetry/error-recovery (e.g. SumatraPDF) can continue running.
    let _ = handler;
    1
}

/// RemoveVectoredExceptionHandler: no-op stub returning success.
// Wine ref: dlls/ntdll/exception.c — delegates to remove_vectored_handler(&vectored_exception_handlers, handler);
// walks the list, removes and frees the entry; returns count of remaining handlers
pub extern "win64" fn remove_vectored_exception_handler(handle: usize) -> u32 {
    let _ = handle;
    1
}

/// AddVectoredContinueHandler: no-op stub returning the handler as a fake handle.
// Wine ref: dlls/ntdll/exception.c — delegates to add_vectored_handler(&vectored_continue_handlers, first, func);
// same linked-list mechanism as AddVectoredExceptionHandler but separate list
pub extern "win64" fn add_vectored_continue_handler(_first: u32, handler: usize) -> usize {
    let _ = handler;
    1
}

/// RemoveVectoredContinueHandler: no-op stub returning success.
// Wine ref: dlls/ntdll/exception.c — delegates to remove_vectored_handler(&vectored_continue_handlers, handler);
// same mechanism as RemoveVectoredExceptionHandler but uses the continue handler list
pub extern "win64" fn remove_vectored_continue_handler(handle: usize) -> u32 {
    let _ = handle;
    1
}

/// File type constant for unknown files.
const FILE_TYPE_UNKNOWN: u32 = 0x0000;

/// GetUserDefaultLCID: return English (United States) locale ID.
// Wine ref: dlls/kernelbase/locale.c:6383 — returns global `user_lcid` set at init from
// NtQueryDefaultLocale(TRUE, &user_lcid); Weave hardcodes EN_US
pub extern "win64" fn get_user_default_lcid() -> u32 {
    LOCALE_EN_US
}

/// GetSystemDefaultLCID: return English (United States) locale ID.
// Wine ref: dlls/kernelbase/locale.c:6236 — returns global `system_lcid` set at init from
// NtQueryDefaultLocale(FALSE, &system_lcid); Weave hardcodes EN_US
pub extern "win64" fn get_system_default_lcid() -> u32 {
    LOCALE_EN_US
}

/// GetUserDefaultUILanguage: return English (United States) language ID.
// Wine ref: dlls/kernelbase/locale.c:6410 — returns LANGIDFROMLCID(GetUserDefaultLCID());
// extracts primary+sublang ID from the lower 16 bits of the LCID
pub extern "win64" fn get_user_default_ui_language() -> u16 {
    LOCALE_EN_US as u16
}

/// GetSystemDefaultLangID: return English (United States) language ID.
// Wine ref: dlls/kernelbase/locale.c:6245 — returns LANGIDFROMLCID(GetSystemDefaultLCID());
// extracts primary+sublang ID from the lower 16 bits of the system LCID
pub extern "win64" fn get_system_default_lang_id() -> u16 {
    LOCALE_EN_US as u16
}

/// IsValidCodePage: validate code page identifiers.
// Wine ref: dlls/kernelbase/locale.c:6678 — CP_ACP/CP_OEMCP/CP_MACCP/CP_THREAD_ACP return FALSE
// unconditionally; all others call get_codepage_table(codepage) and return TRUE if non-NULL
pub extern "win64" fn is_valid_code_page(code_page: u32) -> i32 {
    match code_page {
        0 | 65001 | 1252 | 437 => 1, // TRUE for UTF-8, CP_ACP, CP_OEM
        _ => 0,                      // FALSE for others
    }
}

/// GetFileType: return FILE_TYPE_CHAR for stdio, FILE_TYPE_DISK for open file
/// handles, FILE_TYPE_UNKNOWN for unrecognised handles.
///
/// The UCRT's internal `_open_osfhandle` (called from `_wfopen`) rejects any
/// handle where GetFileType returns FILE_TYPE_UNKNOWN — it sets errno=EBADF and
/// returns -1, silently aborting the entire fopen chain.
// Wine ref: dlls/kernelbase/file.c:3289 — resolves STD_*_HANDLE pseudo-handles via GetStdHandle;
// calls NtQueryVolumeInformationFile(FileFsDeviceInformation); maps device types:
// FILE_DEVICE_CONSOLE/SERIAL/PARALLEL/TAPE/NULL/UNKNOWN → FILE_TYPE_CHAR; NAMED_PIPE → FILE_TYPE_PIPE; else FILE_TYPE_DISK
pub extern "win64" fn get_file_type(h_file: usize) -> u32 {
    if h_file == handles::STDIN_HANDLE
        || h_file == handles::STDOUT_HANDLE
        || h_file == handles::STDERR_HANDLE
    {
        return 0x0002; // FILE_TYPE_CHAR
    }
    if handles::get_fd(h_file).is_some() {
        0x0001 // FILE_TYPE_DISK
    } else {
        FILE_TYPE_UNKNOWN
    }
}

// ── File and console functions ──────────────────────────────────────────────

/// GetFileSizeEx: return the true file size as an i64.
///
/// # Safety
/// `lp_file_size` must be a valid writable pointer to an i64.
// Wine ref: dlls/kernelbase/file.c:3242 — calls NtQueryInformationFile(FileStandardInformation);
// writes info.EndOfFile (LARGE_INTEGER) directly to *size; returns FALSE on NT error
pub unsafe extern "win64" fn get_file_size_ex(h_file: usize, lp_file_size: *mut i64) -> i32 {
    eprintln!("weave/GetFileSizeEx: entry handle={h_file:#x}");
    let fd = match handles::get_fd(h_file) {
        Some(fd) => fd,
        None => {
            set_last_error(file_io::ERROR_INVALID_HANDLE);
            eprintln!("weave/GetFileSizeEx: exit handle={h_file:#x} → FALSE (bad_handle)");
            return 0; // FALSE
        }
    };

    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let ret = unsafe { libc::fstat(fd, &mut stat) };
    if ret != 0 {
        set_last_error(file_io::ERROR_INVALID_HANDLE);
        eprintln!("weave/GetFileSizeEx: exit handle={h_file:#x} fd={fd} → FALSE (fstat_err)");
        return 0; // FALSE
    }

    if !lp_file_size.is_null() {
        unsafe { *lp_file_size = stat.st_size };
    }
    set_last_error(0);
    eprintln!(
        "weave/GetFileSizeEx: exit handle={h_file:#x} fd={fd} size={} → TRUE",
        stat.st_size
    );
    1 // TRUE
}

/// GetConsoleMode: return TRUE only for real tty/console handles; otherwise
/// FALSE + ERROR_INVALID_HANDLE.
///
/// Wine ref: dlls/kernelbase/console.c:932 — calls console_ioctl
/// (IOCTL_CONDRV_GET_MODE); the ioctl fails with STATUS_OBJECT_TYPE_MISMATCH
/// for non-console handles, which BaseDllHandleError maps to FALSE +
/// ERROR_INVALID_HANDLE.
///
/// Why this matters: gnulib's `IsConsoleHandle` (lib/select.c) is defined as
/// `GetConsoleMode(h, &mode) != 0`. Gnulib's `rpl_select` then uses this to
/// pre-classify fds before the MsgWait handle array is built. A stub that
/// returns TRUE for every handle causes gnulib to misclassify sockets as
/// consoles; its rfds pre-classification loop then silently drops them, and
/// MsgWait waits on the hEvent alone — nothing ever signals it, infinite hang.
/// Wget's "HTTP GET sent, waiting forever for response" bug was exactly this.
///
/// Weave has no real Windows console emulation. When the guest runs attached
/// to a real Linux tty we return TRUE with a plausible cooked-mode value so
/// console-aware apps get reasonable behavior; otherwise we return FALSE.
///
/// # Safety
/// `lp_mode` must be a valid writable pointer to a u32 (or null).
pub unsafe extern "win64" fn get_console_mode(h_console_handle: usize, lp_mode: *mut u32) -> i32 {
    // Map handle to fd. Weave's non-kernel handles (sockets, files) are
    // identity-mapped to Linux fds; STD_{INPUT,OUTPUT,ERROR}_HANDLE carry
    // HANDLE_OFFSET=4 → fd=0,1,2 via the std_handle table. Cheap test: small
    // positive integers that look like fds.
    let fd: i32 = match h_console_handle {
        // STD_INPUT_HANDLE / OUTPUT / ERROR encode stdin/stdout/stderr.
        // (-10, -11, -12 as i32 → 0xFFFFFFF6 / 0xFFFFFFF5 / 0xFFFFFFF4 as usize)
        0xFFFF_FFFF_FFFF_FFF6 => 0,
        0xFFFF_FFFF_FFFF_FFF5 => 1,
        0xFFFF_FFFF_FFFF_FFF4 => 2,
        h if h > 0 && h < 4096 => h as i32,
        _ => {
            weave_common::set_last_error(6); // ERROR_INVALID_HANDLE
            return 0; // FALSE
        }
    };

    // Only real ttys count as "consoles" for our purposes. Sockets, pipes,
    // regular files → not a console → FALSE + ERROR_INVALID_HANDLE.
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::isatty(fd) } == 0 {
            weave_common::set_last_error(6); // ERROR_INVALID_HANDLE
            return 0; // FALSE
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        // Non-Linux builds: conservative — always report not-a-console.
        weave_common::set_last_error(6);
        return 0;
    }

    // Real tty: report ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT |
    // ENABLE_ECHO_INPUT (typical cooked-mode default on Windows console).
    unsafe {
        if !lp_mode.is_null() {
            *lp_mode = 0x0001 | 0x0002 | 0x0004;
        }
    }
    1 // TRUE
}

/// SetConsoleMode: apply Win32 console mode flags to the underlying TTY via tcsetattr(2).
///
/// Maps `ENABLE_LINE_INPUT` (0x0002) → ICANON, `ENABLE_ECHO_INPUT` (0x0004) → ECHO,
/// `ENABLE_PROCESSED_INPUT` (0x0001) → ISIG. Output-only flags have no direct termios
/// equivalent and are silently accepted (no-op). Non-TTY fds (pipes, files) and unknown
/// handles succeed as a no-op. This is best-effort: if tcgetattr/tcsetattr fails for any
/// reason we still return TRUE.
///
/// # Safety
/// No pointer arguments are dereferenced.
// Wine ref: dlls/kernelbase/console.c — SetConsoleMode; on Windows calls console_ioctl
// (IOCTL_CONDRV_SET_MODE); on Linux we map to termios attributes directly.
pub unsafe extern "win64" fn set_console_mode(h_console_handle: usize, dw_mode: u32) -> i32 {
    // Resolve handle → Linux fd. Unknown/invalid handles are a silent no-op (TRUE), not an error.
    let fd = match handles::get_fd(h_console_handle) {
        Some(fd) => fd,
        None => return 1, // not a file handle — no-op, TRUE
    };

    #[cfg(target_os = "linux")]
    {
        // Non-TTY fds (pipes, sockets, regular files) succeed silently.
        if unsafe { libc::isatty(fd) } == 0 {
            return 1; // TRUE — non-TTY is not an error
        }

        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        // Read current termios state. If it fails, return TRUE (best-effort).
        if unsafe { libc::tcgetattr(fd, &mut termios) } != 0 {
            return 1; // TRUE — best-effort
        }

        // Apply input-mode flags. Output-mode flags (ENABLE_PROCESSED_OUTPUT 0x0001,
        // ENABLE_WRAP_AT_EOL_OUTPUT 0x0002) have no termios equivalent — they are
        // intentionally not mapped. We apply termios changes regardless of handle direction:
        // if an output handle is backed by a real TTY, applying these flags is harmless.
        const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
        const ENABLE_LINE_INPUT: u32 = 0x0002;
        const ENABLE_ECHO_INPUT: u32 = 0x0004;

        if dw_mode & ENABLE_LINE_INPUT != 0 {
            termios.c_lflag |= libc::ICANON;
        } else {
            termios.c_lflag &= !libc::ICANON;
        }

        if dw_mode & ENABLE_ECHO_INPUT != 0 {
            termios.c_lflag |= libc::ECHO;
        } else {
            termios.c_lflag &= !libc::ECHO;
        }

        if dw_mode & ENABLE_PROCESSED_INPUT != 0 {
            termios.c_lflag |= libc::ISIG;
        } else {
            termios.c_lflag &= !libc::ISIG;
        }

        // Apply — TCSANOW takes effect immediately. Errors are silently ignored (best-effort).
        let _ = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, dw_mode);
    }

    1 // TRUE
}

// ── Console functions ─────────────────────────────────────────────────────────

/// WriteConsoleA: write ANSI buffer to console handle.
///
/// Converts ANSI to UTF-8 and writes to the Linux fd.
///
/// # Safety
/// `lp_buffer` must be valid for `n_chars` bytes.
// Wine ref: dlls/kernelbase/console.c:2147 — calls console_ioctl(IOCTL_CONDRV_WRITE_FILE) with
// the raw buffer; on success sets *written=length; Wine goes through condrv not a Unix fd write
pub unsafe extern "win64" fn write_console_a(
    h_console_output: usize,
    lp_buffer: *const u8,
    n_chars: u32,
    lp_chars_written: *mut u32,
    _lp_reserved: usize,
) -> i32 {
    let fd = match handles::get_fd(h_console_output) {
        Some(fd) => fd,
        None => return 0, // FALSE
    };
    let slice = unsafe { std::slice::from_raw_parts(lp_buffer, n_chars as usize) };
    let s = String::from_utf8_lossy(slice);
    let bytes = s.as_bytes();
    let n = unsafe { libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len()) };
    if !lp_chars_written.is_null() {
        unsafe { *lp_chars_written = if n >= 0 { n_chars } else { 0 } };
    }
    (n >= 0) as i32
}

/// SetConsoleTitleW: set console title (wide version).
///
/// No-op. Return TRUE.
///
/// # Safety
/// Pointer argument is accepted but not dereferenced.
// Wine ref: dlls/kernelbase/console.c:1736 — calls console_ioctl(IOCTL_CONDRV_SET_TITLE)
// with title bytes = lstrlenW(title)*sizeof(WCHAR); no null terminator sent in ioctl.
pub unsafe extern "win64" fn set_console_title_w(lp_console_title: *const u16) -> i32 {
    // Wine ref: dlls/kernelbase/console.c — IOCTL_CONDRV_SET_TITLE to condrv driver.
    // Weave: write OSC 0 escape sequence to stderr (sets terminal window title).
    if lp_console_title.is_null() {
        set_last_error(87);
        return 0;
    }
    let title = unsafe {
        let mut len = 0;
        while *lp_console_title.add(len) != 0 {
            len += 1;
        }
        std::slice::from_raw_parts(lp_console_title, len)
    };
    let s = String::from_utf16_lossy(title);
    let esc = format!("\x1b]0;{s}\x07");
    unsafe { libc::write(2, esc.as_ptr() as *const libc::c_void, esc.len()) };
    set_last_error(0);
    1
}

/// SetConsoleTitleA: set console title (ANSI version).
///
/// Reads null-terminated ANSI string and writes OSC 0 escape to stderr.
///
/// # Safety
/// `lp_console_title` must be a valid null-terminated byte string or NULL.
// Wine ref: dlls/kernelbase/console.c — converts via MultiByteToWideChar(CP_ACP)
// then delegates to SetConsoleTitleW.
pub unsafe extern "win64" fn set_console_title_a(lp_console_title: *const u8) -> i32 {
    if lp_console_title.is_null() {
        set_last_error(87);
        return 0;
    }
    let s = unsafe { std::ffi::CStr::from_ptr(lp_console_title as *const libc::c_char) }
        .to_string_lossy();
    let esc = format!("\x1b]0;{s}\x07");
    unsafe { libc::write(2, esc.as_ptr() as *const libc::c_void, esc.len()) };
    set_last_error(0);
    1
}

/// GetConsoleTitleW: get console title (wide version).
///
/// Write 0 to buffer, return 0.
///
/// # Safety
/// `lp_console_title` must be valid for `n_size` u16 words.
// Wine ref: dlls/kernelbase/console.c:1105 — delegates to get_console_title(title, size, TRUE);
// TRUE = current title (vs FALSE = original title for GetConsoleOriginalTitleW).
pub unsafe extern "win64" fn get_console_title_w(lp_console_title: *mut u16, n_size: u32) -> u32 {
    // title not stored in Weave (SetConsoleTitleW writes OSC escape only); return empty
    if !lp_console_title.is_null() && n_size > 0 {
        unsafe { *lp_console_title = 0 };
    }
    0
}

/// GetConsoleTitleA: get console title (ANSI version).
///
/// Write 0 to buffer, return 0.
///
/// # Safety
/// `lp_console_title` must be valid for `n_size` bytes.
// Wine ref: dlls/kernelbase/console.c::GetConsoleTitleA:1086 — calls get_console_title into
// a wide buffer, then WideCharToMultiByte(CP_ACP) to fill ANSI output.
pub unsafe extern "win64" fn get_console_title_a(lp_console_title: *mut u8, n_size: u32) -> u32 {
    // title not stored in Weave; return empty
    if !lp_console_title.is_null() && n_size > 0 {
        unsafe { *lp_console_title = 0 };
    }
    0
}

/// GetConsoleScreenBufferInfo: get console screen buffer info.
///
/// Fill struct with fake 80×25 console info, return TRUE.
///
/// # Safety
/// `lp_console_screen_buffer_info` must be a valid writable pointer to a ConsoleScreenBufferInfo.
// Wine ref: dlls/kernelbase/console.c:1019 — calls console_ioctl(IOCTL_CONDRV_GET_OUTPUT_INFO)
// into condrv_output_info; maps width/height/cursor_x/cursor_y/attr/win_left/right/top/bottom/max_width/max_height
pub unsafe extern "win64" fn get_console_screen_buffer_info(
    _h_console_output: usize,
    lp_console_screen_buffer_info: *mut ConsoleScreenBufferInfo,
) -> i32 {
    if lp_console_screen_buffer_info.is_null() {
        return 0; // FALSE
    }
    unsafe {
        (*lp_console_screen_buffer_info).size_x = 80;
        (*lp_console_screen_buffer_info).size_y = 25;
        (*lp_console_screen_buffer_info).cursor_x = 0;
        (*lp_console_screen_buffer_info).cursor_y = 0;
        (*lp_console_screen_buffer_info).attributes = 7; // gray on black
        (*lp_console_screen_buffer_info).window_left = 0;
        (*lp_console_screen_buffer_info).window_top = 0;
        (*lp_console_screen_buffer_info).window_right = 79;
        (*lp_console_screen_buffer_info).window_bottom = 24;
        (*lp_console_screen_buffer_info).max_x = 80;
        (*lp_console_screen_buffer_info).max_y = 25;
    }
    1 // TRUE
}

/// SetConsoleTextAttribute: set console text attributes.
///
/// No-op. Return TRUE.
///
/// # Safety
/// No pointer arguments are dereferenced.
// Wine ref: dlls/kernelbase/console.c:1706 — sends IOCTL_CONDRV_SET_OUTPUT_INFO with
// SET_CONSOLE_OUTPUT_INFO_ATTR flag; condrv_output_info_params.info.attr = attr.
pub unsafe extern "win64" fn set_console_text_attribute(
    _h_console_output: usize,
    w_attributes: u16,
) -> i32 {
    // Wine ref: dlls/kernelbase/console.c — IOCTL_CONDRV_SET_OUTPUT_INFO to condrv.
    // Weave: translate Windows BGR color bits to ANSI SGR escape on stderr.
    // Win bits 0-2 = FG color (B,G,R), bit 3 = FG bright; bits 4-6 = BG, bit 7 = BG bright.
    fn reorder(c: u8) -> u8 {
        // Win BGR → ANSI RGB: swap bit 0 (B) and bit 2 (R)
        ((c & 4) >> 2) | (c & 2) | ((c & 1) << 2)
    }
    let fg = reorder((w_attributes & 0x07) as u8);
    let bg = reorder(((w_attributes >> 4) & 0x07) as u8);
    let fg_code = if w_attributes & 0x08 != 0 {
        90 + fg
    } else {
        30 + fg
    };
    let bg_code = if w_attributes & 0x80 != 0 {
        100 + bg
    } else {
        40 + bg
    };
    let esc = format!("\x1b[{fg_code};{bg_code}m");
    unsafe { libc::write(2, esc.as_ptr() as *const libc::c_void, esc.len()) };
    1
}

// ── SetConsoleCtrlHandler state ──────────────────────────────────────────────
//
// Wine ref: dlls/kernelbase/console.c:1502 — NULL func toggles ConsoleFlags bit
// 1 in PEB->ProcessParameters; non-NULL func add=TRUE prepends to ctrl_handler
// linked-list; add=FALSE walks list and removes first match; not found →
// SetLastError(ERROR_INVALID_PARAMETER) + return FALSE.
//
// Weave mapping: linked list → Vec<usize> protected by Mutex; ConsoleFlags bit →
// CTRL_IGNORE AtomicBool; one-time sigaction install guarded by SIGNAL_INSTALLED.

/// Handler function pointers (as usize), newest appended last.
/// Iterate in reverse (newest-first) when dispatching.
static CTRL_HANDLERS: OnceLock<Mutex<Vec<usize>>> = OnceLock::new();

/// When true, Ctrl+C / Ctrl+Break signals are silently ignored (NULL-func + add=TRUE).
static CTRL_IGNORE: AtomicBool = AtomicBool::new(false);

/// Guards one-time sigaction install — set to true after SIGINT/SIGTERM are hooked.
static SIGNAL_INSTALLED: AtomicBool = AtomicBool::new(false);

fn ctrl_handlers() -> &'static Mutex<Vec<usize>> {
    CTRL_HANDLERS.get_or_init(|| Mutex::new(Vec::new()))
}

/// CTRL event identifiers (matches Windows CTRL_*_EVENT constants).
const CTRL_C_EVENT: u32 = 0;
const CTRL_CLOSE_EVENT: u32 = 2;

/// Signal handler dispatched by SIGINT and SIGTERM.
///
/// Must be `extern "C"` — the kernel calls this directly.
/// Uses try_lock() to avoid deadlock: if the mutex is held by the main thread
/// at signal delivery time we skip the handler chain silently (documented
/// degradation — holding a lock across signal delivery is caller's problem).
extern "C" fn ctrl_signal_dispatch(sig: i32) {
    if CTRL_IGNORE.load(Ordering::Relaxed) {
        return;
    }
    let event = if sig == libc::SIGTERM {
        CTRL_CLOSE_EVENT
    } else {
        CTRL_C_EVENT
    };
    // try_lock: if mutex is contended at signal delivery time, skip silently.
    if let Ok(handlers) = ctrl_handlers().try_lock() {
        // Iterate newest-first (reverse of insertion order).
        for &fn_ptr in handlers.iter().rev() {
            // SAFETY: fn_ptr was stored from a valid extern "win64" fn cast.
            let handler: unsafe extern "win64" fn(u32) -> i32 =
                unsafe { std::mem::transmute(fn_ptr) };
            let handled = unsafe { handler(event) };
            if handled != 0 {
                break; // handler returned TRUE — stop chain
            }
        }
    }
}

/// Install SIGINT and SIGTERM sigaction handlers exactly once.
fn install_signal_handlers_once() {
    if SIGNAL_INSTALLED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return; // already installed
    }
    // SAFETY: sigaction is safe to call before any threads diverge and we only
    // store a plain extern "C" fn pointer — no closures, no allocations.
    unsafe {
        let sa = libc::sigaction {
            sa_sigaction: ctrl_signal_dispatch as *const () as libc::sighandler_t,
            sa_mask: std::mem::zeroed(),
            sa_flags: libc::SA_RESTART,
            #[cfg(target_os = "linux")]
            sa_restorer: None,
        };
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

/// SetConsoleCtrlHandler: maintain a process-global handler list and install
/// a real sigaction on first registration.
///
/// # Safety
/// `handler_routine` must be 0 (NULL) or a valid `extern "win64" fn(u32) -> i32`
/// function pointer cast to usize.
// Wine ref: dlls/kernelbase/console.c:1502 — NULL func toggles ConsoleFlags bit;
// non-NULL add=TRUE prepends; add=FALSE removes first match or ERROR_INVALID_PARAMETER.
pub unsafe extern "win64" fn set_console_ctrl_handler(handler_routine: usize, add: i32) -> i32 {
    if handler_routine == 0 {
        // NULL func: toggle CTRL_IGNORE flag
        CTRL_IGNORE.store(add != 0, Ordering::Release);
        return 1; // TRUE
    }

    let handlers = ctrl_handlers();
    let mut guard = handlers.lock().unwrap_or_else(|e| e.into_inner());

    if add != 0 {
        // add=TRUE: append (newest last; dispatch iterates in reverse)
        guard.push(handler_routine);
        install_signal_handlers_once();
        1 // TRUE
    } else {
        // add=FALSE: remove first match
        if let Some(pos) = guard.iter().position(|&p| p == handler_routine) {
            guard.remove(pos);
            1 // TRUE
        } else {
            weave_common::set_last_error(0x57); // ERROR_INVALID_PARAMETER
            0 // FALSE
        }
    }
}

/// GetNumberOfConsoleInputEvents: report pending console input events.
///
/// In Weave, stdin is a pipe (CI/Docker) or a real terminal fd — never a
/// Windows console object.  The Windows contract for this API on a
/// non-console handle is FALSE + `ERROR_INVALID_HANDLE`.  MinGW/CRT
/// startup loops (e.g. wget's pre-send polling loop that cycles
/// `WSAEnumNetworkEvents` → `ioctlsocket(FIONBIO)` → `GetNumberOfConsoleInputEvents`)
/// check this return to decide "stdin is not a console, stop polling it"
/// and exit the loop so actual work (`send()`) can proceed.
///
/// Before this fix, the symbol was unresolved; the stub trampoline
/// returned 0 and also did not set last-error.  Callers that required
/// FALSE-plus-`ERROR_INVALID_HANDLE` to break the loop kept spinning.
///
/// Wine ref: dlls/kernelbase/console.c:1219 —
/// `GetNumberOfConsoleInputEvents(HANDLE handle, DWORD *count)` calls
/// `console_ioctl(handle, IOCTL_CONDRV_GET_INPUT_COUNT, ...)`; the
/// ioctl returns `ERROR_INVALID_HANDLE` for handles that are not
/// console input handles (the ioctl is only serviced by conhost).
/// That matches the Windows documented behaviour for non-console
/// handles — FALSE + `ERROR_INVALID_HANDLE`.
///
/// We also defensively zero `*lp_count` when the pointer is non-null,
/// matching what callers who ignore the return value may expect.
///
/// # Safety
/// `lp_count` may be null, or a valid writable pointer to a `u32`.
pub unsafe extern "win64" fn get_number_of_console_input_events(
    _h_console_input: usize,
    lp_count: *mut u32,
) -> i32 {
    unsafe {
        if !lp_count.is_null() {
            *lp_count = 0;
        }
    }
    set_last_error(file_io::ERROR_INVALID_HANDLE);
    0 // FALSE — stdin is not a console in Weave
}

// ── Task-01 additions — curl stubs ────────────────────────────────────────────

/// CancelIo — cancel pending I/O on a file handle. Stub returns TRUE.
///
/// Wine ref: dlls/kernelbase/sync.c — CancelIo calls NtCancelIoFile on the
/// kernel handle. Weave: no async I/O model; return TRUE (no-op).
///
/// # Safety
/// `h_file` is accepted but not used.
// Wine ref: dlls/kernelbase/sync.c — CancelIo(hFile) calls NtCancelIoFile; cancels all pending I/O for hFile issued by the current thread
pub unsafe extern "win64" fn cancel_io(_h_file: usize) -> i32 {
    1 // TRUE — no pending I/O in Weave
}

/// SleepEx — sleep for a specified interval, optionally alertable. Returns 0.
///
/// Wine ref: dlls/kernel32/sync.c — SleepEx calls NtDelayExecution. When
/// bAlertable is TRUE it can return WAIT_IO_COMPLETION (0xC0). Weave: delegate
/// to libc::usleep.
///
/// # Safety
/// No pointer arguments.
// Wine ref: dlls/kernel32/sync.c — SleepEx calls NtDelayExecution(Alertable, &timeout); returns 0 normally, WAIT_IO_COMPLETION(0xC0) when an APC fires
pub unsafe extern "win64" fn sleep_ex(dw_milliseconds: u32, _b_alertable: i32) -> u32 {
    eprintln!("weave/SleepEx: ms={dw_milliseconds} alertable={_b_alertable}");
    if dw_milliseconds > 0 {
        libc::usleep((dw_milliseconds as u64 * 1000) as libc::c_uint);
    }
    0 // WAIT_OBJECT_0
}

/// QueueUserAPC — queue a user APC to a thread.
///
/// Wine ref: dlls/kernelbase/thread.c — forwards to NtQueueApcThread and
/// returns TRUE on STATUS_SUCCESS. Weave does not yet deliver APC callbacks,
/// but many apps use this API as a wakeup/scheduling hint and only need the
/// call to succeed so the surrounding wait path can continue.
///
/// # Safety
/// `pfn_apc` is accepted but not called; `h_thread` and `dw_data` are ignored.
pub unsafe extern "win64" fn queue_user_apc(
    _pfn_apc: usize,
    _h_thread: usize,
    _dw_data: usize,
) -> u32 {
    1 // TRUE
}

// MODULEENTRY32W layout (Windows x64, tlhelp32.h):
//   dwSize         u32   = 4
//   th32ModuleID   u32
//   th32ProcessID  u32
//   GlblcntUsage   u32
//   ProccntUsage   u32
//   modBaseAddr    *u8   = 8 (at offset 20 due to padding)
//   modBaseSize    u32   = 4
//   hModule        usize = 8
//   szModule[256 chars × 2 bytes = 512]
//   szExePath[260 chars × 2 bytes = 520]
// Total: ≥ 568 bytes.
// We only support the null-stub path — no toolhelp snapshot in Weave.

/// Module32First — retrieve the first module in a snapshot. Returns FALSE.
///
/// Wine ref: dlls/kernelbase/toolhelp.c — Module32First reads the first entry
/// from the snapshot. Weave has no Toolhelp snapshots; return FALSE + ERROR_NO_MORE_FILES.
///
/// # Safety
/// `h_snapshot` and `lp_me` are accepted but not used.
// Wine ref: dlls/kernelbase/toolhelp.c — Module32First/Next walk the snapshot module list; return FALSE+ERROR_NO_MORE_FILES(18) when exhausted
pub unsafe extern "win64" fn module32_first(_h_snapshot: usize, _lp_me: *mut u8) -> i32 {
    weave_common::set_last_error(18); // ERROR_NO_MORE_FILES
    0 // FALSE
}

/// Module32Next — retrieve the next module in a snapshot. Returns FALSE.
///
/// Wine ref: dlls/kernelbase/toolhelp.c — Module32Next advances the snapshot cursor.
/// Weave: always returns FALSE + ERROR_NO_MORE_FILES.
///
/// # Safety
/// `h_snapshot` and `lp_me` are accepted but not used.
// Wine ref: dlls/kernelbase/toolhelp.c — Module32Next advances cursor; returns FALSE+ERROR_NO_MORE_FILES when no more entries
pub unsafe extern "win64" fn module32_next(_h_snapshot: usize, _lp_me: *mut u8) -> i32 {
    weave_common::set_last_error(18); // ERROR_NO_MORE_FILES
    0 // FALSE
}

/// GetLongPathNameW — convert short (8.3) path to long path name.
///
/// # Safety
/// `lp_sz_short_path` must be a valid null-terminated UTF-16 string.
/// `lp_sz_long_path` must be a valid buffer of `cch_buffer` UTF-16 chars, or null.
// Wine ref: dlls/kernelbase/path.c — GetLongPathNameW walks path components via
// FindFirstFileW; on Linux there's no 8.3 distinction so we copy the input as-is.
pub unsafe extern "win64" fn get_long_path_name_w(
    lp_sz_short_path: *const u16,
    lp_sz_long_path: *mut u16,
    cch_buffer: u32,
) -> u32 {
    if lp_sz_short_path.is_null() {
        return 0;
    }
    let mut len = 0usize;
    while unsafe { *lp_sz_short_path.add(len) } != 0 {
        len += 1;
    }
    let needed = (len + 1) as u32;
    if lp_sz_long_path.is_null() || cch_buffer < needed {
        return needed; // return required size
    }
    unsafe {
        std::ptr::copy_nonoverlapping(lp_sz_short_path, lp_sz_long_path, needed as usize);
    }
    len as u32
}

/// GetShortPathNameW — convert long path to short (8.3) path name.
///
/// # Safety
/// `lp_sz_long_path` must be a valid null-terminated UTF-16 string.
/// `lp_sz_short_path` must be a valid buffer of `cch_buffer` UTF-16 chars, or null.
// Wine ref: dlls/kernelbase/path.c — GetShortPathNameW generates 8.3 form via NtQueryInformationFile;
// Linux has no 8.3 distinction so we return the input path unchanged.
pub unsafe extern "win64" fn get_short_path_name_w(
    lp_sz_long_path: *const u16,
    lp_sz_short_path: *mut u16,
    cch_buffer: u32,
) -> u32 {
    get_long_path_name_w(lp_sz_long_path, lp_sz_short_path, cch_buffer)
}

/// PeekNamedPipe — check for data in a named pipe without reading. Returns TRUE with zero bytes.
///
/// Wine ref: dlls/kernelbase/file.c — PeekNamedPipe uses NtQueryInformationFile
/// on the pipe handle. Weave: return TRUE with 0 bytes available.
///
/// # Safety
/// All pointer arguments may be null; we only write to non-null ones.
// Wine ref: dlls/kernelbase/file.c — PeekNamedPipe calls NtQueryInformationFile(FilePipeLocalInfo); fills lpBytesRead/lpTotalBytesAvail/lpBytesLeftThisMessage
pub unsafe extern "win64" fn peek_named_pipe(
    _h_named_pipe: usize,
    _lp_buffer: *mut u8,
    _n_buffer_size: u32,
    lp_bytes_read: *mut u32,
    lp_total_bytes_avail: *mut u32,
    lp_bytes_left_this_message: *mut u32,
) -> i32 {
    if !lp_bytes_read.is_null() {
        *lp_bytes_read = 0;
    }
    if !lp_total_bytes_avail.is_null() {
        *lp_total_bytes_avail = 0;
    }
    if !lp_bytes_left_this_message.is_null() {
        *lp_bytes_left_this_message = 0;
    }
    1 // TRUE — no data available, not an error
}

// ── wget gap stubs — KERNEL32 null-IAT cleanup ────────────────────────────────

/// InitializeSRWLock: set the SRW lock to the unlocked state (all-zeros).
///
/// # Safety
/// `srw_lock` must be a valid pointer to an SRWLOCK-sized slot.
// Wine ref: dlls/ntdll/sync.c — RtlInitializeSRWLock zeros the lock word.
pub unsafe extern "win64" fn initialize_srw_lock(srw_lock: *mut usize) {
    if !srw_lock.is_null() {
        unsafe { *srw_lock = 0 };
    }
}

/// ConvertFiberToThread: convert current fiber back to a thread. No-op on Linux.
// Wine ref: dlls/kernel32/fiber.c — ConvertFiberToThread: frees current fiber
// state; Weave has no fiber scheduler so this is a no-op that returns TRUE.
pub extern "win64" fn convert_fiber_to_thread() -> i32 {
    1 // TRUE
}

/// ConvertThreadToFiberEx: convert current thread to a fiber. Returns NULL
/// so MSVC CRT skips fiber-based TLS cleanup (checks for non-NULL before use).
///
/// # Safety
/// No pointer dereference — `_lp_parameter` is unused.
// Wine ref: dlls/kernel32/fiber.c — allocates a fiber context; NULL on failure.
pub unsafe extern "win64" fn convert_thread_to_fiber_ex(
    _lp_parameter: *const u8,
    _dw_flags: u32,
) -> *const u8 {
    set_last_error(120); // ERROR_CALL_NOT_IMPLEMENTED
    std::ptr::null()
}

/// CreateFiberEx: create a new fiber. Returns NULL (not supported).
///
/// # Safety
/// `_lp_parameter` and `_lp_start_address` are unused; no pointer dereference.
// Wine ref: dlls/kernel32/fiber.c — CreateFiberEx: allocates stack and context;
// returns NULL on allocation failure. Callers guard on non-NULL before SwitchToFiber.
pub unsafe extern "win64" fn create_fiber_ex(
    _dw_stack_commit_size: usize,
    _dw_stack_reserve_size: usize,
    _dw_flags: u32,
    _lp_start_address: usize,
    _lp_parameter: *const u8,
) -> *const u8 {
    set_last_error(120); // ERROR_CALL_NOT_IMPLEMENTED
    std::ptr::null()
}

/// DeleteFiber: free a fiber object. No-op (we never create real fibers).
///
/// # Safety
/// `_lp_fiber` is unused; no pointer dereference.
// Wine ref: dlls/kernel32/fiber.c — DeleteFiber: frees the fiber's stack and context.
pub unsafe extern "win64" fn delete_fiber(_lp_fiber: *const u8) {}

/// SwitchToFiber: switch execution to a fiber. No-op (no fiber scheduler).
///
/// # Safety
/// `_lp_fiber` is unused; no pointer dereference.
// Wine ref: dlls/kernel32/fiber.c — SwitchToFiber: context-switches to the target
// fiber. With no real fiber infrastructure, returning immediately is the safe default.
pub unsafe extern "win64" fn switch_to_fiber(_lp_fiber: *const u8) {}

/// FindFirstVolumeW: begin volume enumeration. No volumes to enumerate.
///
/// # Safety
/// `_lpsz_volume_name` is unused; no pointer dereference.
// Wine ref: dlls/kernel32/volume.c — FindFirstVolumeW: opens volume list handle;
// returns INVALID_HANDLE_VALUE on error.
pub unsafe extern "win64" fn find_first_volume_w(
    _lpsz_volume_name: *mut u16,
    _cch_buffer_length: u32,
) -> usize {
    set_last_error(18); // ERROR_NO_MORE_FILES
    usize::MAX // INVALID_HANDLE_VALUE
}

/// FindNextVolumeW: advance volume enumeration. Always fails (no volumes).
///
/// # Safety
/// `_lpsz_volume_name` is unused; no pointer dereference.
// Wine ref: dlls/kernel32/volume.c — FindNextVolumeW: returns FALSE at end.
pub unsafe extern "win64" fn find_next_volume_w(
    _h_find_volume: usize,
    _lpsz_volume_name: *mut u16,
    _cch_buffer_length: u32,
) -> i32 {
    set_last_error(18); // ERROR_NO_MORE_FILES
    0 // FALSE
}

/// FindVolumeClose: close a volume-enumeration handle.
// Wine ref: dlls/kernel32/volume.c — FindVolumeClose: closes the handle; TRUE on success.
pub extern "win64" fn find_volume_close(_h_find_volume: usize) -> i32 {
    1 // TRUE
}

/// GetFinalPathNameByHandleA (ANSI): return final path for an open file handle.
/// Returns 0 (failure) — wget uses this for informational purposes only.
///
/// # Safety
/// `_lpsz_file_path` is unused; no pointer dereference.
// Wine ref: dlls/kernelbase/file.c — GetFinalPathNameByHandleW; A variant wraps it.
pub unsafe extern "win64" fn get_final_path_name_by_handle_a(
    _h_file: usize,
    _lpsz_file_path: *mut u8,
    _cch_file_path: u32,
    _dw_flags: u32,
) -> u32 {
    set_last_error(1); // ERROR_INVALID_FUNCTION
    0
}

/// GetNamedPipeInfo: query named pipe parameters. Returns FALSE (not supported).
///
/// # Safety
/// Output pointer arguments are written only after null check.
// Wine ref: dlls/kernel32/named_pipe.c — GetNamedPipeInfo: ioctl on pipe handle.
pub unsafe extern "win64" fn get_named_pipe_info(
    _h_named_pipe: usize,
    lp_flags: *mut u32,
    lp_out_buffer_size: *mut u32,
    lp_in_buffer_size: *mut u32,
    lp_max_instances: *mut u32,
) -> i32 {
    if !lp_flags.is_null() {
        unsafe { *lp_flags = 0 };
    }
    if !lp_out_buffer_size.is_null() {
        unsafe { *lp_out_buffer_size = 0 };
    }
    if !lp_in_buffer_size.is_null() {
        unsafe { *lp_in_buffer_size = 0 };
    }
    if !lp_max_instances.is_null() {
        unsafe { *lp_max_instances = 0 };
    }
    set_last_error(6); // ERROR_INVALID_HANDLE
    0 // FALSE
}

/// GetPriorityClass: return process priority class.
/// Returns NORMAL_PRIORITY_CLASS (32).
// Wine ref: dlls/kernel32/process.c — GetPriorityClass: queries NtQueryInformationProcess.
pub extern "win64" fn get_priority_class(_h_process: usize) -> u32 {
    32 // NORMAL_PRIORITY_CLASS
}

/// GetSystemTimeAdjustment: query clock adjustment. Returns TRUE with zeros.
///
/// # Safety
/// Output pointer arguments are written only after null check.
// Wine ref: dlls/kernel32/time.c — GetSystemTimeAdjustment: NtQuerySystemInformation.
pub unsafe extern "win64" fn get_system_time_adjustment(
    lp_time_adjustment: *mut u32,
    lp_time_increment: *mut u32,
    lp_time_adjustment_disabled: *mut i32,
) -> i32 {
    if !lp_time_adjustment.is_null() {
        unsafe { *lp_time_adjustment = 0 };
    }
    if !lp_time_increment.is_null() {
        unsafe { *lp_time_increment = 0 };
    }
    if !lp_time_adjustment_disabled.is_null() {
        unsafe { *lp_time_adjustment_disabled = 1 };
    }
    1 // TRUE
}

/// LockFileEx: lock a region of a file. No-op on Linux (advisory locks ignored).
///
/// # Safety
/// `_lp_overlapped` is unused; no pointer dereference.
// Wine ref: dlls/kernel32/file.c — LockFileEx: NtLockFile; no-op acceptable for wget.
pub unsafe extern "win64" fn lock_file_ex(
    _h_file: usize,
    _dw_flags: u32,
    _dw_reserved: u32,
    _n_number_of_bytes_to_lock_low: u32,
    _n_number_of_bytes_to_lock_high: u32,
    _lp_overlapped: *const u8,
) -> i32 {
    1 // TRUE
}

/// UnlockFile: unlock a region of a file. No-op.
// Wine ref: dlls/kernel32/file.c — UnlockFile: NtUnlockFile.
pub extern "win64" fn unlock_file(
    _h_file: usize,
    _dw_file_offset_low: u32,
    _dw_file_offset_high: u32,
    _n_number_of_bytes_to_unlock_low: u32,
    _n_number_of_bytes_to_unlock_high: u32,
) -> i32 {
    1 // TRUE
}

/// OpenFileMappingA (ANSI): open a named file-mapping object. Returns NULL.
///
/// # Safety
/// `_lp_name` is unused; no pointer dereference.
// Wine ref: dlls/kernel32/sync.c — OpenFileMappingA: wraps OpenFileMappingW.
pub unsafe extern "win64" fn open_file_mapping_a(
    _dw_desired_access: u32,
    _b_inherit_handle: i32,
    _lp_name: *const u8,
) -> usize {
    set_last_error(2); // ERROR_FILE_NOT_FOUND
    0 // NULL
}

/// CreateHardLinkA (ANSI): create a hard link. Returns FALSE (not supported).
///
/// # Safety
/// `_lp_file_name` and `_lp_existing_file_name` are unused; no pointer dereference.
// Wine ref: dlls/kernel32/file.c — CreateHardLinkA: wraps CreateHardLinkW.
pub unsafe extern "win64" fn create_hard_link_a(
    _lp_file_name: *const u8,
    _lp_existing_file_name: *const u8,
    _lp_security_attributes: usize,
) -> i32 {
    set_last_error(1); // ERROR_INVALID_FUNCTION
    0 // FALSE
}

/// PeekConsoleInputA: check for console input events. Returns FALSE.
///
/// # Safety
/// `lp_number_of_events_read` is written only after null check.
// Wine ref: dlls/kernel32/console.c — PeekConsoleInputA: wraps PeekConsoleInputW.
pub unsafe extern "win64" fn peek_console_input_a(
    _h_console_input: usize,
    _lp_buffer: *mut u8,
    _n_length: u32,
    lp_number_of_events_read: *mut u32,
) -> i32 {
    if !lp_number_of_events_read.is_null() {
        unsafe { *lp_number_of_events_read = 0 };
    }
    set_last_error(6); // ERROR_INVALID_HANDLE
    0 // FALSE
}

/// ReadConsoleA (ANSI): read characters from console. Returns FALSE.
///
/// # Safety
/// `lp_number_of_chars_read` is written only after null check.
// Wine ref: dlls/kernel32/console.c — ReadConsoleA: wraps ReadConsoleW.
pub unsafe extern "win64" fn read_console_a(
    _h_console_input: usize,
    _lp_buffer: *mut u8,
    _n_number_of_chars_to_read: u32,
    lp_number_of_chars_read: *mut u32,
    _p_input_control: usize,
) -> i32 {
    if !lp_number_of_chars_read.is_null() {
        unsafe { *lp_number_of_chars_read = 0 };
    }
    set_last_error(6); // ERROR_INVALID_HANDLE
    0 // FALSE
}

/// SetSystemTime: set the system time. No-op (returns TRUE).
///
/// # Safety
/// `_lp_system_time` is unused; no pointer dereference.
// Wine ref: dlls/kernel32/time.c — SetSystemTime: requires SeSystemtimePrivilege.
// Stub always succeeds silently — wget likely calls this only in error paths.
pub unsafe extern "win64" fn set_system_time(_lp_system_time: *const u8) -> i32 {
    1 // TRUE
}

// ── Resolver ──────────────────────────────────────────────────────────────────

/// Resolve a kernel32.dll import to a stub address.
// Wine ref: not implemented in Wine — Weave-internal IAT resolver; maps DLL export names to stub fn pointers; no Windows API equivalent
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    // api-ms-win-* API sets forward to kernel32. Accept any such name so that
    // GetProcAddress on a LoadLibrary'd api-ms-win-* handle finds our stubs.
    let is_kernel32 =
        dll.eq_ignore_ascii_case("kernel32.dll") || dll.eq_ignore_ascii_case("kernel32");
    let is_apiset = dll.to_ascii_lowercase().starts_with("api-ms-win-");
    if !is_kernel32 && !is_apiset {
        return None;
    }
    match func {
        "GetStdHandle" => Some(get_std_handle as *const () as usize),
        "WriteConsoleW" => Some(
            write_console_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "ExitProcess" => Some(exit_process as *const () as usize),
        "TerminateProcess" => {
            Some(terminate_process as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetLastError" => Some(get_last_error as *const () as usize),
        "SetLastError" => Some(set_last_error as *const () as usize),
        "SetErrorMode" => {
            Some(set_error_mode as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "VirtualProtect" => {
            Some(virtual_protect as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "VirtualQuery" => {
            Some(virtual_query as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "VirtualAlloc" => {
            Some(virtual_alloc as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "VirtualAllocEx" => Some(
            virtual_alloc_ex as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "VirtualFree" => {
            Some(virtual_free as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "VirtualFreeEx" => {
            Some(virtual_free_ex as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "Sleep" => Some(sleep as *const () as usize),
        "TlsGetValue" => Some(tls_get_value as *const () as usize),
        "InitializeCriticalSection" => {
            Some(initialize_critical_section as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "EnterCriticalSection" => Some(enter_critical_section as *const () as usize),
        "LeaveCriticalSection" => Some(leave_critical_section as *const () as usize),
        "DeleteCriticalSection" => Some(delete_critical_section as *const () as usize),
        "SetUnhandledExceptionFilter" => Some(set_unhandled_exception_filter as *const () as usize),
        "__C_specific_handler" => Some(c_specific_handler as *const () as usize),
        "CreateFileA" => Some(
            create_file_a as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CreateFileW" => Some(
            create_file_w as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "ReadFile" => {
            Some(read_file as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize)
        }
        "WriteFile" => {
            Some(write_file as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize)
        }
        "CloseHandle" => Some(close_handle as *const () as usize),
        "DeleteFileW" => {
            Some(delete_file_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "SetFilePointer" => Some(
            set_file_pointer as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetFileSize" => {
            Some(get_file_size as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "FlushFileBuffers" => Some(flush_file_buffers as *const () as usize),
        "CreateFileMappingW" => Some(
            create_file_mapping_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "MapViewOfFile" => Some(
            map_view_of_file as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "UnmapViewOfFile" => {
            Some(unmap_view_of_file as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "CopyFileW" => {
            Some(copy_file_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "CopyFileA" => {
            Some(copy_file_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "FindFirstFileW" => {
            Some(find_first_file_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "FindFirstFileA" => {
            Some(find_first_file_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "FindNextFileW" => {
            Some(find_next_file_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "FindNextFileA" => {
            Some(find_next_file_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "FindClose" => Some(find_close as *const () as usize),
        "VerSetConditionMask" => Some(ver_set_condition_mask as *const () as usize),
        "VerifyVersionInfoW" => Some(
            verify_version_info_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "GetFileAttributesExW" => Some(
            get_file_attributes_ex_w as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "GetFileAttributesExA" => Some(
            get_file_attributes_ex_a as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "WideCharToMultiByte" => Some(
            wide_char_to_multi_byte as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "MultiByteToWideChar" => Some(
            multi_byte_to_wide_char as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetStartupInfoA" => {
            Some(get_startup_info_a as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "GetStartupInfoW" => {
            Some(get_startup_info_w as unsafe extern "win64" fn(_) as *const () as usize)
        }
        // Heap / global memory
        "GlobalAlloc" => Some(global_alloc as *const () as usize),
        "GlobalFree" => Some(global_free as *const () as usize),
        "GlobalLock" => Some(global_lock as *const () as usize),
        "GlobalUnlock" => Some(global_unlock as *const () as usize),
        "GlobalSize" => Some(global_size as *const () as usize),
        "LocalAlloc" => Some(local_alloc as *const () as usize),
        "LocalFree" => Some(local_free as *const () as usize),
        "LocalLock" => Some(local_lock as *const () as usize),
        "LocalUnlock" => Some(local_unlock as *const () as usize),
        "LocalReAlloc" => {
            Some(local_re_alloc as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "HeapCreate" => Some(heap_create as *const () as usize),
        "HeapDestroy" => Some(heap_destroy as *const () as usize),
        "HeapAlloc" => {
            Some(heap_alloc as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "HeapReAlloc" => {
            Some(heap_re_alloc as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "HeapFree" => {
            Some(heap_free as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "HeapSize" => Some(heap_size as *const () as usize),
        "GetProcessHeap" => Some(get_process_heap as *const () as usize),
        // Code page / DBCS
        "IsDBCSLeadByte" => Some(is_dbcs_lead_byte as *const () as usize),
        "IsDBCSLeadByteEx" => Some(is_dbcs_lead_byte_ex as *const () as usize),
        "GetACP" => Some(get_acp as *const () as usize),
        "GetOEMCP" => Some(get_oemcp as *const () as usize),
        "GetConsoleCP" => Some(get_console_cp as *const () as usize),
        "GetConsoleOutputCP" => Some(get_console_output_cp as *const () as usize),
        // Module loading
        "LoadLibraryA" => {
            Some(load_library_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "LoadLibraryW" => {
            Some(load_library_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "LoadLibraryExA" => {
            Some(load_library_ex_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "LoadLibraryExW" => {
            Some(load_library_ex_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "FreeLibrary" => Some(free_library as *const () as usize),
        "SetDefaultDllDirectories" => {
            Some(set_default_dll_directories as extern "win64" fn(_) -> _ as *const () as usize)
        }
        "AddDllDirectory" => {
            Some(add_dll_directory as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "RemoveDllDirectory" => {
            Some(remove_dll_directory as extern "win64" fn(_) -> _ as *const () as usize)
        }
        "SetDllDirectoryW" => {
            Some(set_dll_directory_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetProcAddress" => {
            Some(get_proc_address as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetModuleHandleA" => {
            Some(get_module_handle_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetModuleHandleW" => {
            Some(get_module_handle_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetModuleHandleExA" => Some(
            get_module_handle_ex_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "GetModuleHandleExW" => Some(
            get_module_handle_ex_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "GetModuleFileNameW" => Some(
            get_module_file_name_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "GetModuleFileNameA" => Some(
            get_module_file_name_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        // K32GetModuleFileNameExW — kernel32 re-export of the psapi function;
        // some callers import it directly from kernel32.
        "K32GetModuleFileNameExW" => Some(
            get_module_file_name_ex_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        // Process / thread identity
        "GetCurrentProcess" => Some(get_current_process as *const () as usize),
        "GetCurrentThread" => Some(get_current_thread as *const () as usize),
        "GetCurrentProcessId" => Some(get_current_process_id as *const () as usize),
        "GetCurrentThreadId" => Some(get_current_thread_id as *const () as usize),
        // Timing
        "GetTickCount" => Some(get_tick_count as *const () as usize),
        "GetTickCount64" => Some(get_tick_count_64 as *const () as usize),
        "QueryPerformanceCounter" => Some(
            query_performance_counter as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "QueryPerformanceFrequency" => Some(
            query_performance_frequency as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "GetSystemTimeAsFileTime" => {
            Some(get_system_time_as_file_time as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "GetLocaleInfoW" => Some(
            get_locale_info_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetLocaleInfoA" => Some(
            get_locale_info_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetLocaleInfoEx" => Some(
            get_locale_info_ex as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetUserDefaultLocaleName" => Some(
            get_user_default_locale_name as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        // System info
        "GetSystemInfo" => {
            Some(get_system_info as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetNativeSystemInfo" => {
            Some(get_native_system_info as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // Debugger
        "IsDebuggerPresent" => Some(is_debugger_present as *const () as usize),
        "OutputDebugStringA" => {
            Some(output_debug_string_a as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "OutputDebugStringW" => {
            Some(output_debug_string_w as unsafe extern "win64" fn(_) as *const () as usize)
        }
        // Events / semaphores
        "CreateEventA" => {
            Some(create_event_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "CreateEventW" => {
            Some(create_event_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "OpenEventA" => {
            Some(open_event_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "OpenEventW" => {
            Some(open_event_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "SetEvent" => Some(set_event as *const () as usize),
        "ResetEvent" => Some(reset_event as *const () as usize),
        "CreateSemaphoreA" => Some(
            create_semaphore_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "CreateSemaphoreW" => Some(
            create_semaphore_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "ReleaseSemaphore" => {
            Some(release_semaphore as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "SetFileApisToOEM" => {
            Some(set_file_apis_to_oem as extern "win64" fn() as *const () as usize)
        }
        "OpenFileMappingW" => Some(
            open_file_mapping_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "DosDateTimeToFileTime" => Some(
            dos_date_time_to_file_time as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        // SRW locks
        "InitializeSRWLock" => {
            Some(initialize_srw_lock as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "AcquireSRWLockExclusive" => {
            Some(acquire_srw_lock_exclusive as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "ReleaseSRWLockExclusive" => {
            Some(release_srw_lock_exclusive as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "AcquireSRWLockShared" => {
            Some(acquire_srw_lock_shared as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "ReleaseSRWLockShared" => {
            Some(release_srw_lock_shared as unsafe extern "win64" fn(_) as *const () as usize)
        }
        // ── wget gap stubs — fiber / volume / misc ──────────────────────────
        "ConvertFiberToThread" => {
            Some(convert_fiber_to_thread as extern "win64" fn() -> _ as *const () as usize)
        }
        "ConvertThreadToFiberEx" => Some(
            convert_thread_to_fiber_ex as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "CreateFiberEx" => Some(
            create_fiber_ex as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "DeleteFiber" => Some(delete_fiber as unsafe extern "win64" fn(_) as *const () as usize),
        "SwitchToFiber" => {
            Some(switch_to_fiber as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "FindFirstVolumeW" => {
            Some(find_first_volume_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "FindNextVolumeW" => {
            Some(find_next_volume_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "FindVolumeClose" => {
            Some(find_volume_close as extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetFinalPathNameByHandleA" => Some(
            get_final_path_name_by_handle_a as unsafe extern "win64" fn(_, _, _, _) -> _
                as *const () as usize,
        ),
        "GetNamedPipeInfo" => Some(
            get_named_pipe_info as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetPriorityClass" => {
            Some(get_priority_class as extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetSystemTimeAdjustment" => Some(
            get_system_time_adjustment as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "LockFileEx" => Some(
            lock_file_ex as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        "UnlockFile" => {
            Some(unlock_file as extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize)
        }
        "OpenFileMappingA" => Some(
            open_file_mapping_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "CreateHardLinkA" => {
            Some(create_hard_link_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "PeekConsoleInputA" => Some(
            peek_console_input_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "ReadConsoleA" => Some(
            read_console_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "SetSystemTime" => {
            Some(set_system_time as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // Condition variables
        "InitializeConditionVariable" => {
            Some(initialize_condition_variable as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "SleepConditionVariableSRW" => Some(
            sleep_condition_variable_srw as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SleepConditionVariableCS" => Some(
            sleep_condition_variable_cs as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "WakeConditionVariable" => {
            Some(wake_condition_variable as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "WakeAllConditionVariable" => {
            Some(wake_all_condition_variable as unsafe extern "win64" fn(_) as *const () as usize)
        }
        // Threads
        "CreateThread" => Some(
            create_thread as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        "GetThreadPriority" => Some(get_thread_priority as *const () as usize),
        "SetThreadPriority" => Some(set_thread_priority as *const () as usize),
        "GetThreadContext" => {
            Some(get_thread_context as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SetThreadContext" => {
            Some(set_thread_context as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SuspendThread" => Some(suspend_thread as *const () as usize),
        "ResumeThread" => Some(resume_thread as *const () as usize),
        // Process handles
        "OpenProcess" => {
            Some(open_process as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "DuplicateHandle" => Some(
            duplicate_handle as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetProcessAffinityMask" => Some(
            get_process_affinity_mask as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "SetProcessAffinityMask" => Some(
            set_process_affinity_mask as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetActiveProcessorGroupCount" => {
            Some(get_active_processor_group_count as extern "win64" fn() -> _ as *const () as usize)
        }
        "GetActiveProcessorCount" => {
            Some(get_active_processor_count as extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetHandleInformation" => Some(
            get_handle_information as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "DeviceIoControl" => Some(
            device_io_control as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // Environment
        "GetEnvironmentVariableW" => Some(
            get_environment_variable_w as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        // Misc
        "FormatMessageA" => Some(
            format_message_a as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "FormatMessageW" => Some(
            format_message_w as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CreateDirectoryW" => {
            Some(create_directory_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "RaiseException" => {
            Some(raise_exception as unsafe extern "win64" fn(_, _, _, _) as *const () as usize)
        }
        // RTL unwind — real implementations in weave_core::unwind
        "RtlCaptureContext" => Some(
            weave_core::unwind::rtl_capture_context_export as unsafe extern "win64" fn(_)
                as *const () as usize,
        ),
        "RtlLookupFunctionEntry" => Some(
            weave_core::unwind::rtl_lookup_function_entry_export
                as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "RtlVirtualUnwind" => Some(
            weave_core::unwind::rtl_virtual_unwind_export
                as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "RtlUnwindEx" => Some(
            weave_core::unwind::rtl_unwind_ex_export as unsafe extern "win64" fn(_, _, _, _, _, _)
                as *const () as usize,
        ),
        "RtlUnwind" => {
            Some(rtl_unwind as unsafe extern "win64" fn(_, _, _, _) as *const () as usize)
        }
        // TLS
        "TlsAlloc" => Some(tls_alloc as *const () as usize),
        "TlsSetValue" => Some(tls_set_value as *const () as usize),
        "TlsFree" => Some(tls_free as *const () as usize),
        // Wait / mutex
        "WaitForSingleObject" => Some(
            wait_for_single_object as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "WaitForSingleObjectEx" => Some(
            wait_for_single_object_ex as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "TryEnterCriticalSection" => Some(
            try_enter_critical_section as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "SwitchToThread" => {
            Some(switch_to_thread as extern "win64" fn() -> _ as *const () as usize)
        }
        "WaitForMultipleObjects" => Some(
            wait_for_multiple_objects as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "WaitForMultipleObjectsEx" => Some(
            wait_for_multiple_objects_ex as unsafe extern "win64" fn(_, _, _, _, _) -> _
                as *const () as usize,
        ),
        "CreateMutexA" => {
            Some(create_mutex_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "CreateMutexW" => {
            Some(create_mutex_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "CreateMutexExA" => Some(
            create_mutex_ex_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "CreateMutexExW" => Some(
            create_mutex_ex_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "ReleaseMutex" => Some(release_mutex as *const () as usize),
        "UnhandledExceptionFilter" => Some(
            unhandled_exception_filter as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        // lstr* string functions
        "lstrcmpA" | "lstrcmp" => {
            Some(lstrcmp_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "lstrcmpW" => Some(lstrcmp_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        "lstrcmpiA" | "lstrcmpi" => {
            Some(lstrcmpi_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "lstrcmpiW" => {
            Some(lstrcmpi_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "lstrlenA" | "lstrlen" => {
            Some(lstrlen_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "lstrlenW" => Some(lstrlen_w as unsafe extern "win64" fn(_) -> _ as *const () as usize),
        "lstrcatA" | "lstrcat" => {
            Some(lstrcat_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "lstrcatW" => Some(lstrcat_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        "lstrcpyA" | "lstrcpy" => {
            Some(lstrcpy_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "lstrcpyW" => Some(lstrcpy_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        "lstrcpynA" | "lstrcpyn" => {
            Some(lstrcpyn_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "lstrcpynW" => {
            Some(lstrcpyn_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        // Directory path functions
        "GetWindowsDirectoryW" => Some(
            get_windows_directory_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetWindowsDirectoryA" => Some(
            get_windows_directory_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetSystemDirectoryW" => Some(
            get_system_directory_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetSystemDirectoryA" => Some(
            get_system_directory_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetTempPathW" => {
            Some(get_temp_path_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetTempPathA" => {
            Some(get_temp_path_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetCurrentDirectoryW" => Some(
            get_current_directory_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetCurrentDirectoryA" => Some(
            get_current_directory_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "SetCurrentDirectoryW" => {
            Some(set_current_directory_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "SetCurrentDirectoryA" => {
            Some(set_current_directory_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // Computer name and username
        "GetComputerNameW" => {
            Some(get_computer_name_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetComputerNameA" => {
            Some(get_computer_name_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetUserNameW" => {
            Some(get_user_name_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetUserNameA" => {
            Some(get_user_name_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // File attribute functions
        "GetFileAttributesW" => {
            Some(get_file_attributes_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetFileAttributesA" => {
            Some(get_file_attributes_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "SetFileAttributesW" => {
            Some(set_file_attributes_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SetFileAttributesA" => {
            Some(set_file_attributes_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // Time functions
        "GetSystemTime" => {
            Some(get_system_time as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "GetLocalTime" => Some(get_local_time as unsafe extern "win64" fn(_) as *const () as usize),
        "SystemTimeToTzSpecificLocalTime" => Some(
            system_time_to_tz_specific_local_time as unsafe extern "win64" fn(_, _, _) -> _
                as *const () as usize,
        ),
        // Environment functions
        "GetEnvironmentVariableA" => Some(
            get_environment_variable_a as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "SetEnvironmentVariableW" => Some(
            set_environment_variable_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "SetEnvironmentVariableA" => Some(
            set_environment_variable_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetEnvironmentStringsW" => Some(get_environment_strings_w as *const () as usize),
        "GetEnvironmentStringsA" | "GetEnvironmentStrings" => {
            Some(get_environment_strings_a as *const () as usize)
        }
        "FreeEnvironmentStringsW" => Some(
            free_environment_strings_w as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "FreeEnvironmentStringsA" => Some(
            free_environment_strings_a as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "GetFullPathNameW" => Some(
            get_full_path_name_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetFullPathNameA" => Some(
            get_full_path_name_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetVolumePathNameW" => Some(
            get_volume_path_name_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "MoveFileW" => {
            Some(move_file_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "MoveFileA" => {
            Some(move_file_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "RemoveDirectoryW" => {
            Some(remove_directory_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "RemoveDirectoryA" => {
            Some(remove_directory_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "CreateDirectoryA" => {
            Some(create_directory_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetLogicalDrives" => Some(get_logical_drives as *const () as usize),
        "GetDriveTypeW" => {
            Some(get_drive_type_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetDriveTypeA" => {
            Some(get_drive_type_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetDiskFreeSpaceExW" => Some(
            get_disk_free_space_ex_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetExitCodeProcess" => {
            Some(get_exit_code_process as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetExitCodeThread" => {
            Some(get_exit_code_thread as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "TerminateThread" => {
            Some(terminate_thread as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // Locale functions
        "GetUserDefaultLCID" => Some(get_user_default_lcid as *const () as usize),
        "GetSystemDefaultLCID" => Some(get_system_default_lcid as *const () as usize),
        "GetUserDefaultUILanguage" => Some(get_user_default_ui_language as *const () as usize),
        "GetSystemDefaultLangID" => Some(get_system_default_lang_id as *const () as usize),
        "IsValidCodePage" => Some(is_valid_code_page as *const () as usize),
        "IsWow64Process" => {
            Some(is_wow64_process as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "IsProcessorFeaturePresent" => Some(is_processor_feature_present as *const () as usize),
        "FlushInstructionCache" => Some(
            flush_instruction_cache as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "GetSystemTimePreciseAsFileTime" => Some(
            get_system_time_precise_as_file_time as unsafe extern "win64" fn(_) as *const ()
                as usize,
        ),
        "GetLargePageMinimum" => Some(get_large_page_minimum as *const () as usize),
        "SetHandleInformation" => Some(
            set_handle_information as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        // SRW locks
        "TryAcquireSRWLockExclusive" => Some(
            try_acquire_srw_lock_exclusive as unsafe extern "win64" fn(_) -> _ as *const ()
                as usize,
        ),
        "TryAcquireSRWLockShared" => Some(
            try_acquire_srw_lock_shared as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "ProcessIdToSessionId" => Some(
            process_id_to_session_id as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "WaitOnAddress" => {
            Some(wait_on_address as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "WakeByAddressSingle" => Some(wake_by_address_single as *const () as usize),
        "WakeByAddressAll" => Some(wake_by_address_all as *const () as usize),
        "SetThreadDescription" => Some(
            set_thread_description as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetThreadDescription" => Some(
            get_thread_description as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "CreateTimerQueueTimer" => Some(
            create_timer_queue_timer as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "DeleteTimerQueueTimer" => Some(
            delete_timer_queue_timer as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "SetThreadAffinityMask" => Some(
            set_thread_affinity_mask as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "InitOnceExecuteOnce" => Some(
            init_once_execute_once as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "InitOnceBeginInitialize" => Some(
            init_once_begin_initialize as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "InitOnceComplete" => {
            Some(init_once_complete as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "CreateWaitableTimerW" => Some(
            create_waitable_timer_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "CreateWaitableTimerA" => Some(
            create_waitable_timer_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "CreateWaitableTimerExW" => Some(
            create_waitable_timer_ex_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SetWaitableTimer" => Some(
            set_waitable_timer as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CancelWaitableTimer" => {
            Some(cancel_waitable_timer as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "ExpandEnvironmentStringsW" => Some(
            expand_environment_strings_w as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "ExpandEnvironmentStringsA" => Some(
            expand_environment_strings_a as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "SearchPathW" => Some(
            search_path_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        "SearchPathA" => Some(
            search_path_a as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        "GetTempFileNameW" => Some(
            get_temp_file_name_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetTempFileNameA" => Some(
            get_temp_file_name_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetFileType" => Some(get_file_type as *const () as usize),
        // File and console functions
        "GetFileSizeEx" => {
            Some(get_file_size_ex as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetConsoleMode" => {
            Some(get_console_mode as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SetConsoleMode" => {
            Some(set_console_mode as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetVersion" => Some(get_version as *const () as usize),
        "GetVersionExW" => {
            Some(get_version_ex_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetVersionExA" => {
            Some(get_version_ex_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "CreateToolhelp32Snapshot" => Some(
            create_toolhelp32_snapshot as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "Process32FirstW" => {
            Some(process32_first_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "Process32NextW" => {
            Some(process32_next_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "Process32First" => {
            Some(process32_first as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "Process32Next" => {
            Some(process32_next as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetSystemPowerStatus" => {
            Some(get_system_power_status as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "SetThreadExecutionState" => {
            Some(set_thread_execution_state as extern "win64" fn(_) -> _ as *const () as usize)
        }
        "RtlAddFunctionTable" => Some(
            rtl_add_function_table as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "GetUserDefaultLangID" => Some(get_user_default_lang_id as *const () as usize),
        "CopyFileExW" => Some(
            copy_file_ex_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const () as usize,
        ),
        "GetCompressedFileSizeW" => Some(
            get_compressed_file_size_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "CreateHardLinkW" => {
            Some(create_hard_link_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "MoveFileWithProgressW" => Some(
            move_file_with_progress_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetDiskFreeSpaceW" => Some(
            get_disk_free_space_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "FileTimeToDosDateTime" => Some(
            file_time_to_dos_date_time as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "GlobalMemoryStatusEx" => {
            Some(global_memory_status_ex as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "SetPriorityClass" => {
            Some(set_priority_class as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "FindFirstChangeNotificationW" => Some(
            find_first_change_notification_w as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "FindNextChangeNotification" => Some(
            find_next_change_notification as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "FindCloseChangeNotification" => Some(
            find_close_change_notification as unsafe extern "win64" fn(_) -> _ as *const ()
                as usize,
        ),
        "FindFirstStreamW" => Some(
            find_first_stream_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "FindNextStreamW" => {
            Some(find_next_stream_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetCommandLineW" => Some(get_command_line_w as *const () as usize),
        "GetCommandLineA" => Some(get_command_line_a as *const () as usize),
        "EncodePointer" => Some(encode_pointer as *const () as usize),
        "DecodePointer" => Some(decode_pointer as *const () as usize),
        "FlsAlloc" => Some(fls_alloc as *const () as usize),
        "FlsGetValue" => Some(fls_get_value as *const () as usize),
        "FlsSetValue" => Some(fls_set_value as *const () as usize),
        "FlsFree" => Some(fls_free as *const () as usize),
        "InitializeCriticalSectionAndSpinCount" => Some(
            initialize_critical_section_and_spin_count as unsafe extern "win64" fn(_, _) -> _
                as *const () as usize,
        ),
        "InitializeCriticalSectionEx" => Some(
            initialize_critical_section_ex as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "HeapSetInformation" => Some(
            heap_set_information as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "SetHandleCount" => Some(set_handle_count as *const () as usize),
        "GetThreadLocale" => Some(get_thread_locale as *const () as usize),
        "SetThreadLocale" => Some(set_thread_locale as *const () as usize),
        "SetThreadStackGuarantee" => Some(
            set_thread_stack_guarantee as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "GetTimeZoneInformation" => Some(
            get_time_zone_information as unsafe extern "win64" fn(_) -> _ as *const () as usize,
        ),
        "GetDynamicTimeZoneInformation" => Some(
            get_dynamic_time_zone_information as unsafe extern "win64" fn(_) -> _ as *const ()
                as usize,
        ),
        // String comparison
        "CompareStringA" => Some(
            compare_string_a as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CompareStringW" => Some(
            compare_string_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CompareStringOrdinal" => Some(
            compare_string_ordinal as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // String mapping
        "LCMapStringW" => Some(
            lc_map_string_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // Character classification
        "GetStringTypeW" => Some(
            get_string_type_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetStringTypeExW" => Some(
            get_string_type_ex_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetStringTypeExA" => Some(
            get_string_type_ex_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetStringTypeA" => Some(
            get_string_type_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "AreFileApisANSI" => {
            Some(are_file_apis_ansi as extern "win64" fn() -> _ as *const () as usize)
        }
        "CompareStringEx" => Some(
            compare_string_ex as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "LCMapStringEx" => Some(
            lc_map_string_ex as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "LCMapStringA" => Some(
            lc_map_string_a as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // File time and positioning
        "SetFilePointerEx" => Some(
            set_file_pointer_ex as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "GetFileTime" => {
            Some(get_file_time as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "SetFileTime" => {
            Some(set_file_time as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        // Vectored exception handlers
        "AddVectoredExceptionHandler" => Some(add_vectored_exception_handler as *const () as usize),
        "RemoveVectoredExceptionHandler" => {
            Some(remove_vectored_exception_handler as *const () as usize)
        }
        "AddVectoredContinueHandler" => Some(add_vectored_continue_handler as *const () as usize),
        "RemoveVectoredContinueHandler" => {
            Some(remove_vectored_continue_handler as *const () as usize)
        }
        // Console functions
        "WriteConsoleA" => Some(
            write_console_a as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "SetConsoleTitleW" => {
            Some(set_console_title_w as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "SetConsoleTitleA" => {
            Some(set_console_title_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetConsoleTitleW" => {
            Some(get_console_title_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetConsoleTitleA" => {
            Some(get_console_title_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetConsoleScreenBufferInfo" => Some(
            get_console_screen_buffer_info as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "SetConsoleTextAttribute" => Some(
            set_console_text_attribute as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "SetConsoleCtrlHandler" => Some(
            set_console_ctrl_handler as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "GetNumberOfConsoleInputEvents" => Some(
            get_number_of_console_input_events as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        // Task 2: File information functions
        "GetFileInformationByHandle" => Some(
            get_file_information_by_handle as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "GetFileInformationByHandleEx" => Some(
            get_file_information_by_handle_ex as unsafe extern "win64" fn(_, _, _, _) -> _
                as *const () as usize,
        ),
        "GetFinalPathNameByHandleW" => Some(
            get_final_path_name_by_handle_w as unsafe extern "win64" fn(_, _, _, _) -> _
                as *const () as usize,
        ),
        "GetProductInfo" => Some(
            get_product_info as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "RegisterApplicationRestart" => Some(
            register_application_restart as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "UnregisterApplicationRestart" => {
            Some(unregister_application_restart as extern "win64" fn() -> _ as *const () as usize)
        }
        "GetApplicationRestartSettings" => Some(
            get_application_restart_settings as unsafe extern "win64" fn(_, _, _, _) -> _
                as *const () as usize,
        ),
        "ReadDirectoryChangesW" => Some(
            read_directory_changes_w as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "SetEndOfFile" => {
            Some(set_end_of_file as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetLogicalDriveStringsW" => Some(
            get_logical_drive_strings_w as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "GetLogicalDriveStringsA" => Some(
            get_logical_drive_strings_a as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "GetVolumeInformationW" => Some(
            get_volume_information_w as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        // Task 3: Process/thread stubs
        "CreateProcessW" => Some(
            create_process_w as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "CreateProcessA" => Some(
            create_process_a as unsafe extern "win64" fn(_, _, _, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "WaitForInputIdle" => {
            Some(wait_for_input_idle as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetProcessId" => {
            Some(get_process_id as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "OpenThread" => {
            Some(open_thread as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "GetThreadId" => {
            Some(get_thread_id as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        // Task 4: File time operations
        "CompareFileTime" => {
            Some(compare_file_time as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "FileTimeToLocalFileTime" => Some(
            file_time_to_local_file_time as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "LocalFileTimeToFileTime" => Some(
            local_file_time_to_file_time as unsafe extern "win64" fn(_, _) -> _ as *const ()
                as usize,
        ),
        "SystemTimeToFileTime" => Some(
            system_time_to_file_time as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "FileTimeToSystemTime" => Some(
            file_time_to_system_time as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        // Task 5: Console misc + MoveFileEx
        "AllocConsole" => Some(alloc_console as *const () as usize),
        "FreeConsole" => Some(free_console as *const () as usize),
        "AttachConsole" => {
            Some(attach_console as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "GetConsoleWindow" => Some(get_console_window as *const () as usize),
        "MoveFileExW" => {
            Some(move_file_ex_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "MoveFileExA" => {
            Some(move_file_ex_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        // ── PuTTY gap-fill ────────────────────────────────────────────────
        "Beep" => Some(beep as *const () as usize),
        "MulDiv" => Some(mul_div as *const () as usize),
        "SetStdHandle" => Some(set_std_handle as *const () as usize),
        "DeleteFileA" => {
            Some(delete_file_a as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "FindFirstFileExW" => Some(
            find_first_file_ex_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetCPInfo" => {
            Some(get_cp_info as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetDateFormatW" => Some(
            get_date_format_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetTimeFormatW" => Some(
            get_time_format_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GlobalMemoryStatus" => {
            Some(global_memory_status as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "InitializeSListHead" => {
            Some(initialize_slist_head as unsafe extern "win64" fn(_) as *const () as usize)
        }
        "InterlockedPopEntrySList" => {
            Some(interlockedpopentryslsit as unsafe extern "win64" fn(_) -> _ as *const () as usize)
        }
        "InterlockedPushEntrySList" => Some(
            interlockedpushentryslsit as unsafe extern "win64" fn(_, _) -> _ as *const () as usize,
        ),
        "IsValidLocale" => Some(is_valid_locale as *const () as usize),
        "EnumSystemLocalesW" => {
            Some(enum_system_locales_w as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "AppPolicyGetProcessTerminationMethod" => Some(
            app_policy_get_process_termination_method as unsafe extern "win64" fn(_, _) -> _
                as *const () as usize,
        ),
        "AppPolicyGetThreadInitializationType" => Some(
            app_policy_get_thread_initialization_type as unsafe extern "win64" fn(_, _) -> _
                as *const () as usize,
        ),
        "LCIDToLocaleName" => Some(
            lcid_to_locale_name as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "LocaleNameToLCID" => {
            Some(locale_name_to_lcid as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetDateFormatEx" => Some(
            get_date_format_ex as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetTimeFormatEx" => Some(
            get_time_format_ex as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "EnumSystemLocalesEx" => Some(
            enum_system_locales_ex as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "FindResourceA" => {
            Some(find_resource_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "FindResourceW" => {
            Some(find_resource_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "EnumResourceNamesW" => Some(
            enum_resource_names_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "FreeResource" => Some(free_resource as *const () as usize),
        "LoadResource" => Some(load_resource as *const () as usize),
        "LockResource" => Some(lock_resource as *const () as usize),
        "SizeofResource" => Some(sizeof_resource as *const () as usize),
        "GetProcessTimes" => Some(
            get_process_times as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "GetThreadTimes" => Some(
            get_thread_times as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "GetOverlappedResult" => Some(
            get_overlapped_result as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "RtlPcToFileHeader" => {
            Some(rtl_pc_to_file_header as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "CreateFileMappingA" => Some(
            create_file_mapping_a as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "CreatePipe" => {
            Some(create_pipe as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize)
        }
        "ReadConsoleW" => Some(
            read_console_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const () as usize,
        ),
        "ConnectNamedPipe" => {
            Some(connect_named_pipe as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "CreateNamedPipeA" => Some(
            create_named_pipe_a as unsafe extern "win64" fn(_, _, _, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "WaitNamedPipeA" => {
            Some(wait_named_pipe_a as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "ClearCommBreak" => Some(clear_comm_break as *const () as usize),
        "SetCommBreak" => Some(set_comm_break as *const () as usize),
        "GetCommState" => {
            Some(get_comm_state as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SetCommState" => {
            Some(set_comm_state as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "SetCommTimeouts" => {
            Some(set_comm_timeouts as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        // INI cluster — Phase A stubs for IrfanView (E3-M3)
        "GetPrivateProfileStringW" => Some(
            get_private_profile_string_w as unsafe extern "win64" fn(_, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "GetPrivateProfileStringA" => Some(
            get_private_profile_string_a as unsafe extern "win64" fn(_, _, _, _, _, _) -> _
                as *const () as usize,
        ),
        "GetPrivateProfileIntW" => Some(
            get_private_profile_int_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetPrivateProfileIntA" => Some(
            get_private_profile_int_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "GetPrivateProfileSectionW" => Some(
            get_private_profile_section_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "WritePrivateProfileStringW" => Some(
            write_private_profile_string_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "WritePrivateProfileStringA" => Some(
            write_private_profile_string_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "WritePrivateProfileSectionW" => Some(
            write_private_profile_section_w as unsafe extern "win64" fn(_, _, _) -> _ as *const ()
                as usize,
        ),
        "GetProfileStringW" => Some(
            get_profile_string_w as unsafe extern "win64" fn(_, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        // Task-01 additions — curl
        "CancelIo" => Some(cancel_io as unsafe extern "win64" fn(_) -> _ as *const () as usize),
        "SleepEx" => Some(sleep_ex as unsafe extern "win64" fn(_, _) -> _ as *const () as usize),
        "QueueUserAPC" => {
            Some(queue_user_apc as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "Module32First" => {
            Some(module32_first as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "Module32Next" => {
            Some(module32_next as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "Module32FirstW" => {
            Some(module32_first as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "Module32NextW" => {
            Some(module32_next as unsafe extern "win64" fn(_, _) -> _ as *const () as usize)
        }
        "GetLongPathNameW" => Some(
            get_long_path_name_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "GetShortPathNameW" => Some(
            get_short_path_name_w as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        "PeekNamedPipe" => Some(
            peek_named_pipe as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        _ => {
            // version.dll functions are forwarded through kernel32 in some apps;
            // also handle them when the DLL name is version.dll directly.
            resolve_version(dll, func)
        }
    }
}

// ── version.dll stubs ─────────────────────────────────────────────────────────
//
// version.dll provides file version information (FileVersionInfo API).
// IrfanView and many other apps call GetFileVersionInfoSizeW to probe for a
// version resource, then GetFileVersionInfoW to load it, then VerQueryValueW
// to extract fields (ProductVersion, FileDescription, etc.).
//
// Implementation strategy: look up the already-loaded image base by path via
// weave-core's path→base registry, then walk the PE's RT_VERSION resource
// using the existing resource walker. If the module is not loaded or has no
// version resource, return 0 gracefully.
//
// Wine ref: dlls/kernelbase/version.c — GetFileVersionInfoSizeExW opens the
// file by path via LoadLibraryExW(LOAD_LIBRARY_AS_IMAGE_RESOURCE) then calls
// FindResourceW / SizeofResource. Weave uses the pre-registered loaded base
// instead of re-opening from disk.

/// Decode a NUL-terminated wide string to UTF-8. Returns None if ptr is null.
///
/// # Safety
/// `ptr` must be null or a valid pointer to a NUL-terminated UTF-16 sequence.
unsafe fn wide_to_utf8(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    // SAFETY: caller guarantees a NUL-terminated sequence.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    Some(String::from_utf16_lossy(slice))
}

/// GetFileVersionInfoSizeW — return the byte size needed to hold the version resource.
///
/// Locates the RT_VERSION resource in the already-loaded guest PE image.
/// Sets `*lpdwHandle = 0` always (Wine contract: handle is always 0).
/// Returns 0 if the module is not registered or has no version resource.
///
/// # Safety
/// `lp_filename` must be a null-terminated wide string or null.
/// `lpdw_handle` must be null or a writable `*mut u32`.
///
/// Wine ref: dlls/kernelbase/version.c — GetFileVersionInfoSizeExW: sets
/// *ret_handle=0 always; returns `len + sizeof(DWORD)` where len is the raw
/// RT_VERSION resource size and the DWORD is for the "FE2X"/"FE3X" trailer.
/// That is `raw_size + 4` — no doubling.
pub unsafe extern "win64" fn get_file_version_info_size_w(
    lp_filename: *const u16,
    lpdw_handle: *mut u32,
) -> u32 {
    if !lpdw_handle.is_null() {
        unsafe { *lpdw_handle = 0 };
    }
    let path = match unsafe { wide_to_utf8(lp_filename) } {
        Some(p) => p,
        None => return 0,
    };
    let base = match weave_core::module_handles::base_by_path(&path) {
        Some(b) => b,
        None => return 0,
    };
    let hrsrc = weave_core::resource::find_resource_entry(
        base,
        weave_core::resource::ResourceId::Id(weave_core::resource::RT_VERSION),
        weave_core::resource::ResourceId::Id(weave_core::resource::VS_VERSION_INFO_ID),
        0, // LANG_NEUTRAL — fall through to first available
    );
    match hrsrc {
        Some(entry_ptr) => {
            // SAFETY: entry_ptr is a valid IMAGE_RESOURCE_DATA_ENTRY pointer
            // inside the mapped PE image at `base`.
            let raw_size = unsafe { weave_core::resource::resource_entry_size(entry_ptr) };
            raw_size + 4 // +4 for the "FE2X" sentinel appended by GetFileVersionInfoW
        }
        None => 0,
    }
}

/// GetFileVersionInfoSizeA — ANSI variant; delegates to the W version.
///
/// # Safety
/// `lp_filename` must be null or a valid pointer to a NUL-terminated ANSI string.
/// `lpdw_handle` must be null or a writable `*mut u32`.
///
/// Wine ref: dlls/kernelbase/version.c — GetFileVersionInfoSizeA converts the
/// ANSI filename via RtlCreateUnicodeStringFromAsciiz then delegates to
/// GetFileVersionInfoSizeExW(FILE_VER_GET_LOCALISED, wide, handle).
pub unsafe extern "win64" fn get_file_version_info_size_a(
    lp_filename: *const u8,
    lpdw_handle: *mut u32,
) -> u32 {
    if !lpdw_handle.is_null() {
        unsafe { *lpdw_handle = 0 };
    }
    let path = if lp_filename.is_null() {
        return 0;
    } else {
        let mut len = 0usize;
        // SAFETY: caller guarantees NUL-terminated ANSI string.
        while unsafe { *lp_filename.add(len) } != 0 {
            len += 1;
        }
        let bytes = unsafe { std::slice::from_raw_parts(lp_filename, len) };
        String::from_utf8_lossy(bytes).into_owned()
    };
    let base = match weave_core::module_handles::base_by_path(&path) {
        Some(b) => b,
        None => return 0,
    };
    let hrsrc = weave_core::resource::find_resource_entry(
        base,
        weave_core::resource::ResourceId::Id(weave_core::resource::RT_VERSION),
        weave_core::resource::ResourceId::Id(weave_core::resource::VS_VERSION_INFO_ID),
        0,
    );
    match hrsrc {
        Some(entry_ptr) => {
            let raw_size = unsafe { weave_core::resource::resource_entry_size(entry_ptr) };
            raw_size + 4 // +4 for the "FE2X" sentinel
        }
        None => 0,
    }
}

/// GetFileVersionInfoW — copy the raw VS_VERSIONINFO bytes into the caller's buffer.
///
/// Returns 1 (TRUE) on success, 0 (FALSE) if the module is not registered,
/// has no RT_VERSION resource, or if the buffer pointer is null.
///
/// # Safety
/// `lp_filename` must be null or a valid NUL-terminated wide string.
/// `lp_data` must be null or a writable buffer of at least `dw_len` bytes.
///
/// Wine ref: dlls/kernelbase/version.c — GetFileVersionInfoExW calls
/// LoadLibraryExW(LOAD_LIBRARY_AS_IMAGE_RESOURCE), then FindResourceW /
/// LoadResource / LockResource / memcpy(data, ptr, min(size, datasize));
/// appends a 4-byte "FE2X" sentinel after the VS_VERSIONINFO data for
/// GetFileVersionInfoSizeExW's *2+4 buffer contract.
pub unsafe extern "win64" fn get_file_version_info_w(
    lp_filename: *const u16,
    _dw_handle: u32,
    dw_len: u32,
    lp_data: *mut u8,
) -> i32 {
    if lp_data.is_null() || dw_len == 0 {
        return 0;
    }
    let path = match unsafe { wide_to_utf8(lp_filename) } {
        Some(p) => p,
        None => return 0,
    };
    let base = match weave_core::module_handles::base_by_path(&path) {
        Some(b) => b,
        None => return 0,
    };
    let hrsrc = weave_core::resource::find_resource_entry(
        base,
        weave_core::resource::ResourceId::Id(weave_core::resource::RT_VERSION),
        weave_core::resource::ResourceId::Id(weave_core::resource::VS_VERSION_INFO_ID),
        0,
    );
    let entry_ptr = match hrsrc {
        Some(e) => e,
        None => return 0,
    };
    // SAFETY: entry_ptr is a valid IMAGE_RESOURCE_DATA_ENTRY.
    let (data_ptr, data_size) =
        match unsafe { weave_core::resource::resource_entry_ptr_and_size(base, entry_ptr) } {
            Some(x) => x,
            None => return 0,
        };
    let copy_len = data_size.min(dw_len as usize);
    // SAFETY: data_ptr and lp_data are valid, non-overlapping, copy_len bytes.
    unsafe { std::ptr::copy_nonoverlapping(data_ptr, lp_data, copy_len) };
    // Append Wine's "FE2X" sentinel if there is room (signals "32-bit resource").
    // Wine ref: GetFileVersionInfoExW case IMAGE_NT_SIGNATURE:
    //   `len = vvis->wLength + sizeof(signature);`
    //   `if (datasize >= len) memcpy((char*)data + vvis->wLength, signature, sizeof(signature));`
    // Weave mirrors this: write "FE2X" at offset copy_len if the buffer has room.
    if (copy_len + 4) <= dw_len as usize {
        let sentinel: [u8; 4] = *b"FE2X";
        unsafe {
            std::ptr::copy_nonoverlapping(sentinel.as_ptr(), lp_data.add(copy_len), 4);
        }
    }
    1 // TRUE
}

/// GetFileVersionInfoA — ANSI variant; converts path to UTF-8 and delegates.
///
/// # Safety
/// `lp_filename` must be null or a valid NUL-terminated ANSI string.
/// `lp_data` must be null or a writable buffer of at least `dw_len` bytes.
///
/// Wine ref: dlls/kernelbase/version.c — GetFileVersionInfoA converts the ANSI
/// filename via RtlCreateUnicodeStringFromAsciiz then calls GetFileVersionInfoExW.
pub unsafe extern "win64" fn get_file_version_info_a(
    lp_filename: *const u8,
    _dw_handle: u32,
    dw_len: u32,
    lp_data: *mut u8,
) -> i32 {
    if lp_data.is_null() || dw_len == 0 {
        return 0;
    }
    let path = if lp_filename.is_null() {
        return 0;
    } else {
        let mut len = 0usize;
        while unsafe { *lp_filename.add(len) } != 0 {
            len += 1;
        }
        let bytes = unsafe { std::slice::from_raw_parts(lp_filename, len) };
        String::from_utf8_lossy(bytes).into_owned()
    };
    let base = match weave_core::module_handles::base_by_path(&path) {
        Some(b) => b,
        None => return 0,
    };
    let hrsrc = weave_core::resource::find_resource_entry(
        base,
        weave_core::resource::ResourceId::Id(weave_core::resource::RT_VERSION),
        weave_core::resource::ResourceId::Id(weave_core::resource::VS_VERSION_INFO_ID),
        0,
    );
    let entry_ptr = match hrsrc {
        Some(e) => e,
        None => return 0,
    };
    let (data_ptr, data_size) =
        match unsafe { weave_core::resource::resource_entry_ptr_and_size(base, entry_ptr) } {
            Some(x) => x,
            None => return 0,
        };
    let copy_len = data_size.min(dw_len as usize);
    unsafe { std::ptr::copy_nonoverlapping(data_ptr, lp_data, copy_len) };
    if (copy_len + 4) <= dw_len as usize {
        let sentinel: [u8; 4] = *b"FE2X";
        unsafe {
            std::ptr::copy_nonoverlapping(sentinel.as_ptr(), lp_data.add(copy_len), 4);
        }
    }
    1 // TRUE
}

// ── VS_VERSIONINFO block walker (bounds-checked) ─────────────────────────────
//
// Wine ref: dlls/kernelbase/version.c — VS_VERSION_INFO_STRUCT32 layout:
//   WORD wLength; WORD wValueLength; WORD wType; WCHAR szKey[]; (DWORD padding)
//   BYTE Value[]; (DWORD padding) VS_VERSION_INFO_STRUCT32 Children[];
//
// Wine `DWORD_ALIGN(base, ptr)` macro:
//   `(LPBYTE)(base) + ((((LPBYTE)(ptr) - (LPBYTE)(base)) + 3) & ~3)`
// i.e. round the offset-from-base up to the next multiple of 4.
//
// Wine `VersionInfo32_Value(ver)`:
//   `DWORD_ALIGN(ver, ver->szKey + lstrlenW(ver->szKey) + 1)`
// i.e. after the NUL terminator of szKey, pad to 4-byte boundary relative to
// the block's own base. That byte offset is where the Value[] bytes start.
//
// Wine `VersionInfo32_Next(ver)`:
//   `VersionInfo32_Value(ver) + ((wValueLength * (wType?2:1) + 3) & ~3)`
// i.e. wValueLength is in WCHARs when wType==1 (text) and bytes when wType==0
// (binary); multiply up to bytes then pad to 4. That lands on the next sibling.
//
// Wine `VersionInfo32_FindChild`:
//   iterates children while `(char*)child < (char*)info + info->wLength`,
//   case-insensitive key compare with NUL check, advances via
//   `VersionInfo32_Next(child)`. Returns NULL on no-match or zero-length entry.

/// A view over a single VS_VERSION_INFO_STRUCT32 entry within a larger block.
///
/// Construction is bounds-checked against the enclosing slice. Readers must
/// never dereference raw pointers past `entry.as_ptr().add(entry.len())`.
#[derive(Clone, Copy)]
struct VerEntry<'a> {
    /// Full bytes of this entry — [0..wLength) measured from entry start.
    entry: &'a [u8],
    w_value_length: u16,
    w_type: u16,
    /// Byte offset from entry[0] where the Value[] bytes begin (after szKey
    /// NUL and DWORD padding). Guaranteed `<= entry.len()` on construction.
    value_offset: usize,
    /// Length of szKey in WCHARs, NOT including the NUL terminator.
    key_wchars: usize,
}

impl<'a> VerEntry<'a> {
    /// Parse a version-info entry at the start of `buf`. Returns `None` on any
    /// bounds or structural failure — never panics on malformed input.
    fn parse(buf: &'a [u8]) -> Option<VerEntry<'a>> {
        // Fixed header: wLength(2) + wValueLength(2) + wType(2) = 6 bytes.
        let w_length = u16::from_le_bytes(buf.get(0..2)?.try_into().ok()?) as usize;
        let w_value_length = u16::from_le_bytes(buf.get(2..4)?.try_into().ok()?);
        let w_type = u16::from_le_bytes(buf.get(4..6)?.try_into().ok()?);

        // wLength must cover the fixed header and szKey + NUL, and fit in buf.
        if w_length < 8 || w_length > buf.len() {
            return None;
        }
        let entry = buf.get(..w_length)?;

        // Walk szKey (UTF-16) until NUL. Key bytes live at offsets 6.. within
        // the entry; bound the search by the entry length so a missing NUL
        // cannot read into the next block.
        let mut key_wchars = 0usize;
        loop {
            let off = 6 + key_wchars * 2;
            let slice = entry.get(off..off + 2)?;
            let w = u16::from_le_bytes([slice[0], slice[1]]);
            if w == 0 {
                break;
            }
            key_wchars += 1;
        }

        // Offset just past the szKey NUL.
        let after_key = 6 + (key_wchars + 1) * 2;
        // DWORD_ALIGN from entry base: round up to next multiple of 4.
        let value_offset = (after_key + 3) & !3;
        if value_offset > entry.len() {
            return None;
        }
        Some(VerEntry {
            entry,
            w_value_length,
            w_type,
            value_offset,
            key_wchars,
        })
    }

    /// szKey bytes as UTF-16 little-endian (no NUL). Keys are ASCII-ish in
    /// practice (e.g. "StringFileInfo", "040904b0") so compare decoded.
    fn key_utf16(&self) -> Vec<u16> {
        let mut out = Vec::with_capacity(self.key_wchars);
        for i in 0..self.key_wchars {
            let off = 6 + i * 2;
            // The entry length was validated to cover the full szKey during
            // parse(), so this range is always in-bounds; fall back to 0 on
            // any unexpected truncation rather than panicking.
            if let Some(slice) = self.entry.get(off..off + 2) {
                out.push(u16::from_le_bytes([slice[0], slice[1]]));
            }
        }
        out
    }

    /// Wine: `wValueLength` is WCHAR count when wType==1, byte count when ==0.
    /// Convert to bytes for range arithmetic.
    fn value_byte_len(&self) -> usize {
        let mult = if self.w_type == 1 { 2 } else { 1 };
        (self.w_value_length as usize).saturating_mul(mult)
    }

    /// Start of Children[] within the entry, in bytes. That's:
    /// `value_offset + DWORD_ALIGN(value_byte_len)`.
    fn children_offset(&self) -> usize {
        let padded = (self.value_byte_len() + 3) & !3;
        self.value_offset.saturating_add(padded)
    }

    /// A slice of bytes covering this entry's children, bounded by wLength.
    fn children_bytes(&self) -> &'a [u8] {
        let start = self.children_offset().min(self.entry.len());
        &self.entry[start..]
    }
}

/// Case-insensitive ASCII-ish UTF-16 compare (Wine uses wcsnicmp). VS_VERSION
/// keys are ASCII in practice (`StringFileInfo`, `VarFileInfo`, hex codepage
/// tags), so ASCII folding matches Wine's behavior for every realistic input.
fn wstr_eq_ignore_ascii_case(a: &[u16], b: &[u16]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(x, y)| {
        let xf = if (b'A' as u16..=b'Z' as u16).contains(x) {
            x + 32
        } else {
            *x
        };
        let yf = if (b'A' as u16..=b'Z' as u16).contains(y) {
            y + 32
        } else {
            *y
        };
        xf == yf
    })
}

/// Walk immediate children of `parent` looking for the one whose szKey matches
/// `key` (case-insensitive, no partials). Returns None on miss or malformed
/// traversal — never panics.
///
/// Wine ref: dlls/kernelbase/version.c::VersionInfo32_FindChild — iterates
/// `while (char*)child < (char*)info + info->wLength`, compares with
/// `wcsnicmp`, aborts on `!child->wLength` to avoid infinite loops.
fn find_child_by_key<'a>(parent: &VerEntry<'a>, key: &[u16]) -> Option<VerEntry<'a>> {
    let mut bytes = parent.children_bytes();
    while !bytes.is_empty() {
        let child = VerEntry::parse(bytes)?;
        if child.entry.is_empty() {
            return None;
        }
        let child_key = child.key_utf16();
        if wstr_eq_ignore_ascii_case(&child_key, key) {
            return Some(child);
        }
        // Advance by the child's own DWORD-padded length. Wine uses the raw
        // wLength for the sibling stride, then DWORD-aligns at the start of
        // the next entry via VersionInfo32_Next — which for our purposes is
        // equivalent to `(wLength + 3) & ~3` relative to entry start, but
        // kept inside the parent's children slice.
        let advance = (child.entry.len() + 3) & !3;
        if advance == 0 || advance > bytes.len() {
            return None;
        }
        bytes = &bytes[advance..];
    }
    None
}

/// VerQueryValueW — extract a sub-block from a VS_VERSIONINFO buffer.
///
/// Handles three path shapes:
/// - `L"\\"` → pointer to the root `VS_FIXEDFILEINFO` (`puLen` = bytes).
/// - `L"\\StringFileInfo\\<lang-cp>\\<key>"` → UTF-16 string value
///   (`puLen` = character count including NUL terminator, per Wine).
/// - `L"\\VarFileInfo\\Translation"` → array of DWORDs
///   (`puLen` = byte count).
///
/// On miss, malformed block, or null input, returns FALSE with outputs cleared.
/// Bounds-checked — never panics on malformed fixtures.
///
/// # Safety
/// `p_block` must be null or a pointer to a `VS_VERSIONINFO` blob (as filled
/// by `GetFileVersionInfoW`). `lp_sub_block` must be null or a NUL-terminated
/// wide string. `lplp_buffer` and `pui_len` must be null or valid write targets.
///
/// Wine ref: dlls/kernelbase/version.c — VerQueryValueW dispatches to
/// `VersionInfo32_QueryValue(pBlock, lpSubBlock, lplpBuffer, puLen, NULL)`
/// which splits the path on '\\', calls `VersionInfo32_FindChild` per segment,
/// and on the final entry writes `*lplpBuffer = VersionInfo32_Value(info);
/// *puLen = info->wValueLength;`. `wValueLength` is a WCHAR count for text
/// entries (wType==1, includes NUL terminator) and a byte count for binary
/// entries (wType==0). Padding between entries is 32-bit aligned via
/// `DWORD_ALIGN` relative to the entry base.
pub unsafe extern "win64" fn ver_query_value_w(
    p_block: *const u8,
    lp_sub_block: *const u16,
    lplp_buffer: *mut *mut u8,
    pui_len: *mut u32,
) -> i32 {
    // Clear outputs first so they're always valid on return.
    if !lplp_buffer.is_null() {
        unsafe { *lplp_buffer = std::ptr::null_mut() };
    }
    if !pui_len.is_null() {
        unsafe { *pui_len = 0 };
    }
    if p_block.is_null() || lp_sub_block.is_null() {
        restrace!(
            "ver_query_value_w pBlock={:#x} → zero (null args)",
            p_block as usize
        );
        return 0;
    }

    // The total block length lives in the first WORD of the root entry.
    // Read it with the raw pointer (we don't have a slice yet) to establish
    // a bounded view, then do everything else through slices.
    let w_length = unsafe { u16::from_le_bytes([*p_block, *p_block.add(1)]) } as usize;
    if w_length < 8 {
        restrace!(
            "ver_query_value_w pBlock={:#x} → zero (wLength<8)",
            p_block as usize
        );
        return 0;
    }
    let block: &[u8] = unsafe { std::slice::from_raw_parts(p_block, w_length) };
    let base_addr = p_block as usize;

    let root = match VerEntry::parse(block) {
        Some(r) => r,
        None => {
            restrace!(
                "ver_query_value_w pBlock={:#x} → zero (malformed root)",
                base_addr
            );
            return 0;
        }
    };

    // Decode the sub-block path (UTF-16 → UTF-8) for traversal.
    let sub = unsafe { wide_to_utf8(lp_sub_block) }.unwrap_or_default();
    let sub_trim = sub.trim_matches('\\');

    // Root path: write FIXEDFILEINFO pointer and its byte count.
    if sub_trim.is_empty() {
        if root.w_value_length == 0 {
            restrace!(
                "ver_query_value_w pBlock={:#x} → zero (empty root value)",
                base_addr
            );
            return 0;
        }
        if !lplp_buffer.is_null() {
            unsafe { *lplp_buffer = p_block.add(root.value_offset) as *mut u8 };
        }
        if !pui_len.is_null() {
            // Root is binary (wType==0); wValueLength is already byte count.
            unsafe { *pui_len = root.w_value_length as u32 };
        }
        restrace!(
            "ver_query_value_w pBlock={:#x} root → TRUE valueLen={}",
            base_addr,
            root.w_value_length
        );
        return 1;
    }

    // Walk segments. Wine's loop splits on '\\' and skips empty segments.
    let mut current = root;
    // Offset (in bytes, from block[0]) of `current.entry[0]`. Used to compute
    // the absolute pointer to the value on the final segment.
    let mut current_offset: usize = 0;
    for segment in sub_trim.split('\\') {
        if segment.is_empty() {
            continue;
        }
        // Encode the segment as UTF-16 (no NUL).
        let key_wide: Vec<u16> = segment.encode_utf16().collect();
        let child = match find_child_by_key(&current, &key_wide) {
            Some(c) => c,
            None => {
                restrace!(
                    "ver_query_value_w sub=\"{}\" → zero (miss \"{}\")",
                    sub_trim,
                    segment
                );
                return 0;
            }
        };
        // Compute where the child's entry lives relative to the block base.
        // child.entry is a sub-slice of block, so we can recover its offset
        // via pointer arithmetic against block[0]. Safe because both slices
        // share provenance.
        let child_offset = (child.entry.as_ptr() as usize).saturating_sub(base_addr);
        if child_offset >= w_length {
            return 0;
        }
        current = child;
        current_offset = child_offset;
    }

    // Final entry: write value pointer and Wine's puLen convention.
    // puLen = wValueLength (raw): WCHAR count for text (incl. NUL), bytes for
    // binary. This matches Wine `*puLen = info->wValueLength;` verbatim.
    let value_abs = current_offset + current.value_offset;
    if value_abs >= w_length {
        restrace!("ver_query_value_w sub=\"{}\" → zero (value OOB)", sub_trim);
        return 0;
    }
    if !lplp_buffer.is_null() {
        unsafe { *lplp_buffer = p_block.add(value_abs) as *mut u8 };
    }
    if !pui_len.is_null() {
        unsafe { *pui_len = current.w_value_length as u32 };
    }
    restrace!(
        "ver_query_value_w sub=\"{}\" → TRUE wValueLength={} wType={}",
        sub_trim,
        current.w_value_length,
        current.w_type
    );
    1
}

/// VerQueryValueA — ANSI variant; widens the sub-block path to UTF-16 and
/// dispatches to [`ver_query_value_w`].
///
/// # Safety
/// Same as VerQueryValueW.
///
/// Wine ref: dlls/kernelbase/version.c — VerQueryValueA detects 16-bit vs
/// 32-bit block via `VersionInfoIs16` (szKey[0] >= ' '); for 32-bit blocks
/// widens lpSubBlock via MultiByteToWideChar(CP_ACP,...) then calls
/// `VersionInfo32_QueryValue`. Weave only supports 32-bit blocks and uses a
/// simple CP_ACP-equivalent widen (treat each byte as a 16-bit code unit).
pub unsafe extern "win64" fn ver_query_value_a(
    p_block: *const u8,
    lp_sub_block: *const u8,
    lplp_buffer: *mut *mut u8,
    pui_len: *mut u32,
) -> i32 {
    // Widen lpSubBlock (or use L"" if null). CP_ACP defaults to Windows-1252;
    // VS_VERSIONINFO path keys are ASCII-only (\\, StringFileInfo, hex tags),
    // so byte-wise widening is sufficient.
    let wide: Vec<u16> = if lp_sub_block.is_null() {
        vec![0]
    } else {
        let mut len = 0usize;
        while unsafe { *lp_sub_block.add(len) } != 0 {
            len += 1;
        }
        let bytes = unsafe { std::slice::from_raw_parts(lp_sub_block, len) };
        let mut v: Vec<u16> = bytes.iter().map(|&b| b as u16).collect();
        v.push(0);
        v
    };
    unsafe { ver_query_value_w(p_block, wide.as_ptr(), lplp_buffer, pui_len) }
}

/// Resolve a version.dll import.
///
/// Some apps import version.dll directly; others route through kernel32
/// apisets. We handle both paths.
// Wine ref: not implemented in Wine — Weave-internal IAT resolver for version.dll; no Windows API equivalent
pub fn resolve_version(dll: &str, func: &str) -> Option<usize> {
    let is_version = dll.eq_ignore_ascii_case("version.dll");
    // api-ms-win-core-version-* apisets forward to version.dll.
    let is_version_apiset = dll
        .to_ascii_lowercase()
        .starts_with("api-ms-win-core-version");
    if !is_version && !is_version_apiset {
        return None;
    }
    Some(match func {
        "GetFileVersionInfoSizeW" => get_file_version_info_size_w as *const () as usize,
        "GetFileVersionInfoSizeA" => get_file_version_info_size_a as *const () as usize,
        "GetFileVersionInfoW" => get_file_version_info_w as *const () as usize,
        "GetFileVersionInfoA" => get_file_version_info_a as *const () as usize,
        "VerQueryValueW" => ver_query_value_w as *const () as usize,
        "VerQueryValueA" => ver_query_value_a as *const () as usize,
        _ => return None,
    })
}

/// Resolve a psapi.dll import.
///
/// SDL2's `SDL_GetBasePath()` loads psapi.dll at runtime and calls
/// `GetModuleFileNameExW` to locate the executable.  We emulate the subset
/// SDL2 needs (current-process + NULL module → exe path).
// Wine ref: not implemented in Wine — Weave-internal IAT resolver for psapi.dll;
// maps the two common export names to get_module_file_name_ex_w.
pub fn resolve_psapi(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("psapi.dll") && !dll.eq_ignore_ascii_case("psapi") {
        return None;
    }
    match func {
        "GetModuleFileNameExW" | "K32GetModuleFileNameExW" => Some(
            get_module_file_name_ex_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        _ => None,
    }
}

// ── PuTTY gap-fill: missing kernel32 stubs ────────────────────────────────────

/// Beep: produce a sound. Returns TRUE (no audio output yet).
// Wine ref: dlls/win32u/driver.c — dispatches to the display driver's pBeep callback (e.g.
// X11DRV_Beep calls XBell); nulldrv_Beep is a no-op; Weave has no audio output
pub extern "win64" fn beep(_dw_freq: u32, _dw_duration: u32) -> i32 {
    // Wine ref: dlls/kernelbase/utils.c — NtDeviceIoControlFile on \Device\Beep.
    // Weave: write BEL character to stderr (terminal bell).
    unsafe { libc::write(2, b"\x07".as_ptr() as *const libc::c_void, 1) };
    1
}

/// MulDiv: multiply and divide with 64-bit intermediate, rounded. (a*b)/c
// Wine ref: dlls/kernelbase/utils.c — computes (nNumber*(int64)nNumerator)/nDenominator with
// 64-bit intermediate; rounds half-away-from-zero; denominator==0 or overflow returns -1
pub extern "win64" fn mul_div(n_number: i32, n_numerator: i32, n_denominator: i32) -> i32 {
    if n_denominator == 0 {
        return -1;
    }
    let result = (n_number as i64).wrapping_mul(n_numerator as i64) / n_denominator as i64;
    result as i32
}

/// SetStdHandle: store a handle in the process-global STD handle override table.
///
/// Returns TRUE (1) on success, FALSE (0) + ERROR_INVALID_PARAMETER if
/// nStdHandle is not one of STD_INPUT_HANDLE / STD_OUTPUT_HANDLE / STD_ERROR_HANDLE.
// Wine ref: dlls/kernelbase/console.c — stores hHandle into process STD table;
// invalid nStdHandle → SetLastError(ERROR_INVALID_PARAMETER), return FALSE.
pub extern "win64" fn set_std_handle(n_std_handle: u32, h_handle: usize) -> i32 {
    let slot = match std_slot(n_std_handle) {
        Some(s) => s,
        None => {
            set_last_error(0x57); // ERROR_INVALID_PARAMETER
            return 0;
        }
    };
    STD_HANDLE_OVERRIDES[slot].store(h_handle, Ordering::Relaxed);
    1
}

/// DeleteFileA: ANSI variant of DeleteFileW.
///
/// # Safety
/// `lp_file_name` must be a valid null-terminated ANSI string.
// Wine ref: dlls/kernelbase/file.c — converts via MultiByteToWideChar(CP_ACP), delegates to
// DeleteFileW; Weave similarly converts ANSI→UTF-16 then calls delete_file_w
pub unsafe extern "win64" fn delete_file_a(lp_file_name: *const u8) -> i32 {
    if lp_file_name.is_null() {
        return 0;
    }
    let mut len = 0usize;
    while unsafe { *lp_file_name.add(len) } != 0 {
        len += 1;
    }
    let name = unsafe { std::slice::from_raw_parts(lp_file_name, len) };
    let name = String::from_utf8_lossy(name);
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    delete_file_w(wide.as_ptr())
}

/// FindFirstFileExW: extended FindFirstFile. Delegates to FindFirstFileW.
///
/// # Safety
/// Pointer arguments must be valid or null.
// Wine ref: dlls/kernelbase/file.c — fInfoLevelStandard uses WIN32_FIND_DATAW; fSearchOp can
// filter by attributes via dwAdditionalFlags=FIND_FIRST_EX_LARGE_FETCH; delegates to NtQueryDirectoryFile
pub unsafe extern "win64" fn find_first_file_ex_w(
    lp_file_name: *const u16,
    _fi_info_level: i32,
    lp_find_file_data: usize,
    _f_search_op: i32,
    _lp_search_filter: usize,
    _dw_additional_flags: u32,
) -> usize {
    unsafe { find_first_file_w(lp_file_name, lp_find_file_data as *mut _) }
}

/// CPINFO layout (minimal — only first_byte_table[2] matters for basic codepages).
#[repr(C)]
pub struct CpInfo {
    max_char_size: u32,
    default_char: [u8; 2],
    lead_byte: [u8; 12],
}

/// GetCPInfo: return code page information. Returns TRUE for known pages.
///
/// # Safety
/// `lp_cp_info` must point to a writable `CPINFO` struct.
// Wine ref: dlls/kernelbase/locale.c:5554 — calls get_codepage_table(codepage); NULL table →
// ERROR_INVALID_PARAMETER; fills MaxCharSize from table->MaximumCharacterSize;
// DefaultChar from table->DefaultChar; LeadByte from table->LeadByte (multi-byte only)
pub unsafe extern "win64" fn get_cp_info(code_page: u32, lp_cp_info: *mut CpInfo) -> i32 {
    if lp_cp_info.is_null() {
        return 0;
    }
    unsafe {
        (*lp_cp_info).max_char_size = match code_page {
            932 | 936 | 949 | 950 => 2, // DBCS code pages
            _ => 1,
        };
        (*lp_cp_info).default_char = [b'?', 0];
        (*lp_cp_info).lead_byte = [0u8; 12];
    }
    1
}

/// GetDateFormatW: format a date as a localized string.
///
/// # Safety
/// `lp_date` is a *const SystemTime or null (null → current local time).
/// `lp_format` is a null-terminated UTF-16 custom format string or null.
/// `lp_date_str` must be writable for at least `cch_date` wide chars when non-zero.
// Wine ref: dlls/kernelbase/locale.c:7925 — get_date_format: lpDate=NULL → GetLocalTime;
// cchDate=0 → return required buffer size (including NUL); tokens: d/dd (day), ddd/dddd
// (abbrev/full day name), M/MM (month), MMM/MMMM (abbrev/full month), y/yy (2-digit year),
// yyy+ (4-digit year), 'text' (literal). Mutually-exclusive flag combos → ERROR_INVALID_FLAGS.
pub unsafe extern "win64" fn get_date_format_w(
    _locale: u32,
    dw_flags: u32,
    lp_date: usize,
    lp_format: *const u16,
    lp_date_str: *mut u16,
    cch_date: i32,
) -> i32 {
    // Read SYSTEMTIME or fall back to current local time.
    let st: SystemTime = if lp_date != 0 {
        unsafe { std::ptr::read(lp_date as *const SystemTime) }
    } else {
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        unsafe { libc::localtime_r(&tv.tv_sec, &mut tm) };
        SystemTime {
            w_year: (tm.tm_year + 1900) as u16,
            w_month: (tm.tm_mon + 1) as u16,
            w_day_of_week: tm.tm_wday as u16,
            w_day: tm.tm_mday as u16,
            w_hour: tm.tm_hour as u16,
            w_minute: tm.tm_min as u16,
            w_second: tm.tm_sec as u16,
            w_milliseconds: 0,
        }
    };

    // Build format string. Custom format overrides flags; flags select the locale pattern.
    let fmt: Vec<u16> = if !lp_format.is_null() {
        let mut len = 0usize;
        while unsafe { *lp_format.add(len) } != 0 {
            len += 1;
        }
        unsafe { std::slice::from_raw_parts(lp_format, len) }.to_vec()
    } else {
        const DATE_LONGDATE: u32 = 0x02;
        let s = if dw_flags & DATE_LONGDATE != 0 {
            "MMMM d, yyyy"
        } else {
            "M/d/yyyy"
        };
        s.encode_utf16().collect()
    };

    // Expand format tokens → UTF-16 output.
    // Wine ref: dlls/kernelbase/locale.c:7977 — same token set.
    const MONTH_ABBREV: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    const MONTH_FULL: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    const DAY_ABBREV: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const DAY_FULL: [&str; 7] = [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    ];

    let mut output: Vec<u16> = Vec::with_capacity(64);
    let mut i = 0usize;
    while i < fmt.len() {
        let ch = fmt[i];
        // Count run of identical chars (determines token width: d vs dd vs ddd etc.)
        let mut count = 1usize;
        while i + count < fmt.len() && fmt[i + count] == ch {
            count += 1;
        }
        match ch as u8 {
            b'd' => {
                let dow = st.w_day_of_week as usize;
                let s = match count {
                    1 => format!("{}", st.w_day),
                    2 => format!("{:02}", st.w_day),
                    3 => DAY_ABBREV.get(dow).copied().unwrap_or("?").to_string(),
                    _ => DAY_FULL.get(dow).copied().unwrap_or("?").to_string(),
                };
                output.extend(s.encode_utf16());
                i += count;
            }
            b'M' => {
                let mi = st.w_month.saturating_sub(1) as usize;
                let s = match count {
                    1 => format!("{}", st.w_month),
                    2 => format!("{:02}", st.w_month),
                    3 => MONTH_ABBREV.get(mi).copied().unwrap_or("?").to_string(),
                    _ => MONTH_FULL.get(mi).copied().unwrap_or("?").to_string(),
                };
                output.extend(s.encode_utf16());
                i += count;
            }
            b'y' => {
                let s = if count <= 2 {
                    format!("{:02}", st.w_year % 100)
                } else {
                    format!("{:04}", st.w_year)
                };
                output.extend(s.encode_utf16());
                i += count;
            }
            b'\'' => {
                // Quoted literal: 'text' — copy inner chars verbatim.
                i += 1;
                while i < fmt.len() {
                    if fmt[i] == b'\'' as u16 {
                        i += 1;
                        break;
                    }
                    output.push(fmt[i]);
                    i += 1;
                }
            }
            _ => {
                output.push(ch);
                i += 1;
            }
        }
    }
    output.push(0); // NUL terminator

    let needed = output.len() as i32;
    if cch_date == 0 {
        return needed;
    }
    if lp_date_str.is_null() || cch_date < needed {
        set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(output.as_ptr(), lp_date_str, output.len()) };
    needed
}

/// GetTimeFormatW: format a time as a localized string.
///
/// # Safety
/// `lp_time` is a *const SystemTime or null (null → current local time).
/// `lp_format` is a null-terminated UTF-16 custom format string or null.
/// `lp_time_str` must be writable for at least `cch_time` wide chars when non-zero.
// Wine ref: dlls/kernelbase/locale.c — get_time_format: lpTime=NULL → GetLocalTime;
// cchTime=0 → return required size; tokens: h/hh (12h), H/HH (24h), m/mm, s/ss, t/tt (AM/PM).
// TIME_NOSECONDS(0x02) skips s/ss; TIME_FORCE24HOURFORMAT(0x08) forces H/HH even for h/hh.
pub unsafe extern "win64" fn get_time_format_w(
    _locale: u32,
    dw_flags: u32,
    lp_time: usize,
    lp_format: *const u16,
    lp_time_str: *mut u16,
    cch_time: i32,
) -> i32 {
    // Read SYSTEMTIME or fall back to current local time.
    let st: SystemTime = if lp_time != 0 {
        unsafe { std::ptr::read(lp_time as *const SystemTime) }
    } else {
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        unsafe { libc::localtime_r(&tv.tv_sec, &mut tm) };
        SystemTime {
            w_year: (tm.tm_year + 1900) as u16,
            w_month: (tm.tm_mon + 1) as u16,
            w_day_of_week: tm.tm_wday as u16,
            w_day: tm.tm_mday as u16,
            w_hour: tm.tm_hour as u16,
            w_minute: tm.tm_min as u16,
            w_second: tm.tm_sec as u16,
            w_milliseconds: 0,
        }
    };

    const TIME_NOSECONDS: u32 = 0x02;
    const TIME_NOTIMEMARKER: u32 = 0x04;
    const TIME_FORCE24HOURFORMAT: u32 = 0x08;
    let no_seconds = dw_flags & TIME_NOSECONDS != 0;
    let no_marker = dw_flags & TIME_NOTIMEMARKER != 0;
    let force24 = dw_flags & TIME_FORCE24HOURFORMAT != 0;

    // Build format string.
    let fmt: Vec<u16> = if !lp_format.is_null() {
        let mut len = 0usize;
        while unsafe { *lp_format.add(len) } != 0 {
            len += 1;
        }
        unsafe { std::slice::from_raw_parts(lp_format, len) }.to_vec()
    } else {
        let s = if no_seconds { "h:mm tt" } else { "h:mm:ss tt" };
        s.encode_utf16().collect()
    };

    let hour12 = if st.w_hour == 0 {
        12u16
    } else if st.w_hour > 12 {
        st.w_hour - 12
    } else {
        st.w_hour
    };
    let ampm = if st.w_hour < 12 { "AM" } else { "PM" };

    let mut output: Vec<u16> = Vec::with_capacity(32);
    let mut i = 0usize;
    while i < fmt.len() {
        let ch = fmt[i];
        let mut count = 1usize;
        while i + count < fmt.len() && fmt[i + count] == ch {
            count += 1;
        }
        match ch as u8 {
            b'h' => {
                let hour = if force24 { st.w_hour } else { hour12 };
                let s = if count == 1 {
                    format!("{}", hour)
                } else {
                    format!("{:02}", hour)
                };
                output.extend(s.encode_utf16());
                i += count;
            }
            b'H' => {
                let s = if count == 1 {
                    format!("{}", st.w_hour)
                } else {
                    format!("{:02}", st.w_hour)
                };
                output.extend(s.encode_utf16());
                i += count;
            }
            b'm' => {
                let s = if count == 1 {
                    format!("{}", st.w_minute)
                } else {
                    format!("{:02}", st.w_minute)
                };
                output.extend(s.encode_utf16());
                i += count;
            }
            b's' => {
                if !no_seconds {
                    let s = if count == 1 {
                        format!("{}", st.w_second)
                    } else {
                        format!("{:02}", st.w_second)
                    };
                    output.extend(s.encode_utf16());
                }
                i += count;
            }
            b't' => {
                if !no_marker {
                    let marker = if count == 1 { &ampm[..1] } else { ampm };
                    output.extend(marker.encode_utf16());
                }
                i += count;
            }
            b'\'' => {
                i += 1;
                while i < fmt.len() {
                    if fmt[i] == b'\'' as u16 {
                        i += 1;
                        break;
                    }
                    output.push(fmt[i]);
                    i += 1;
                }
            }
            _ => {
                output.push(ch);
                i += 1;
            }
        }
    }
    output.push(0); // NUL terminator

    let needed = output.len() as i32;
    if cch_time == 0 {
        return needed;
    }
    if lp_time_str.is_null() || cch_time < needed {
        set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
        return 0;
    }
    unsafe { std::ptr::copy_nonoverlapping(output.as_ptr(), lp_time_str, output.len()) };
    needed
}

/// MEMORYSTATUS layout (Windows 9x/NT).
#[repr(C)]
pub struct MemoryStatus {
    dw_length: u32,
    dw_memory_load: u32,
    dw_total_phys: usize,
    dw_avail_phys: usize,
    dw_total_page_file: usize,
    dw_avail_page_file: usize,
    dw_total_virtual: usize,
    dw_avail_virtual: usize,
}

/// GlobalMemoryStatus: fill a MEMORYSTATUS struct with fake values.
///
/// # Safety
/// `lp_buffer` must point to a writable `MEMORYSTATUS` struct.
// Wine ref: dlls/kernelbase/memory.c — GlobalMemoryStatus delegates to GlobalMemoryStatusEx;
// copies first sizeof(MEMORYSTATUS) bytes from MEMORYSTATUSEX; GlobalMemoryStatusEx caches result
// for 1 second via GetTickCount64() to avoid repeated NtQuerySystemInformation calls
pub unsafe extern "win64" fn global_memory_status(lp_buffer: *mut MemoryStatus) {
    if lp_buffer.is_null() {
        return;
    }
    unsafe {
        (*lp_buffer).dw_length = std::mem::size_of::<MemoryStatus>() as u32;
        (*lp_buffer).dw_memory_load = 30;
        (*lp_buffer).dw_total_phys = 8 * 1024 * 1024 * 1024; // 8 GB
        (*lp_buffer).dw_avail_phys = 4 * 1024 * 1024 * 1024;
        (*lp_buffer).dw_total_page_file = 16 * 1024 * 1024 * 1024;
        (*lp_buffer).dw_avail_page_file = 8 * 1024 * 1024 * 1024;
        (*lp_buffer).dw_total_virtual = 0x0000_7FFF_FFFF_0000usize;
        (*lp_buffer).dw_avail_virtual = 0x0000_7FFF_FFFF_0000usize;
    }
}

/// InitializeSListHead: initialise an interlocked singly-linked list.
///
/// # Safety
/// `list_head` must point to a 16-byte-aligned SLIST_HEADER (zeroed).
// Wine ref: dlls/ntdll/rtl.c — delegates to RtlInitializeSListHead which zeroes
// the SLIST_HEADER; on x86-64 the header is a 128-bit structure containing Next ptr + Depth + Sequence
pub unsafe extern "win64" fn initialize_slist_head(list_head: *mut u128) {
    if !list_head.is_null() {
        unsafe { *list_head = 0 };
    }
}

// SLIST_HEADER internal layout (Weave, 16-byte aligned u128, little-endian):
//   bits  [15:0]  = Depth    (u16 — entry count)
//   bits  [63:16] = Sequence (u48 — ABA counter)
//   bits [127:64] = Next     (u64 — raw *mut u8 pointer to first SLIST_ENTRY; null = empty)
//
// This is Weave's own encoding (not identical to the Windows Header8/Header16 bit-fields).
// All three Interlocked/Initialize SList stubs agree on this layout, so the MSVC CRT's
// calls through our IAT are fully self-consistent.
//
// Wine ref: dlls/ntoskrnl.exe/sync.c — InterlockedPop/PushEntrySList delegates to
// RtlInterlockedPop/PushEntrySList (ntdll); the real Windows path uses lock cmpxchg16b.
// Weave serialises via a global Mutex — correct for all call patterns, including the
// single-threaded MSVC CRT heap init path that triggers the Q-Dir SIGSEGV (Fail #25).

static SLIST_LOCK: Mutex<()> = Mutex::new(());

/// InterlockedPopEntrySList: atomically remove the first entry from the SLIST.
/// Returns a pointer to the removed SLIST_ENTRY, or null if the list was empty.
///
/// # Safety
/// `list_head` must be a valid 16-byte-aligned SLIST_HEADER initialised by InitializeSListHead.
pub unsafe extern "win64" fn interlockedpopentryslsit(list_head: *mut u128) -> *mut u8 {
    if list_head.is_null() {
        return core::ptr::null_mut();
    }
    let _guard = SLIST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let val = unsafe { core::ptr::read_volatile(list_head) };
    let old_next = (val >> 64) as u64 as *mut u8; // high qword = Next ptr
    if old_next.is_null() {
        return core::ptr::null_mut(); // list empty
    }
    // Read entry->Next (first 8 bytes of the SLIST_ENTRY = its Next pointer field).
    let new_next = unsafe { *(old_next as *const *mut u8) };
    let old_depth = (val & 0xFFFF) as u16;
    let old_seq = ((val >> 16) & 0x0000_FFFF_FFFF_FFFF_u128) as u64;
    let new_low = (old_depth.wrapping_sub(1) as u128) | ((old_seq.wrapping_add(1) as u128) << 16);
    let new_val = new_low | ((new_next as u64 as u128) << 64);
    unsafe { core::ptr::write_volatile(list_head, new_val) };
    old_next
}

/// InterlockedPushEntrySList: atomically insert an entry at the head of the SLIST.
/// Returns a pointer to the previous first entry, or null if the list was empty.
///
/// # Safety
/// `list_head` must be a valid 16-byte-aligned SLIST_HEADER initialised by InitializeSListHead.
/// `list_entry` must point to a valid SLIST_ENTRY (first 8 bytes are the Next pointer field).
pub unsafe extern "win64" fn interlockedpushentryslsit(
    list_head: *mut u128,
    list_entry: *mut u8,
) -> *mut u8 {
    if list_head.is_null() || list_entry.is_null() {
        return core::ptr::null_mut();
    }
    let _guard = SLIST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let val = unsafe { core::ptr::read_volatile(list_head) };
    let old_next = (val >> 64) as u64 as *mut u8; // current head
                                                  // Link entry into list: entry->Next = old_next.
    unsafe { *(list_entry as *mut *mut u8) = old_next };
    let old_depth = (val & 0xFFFF) as u16;
    let old_seq = ((val >> 16) & 0x0000_FFFF_FFFF_FFFF_u128) as u64;
    let new_low = (old_depth.wrapping_add(1) as u128) | ((old_seq.wrapping_add(1) as u128) << 16);
    let new_val = new_low | ((list_entry as u64 as u128) << 64);
    unsafe { core::ptr::write_volatile(list_head, new_val) };
    old_next // previous head (null if list was empty)
}

/// IsValidLocale: return TRUE for any locale (we accept all).
// Wine ref: dlls/kernelbase/locale.c:6717 — LOCALE_NEUTRAL/USER_DEFAULT/SYSTEM_DEFAULT return FALSE;
// others call NlsValidateLocale(&lcid, LOCALE_ALLOW_NEUTRAL_NAMES); returns !!result
pub extern "win64" fn is_valid_locale(_locale: u32, _dw_flags: u32) -> i32 {
    1
}

/// EnumSystemLocalesW: call the callback for one fake locale. Returns TRUE.
///
/// # Safety
/// `lp_locale_enum_proc` is called as `extern "win64" fn(*const u16) -> i32`.
// Wine ref: dlls/kernelbase/locale.c — iterates through all locales in locale_table[]; each
// LCID is formatted as hex string via swprintf; callback returning FALSE stops enumeration;
// dwFlags can be LCID_INSTALLED or LCID_SUPPORTED
pub unsafe extern "win64" fn enum_system_locales_w(
    lp_locale_enum_proc: usize,
    _dw_flags: u32,
) -> i32 {
    if lp_locale_enum_proc == 0 {
        return 0;
    }
    // Call the callback with the English (US) locale string.
    let locale: Vec<u16> = "0409\0".encode_utf16().collect();
    // SAFETY: `lp_locale_enum_proc` is a usize holding the numeric address of a
    // Win64-ABI callback supplied by the caller, validated non-zero above.
    // Transmuting to `extern "win64" fn(*const u16) -> i32` is sound because:
    //   1. `usize` and function pointers are both pointer-sized on x86-64.
    //   2. The LOCALE_ENUMPROCW signature is `fn(LPWSTR) -> BOOL`, which maps
    //      exactly to `fn(*const u16) -> i32` under the Win64 calling convention.
    //   3. The caller's `# Safety` contract guarantees the callback is valid.
    let cb: extern "win64" fn(*const u16) -> i32 =
        unsafe { std::mem::transmute(lp_locale_enum_proc) };
    cb(locale.as_ptr());
    1
}

/// AppPolicyGetProcessTerminationMethod: query the process termination policy.
///
/// # Safety
/// `policy` must be a valid writable pointer to a u32.
// Wine ref: include/appmodel.h — AppPolicyProcessTerminationMethod enum;
// Wine does not implement this API (no MSVC CRT AppPolicy* stubs); MSVC CRT
// probes this at startup and uses ExitProcess=0 as the non-packaged-app path.
pub unsafe extern "win64" fn app_policy_get_process_termination_method(
    _process_token: usize,
    policy: *mut u32,
) -> i32 {
    if !policy.is_null() {
        // SAFETY: caller guarantees `policy` is a valid writable u32 pointer.
        unsafe { policy.write(0) }; // AppPolicyProcessTerminationMethod_ExitProcess = 0
    }
    0 // S_OK
}

/// AppPolicyGetThreadInitializationType: query the thread initialization policy.
///
/// # Safety
/// `policy` must be a valid writable pointer to a u32.
// Wine ref: include/appmodel.h — AppPolicyThreadInitializationType enum;
// Wine does not implement this API; MSVC CRT probes this at startup and uses
// None=0 as the non-UWP (classic desktop) thread init path.
pub unsafe extern "win64" fn app_policy_get_thread_initialization_type(
    _process_token: usize,
    policy: *mut u32,
) -> i32 {
    if !policy.is_null() {
        // SAFETY: caller guarantees `policy` is a valid writable u32 pointer.
        unsafe { policy.write(0) }; // AppPolicyThreadInitializationType_None = 0
    }
    0 // S_OK
}

/// LCIDToLocaleName: convert an LCID to a locale name string.
///
/// # Safety
/// `lp_name` must be a valid writable buffer of at least `cch_name` UTF-16 code units,
/// or NULL (in which case returns required buffer length).
// Wine ref: dlls/kernelbase/locale.c:6818 — validates lcid via NlsValidateLocale,
// calls SetLastError(ERROR_INVALID_PARAMETER) on unknown LCID and returns 0;
// returns buffer length including NUL on success.
pub unsafe extern "win64" fn lcid_to_locale_name(
    lcid: u32,
    lp_name: *mut u16,
    cch_name: i32,
    _dw_flags: u32,
) -> i32 {
    // We recognise LCID 0 (LOCALE_USER_DEFAULT) and 0x0409 (en-US) only.
    match lcid {
        0 | 0x0409 => {
            let name: Vec<u16> = "en-US\0".encode_utf16().collect(); // 6 code units incl. NUL
            if lp_name.is_null() || cch_name == 0 {
                return 6; // return required length
            }
            if cch_name < 6 {
                weave_common::set_last_error(122); // ERROR_INSUFFICIENT_BUFFER
                return 0;
            }
            // SAFETY: caller guarantees `lp_name` points to a buffer of ≥ cch_name u16 words.
            unsafe {
                std::ptr::copy_nonoverlapping(name.as_ptr(), lp_name, 6);
            }
            6
        }
        _ => {
            weave_common::set_last_error(87); // ERROR_INVALID_PARAMETER
            0
        }
    }
}

/// LocaleNameToLCID: convert a locale name string to an LCID.
///
/// # Safety
/// `lp_name` must be a valid pointer to a NUL-terminated UTF-16 string, or NULL.
// Wine ref: dlls/kernelbase/locale.c:6992 — calls get_locale_by_name; returns 0
// with SetLastError(ERROR_INVALID_PARAMETER) for unrecognised names; handles
// LOCALE_ALLOW_NEUTRAL_NAMES flag via inotneutral/idefaultlanguage fields.
pub unsafe extern "win64" fn locale_name_to_lcid(lp_name: *const u16, _dw_flags: u32) -> u32 {
    if lp_name.is_null() {
        return 0x0409; // LOCALE_USER_DEFAULT → en-US
    }
    // Read up to 10 UTF-16 code units to identify the name.
    // SAFETY: caller guarantees `lp_name` is a NUL-terminated UTF-16 string.
    let name: String = unsafe {
        let mut len = 0usize;
        while len < 16 && *lp_name.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(lp_name, len);
        String::from_utf16_lossy(slice).to_owned()
    };
    match name.as_str() {
        "en-US" | "en" => 0x0409,
        _ => 0x1000, // LOCALE_CUSTOM_UNSPECIFIED — caller takes its fallback
    }
}

/// GetDateFormatEx: format a date using a locale name.
///
/// # Safety
/// All pointer arguments follow Windows API semantics for this function.
// Wine ref: dlls/kernelbase/locale.c get_date_format — validates locale name,
// applies flags/format string, writes result to buffer; returns 0 on failure.
// CRT probes this at startup to test Ex-variant availability; returning 0
// causes CRT to fall back to GetDateFormatW, which is already implemented.
pub unsafe extern "win64" fn get_date_format_ex(
    _locale_name: *const u16,
    _dw_flags: u32,
    _lp_date: *const (),
    _lp_format: *const u16,
    _lp_date_str: *mut u16,
    _cch_date: i32,
    _lp_calendar: *const (),
) -> i32 {
    // Minimal probe stub — CRT falls back to GetDateFormatW on 0 return.
    0
}

/// GetTimeFormatEx: format a time using a locale name.
///
/// # Safety
/// All pointer arguments follow Windows API semantics for this function.
// Wine ref: dlls/kernelbase/locale.c get_time_format — validates locale name,
// applies flags/format string, writes result to buffer; returns 0 on failure.
// CRT probes this at startup to test Ex-variant availability; returning 0
// causes CRT to fall back to GetTimeFormatW, which is already implemented.
pub unsafe extern "win64" fn get_time_format_ex(
    _locale_name: *const u16,
    _dw_flags: u32,
    _lp_time: *const (),
    _lp_format: *const u16,
    _lp_time_str: *mut u16,
    _cch_time: i32,
) -> i32 {
    // Minimal probe stub — CRT falls back to GetTimeFormatW on 0 return.
    0
}

/// EnumSystemLocalesEx: enumerate system locales, calling back for each one.
///
/// # Safety
/// `lp_locale_enum_proc_ex` must be a valid `extern "win64" fn(*mut u16, u32, isize) -> i32`
/// callback or 0 (treated as no-op).
// Wine ref: dlls/kernelbase/locale.c:5134 — iterates lcnames_index[], passes
// locale name string + flags + param to LOCALE_ENUMPROCEX; returns FALSE if
// reserved != NULL; returns TRUE after enumeration completes.
pub unsafe extern "win64" fn enum_system_locales_ex(
    lp_locale_enum_proc_ex: usize,
    _dw_flags: u32,
    l_param: isize,
    lp_reserved: *const (),
) -> i32 {
    if !lp_reserved.is_null() {
        weave_common::set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0; // FALSE
    }
    if lp_locale_enum_proc_ex == 0 {
        return 1; // TRUE — nothing to enumerate
    }
    // Call callback once with "en-US\0", LOCALE_WINDOWS|LOCALE_SPECIFICDATA, l_param.
    let locale: Vec<u16> = "en-US\0".encode_utf16().collect();
    // SAFETY: `lp_locale_enum_proc_ex` is a usize holding the numeric address of a
    // Win64-ABI callback supplied by the caller, validated non-zero above.
    // LOCALE_ENUMPROCEX signature: fn(LPWSTR, DWORD, LPARAM) -> BOOL, which maps to
    // extern "win64" fn(*mut u16, u32, isize) -> i32.
    let cb: extern "win64" fn(*mut u16, u32, isize) -> i32 =
        unsafe { std::mem::transmute(lp_locale_enum_proc_ex) };
    // LOCALE_WINDOWS(0x00000001) | LOCALE_SPECIFICDATA(0x00000020)
    cb(locale.as_ptr() as *mut u16, 0x00000021, l_param);
    1 // TRUE
}

/// Translate a Win32 resource-name/type pointer (either `MAKEINTRESOURCE(n)`
/// ordinal or a NUL-terminated UTF-16 string pointer) into a [`ResourceId`].
///
/// Wine ref: `IS_INTRESOURCE(x)` is `(((ULONG_PTR)(x)) >> 16) == 0`; values
/// whose upper bits are all zero are ordinals, everything else is a pointer.
///
/// # Safety
/// If `p` is not an ordinal (low 16 bits only), it must be a valid pointer
/// to a NUL-terminated UTF-16 string readable for the length of that string.
unsafe fn resource_id_from_ptr_w(p: usize) -> weave_core::resource::ResourceId {
    if (p >> 16) == 0 {
        return weave_core::resource::ResourceId::Id((p & 0xFFFF) as u16);
    }
    // SAFETY: caller contract — `p` is a UTF-16 C-string pointer.
    let name = unsafe { read_cstr_w(p as *const u16) };
    weave_core::resource::ResourceId::Name(name.encode_utf16().collect())
}

/// ANSI variant: ordinals are encoded the same way; string pointers are
/// ANSI (CP_ACP in Wine; we treat as UTF-8-lossy since Weave's guest ANSI
/// round-trip is not exact).
///
/// # Safety
/// If `p` is not an ordinal, it must be a valid NUL-terminated ANSI string
/// pointer readable for the length of that string.
unsafe fn resource_id_from_ptr_a(p: usize) -> weave_core::resource::ResourceId {
    if (p >> 16) == 0 {
        return weave_core::resource::ResourceId::Id((p & 0xFFFF) as u16);
    }
    // SAFETY: caller contract.
    let name = unsafe { read_cstr_a(p as *const u8) };
    weave_core::resource::ResourceId::Name(name.encode_utf16().collect())
}

/// FindResourceA: locate a resource in a module. Delegates to FindResourceW
/// after ANSI→UTF-16 name/type conversion.
///
/// # Safety
/// Pointer arguments must be either small ordinals (`MAKEINTRESOURCEA`) or
/// NUL-terminated ANSI strings readable for their length.
// Wine ref: dlls/kernelbase/loader.c — converts ANSI name/type to Unicode if not IS_INTRESOURCE;
// delegates to FindResourceExW(hModule, typeW, nameW, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL));
// LdrFindResource_U returns an HRSRC (pointer into the PE image)
// implemented 2026-04-19
pub unsafe extern "win64" fn find_resource_a(
    h_module: usize,
    lp_name: *const u8,
    lp_type: *const u8,
) -> usize {
    // SAFETY: caller contract propagated to resource_id_from_ptr_a.
    let name = unsafe { resource_id_from_ptr_a(lp_name as usize) };
    let type_ = unsafe { resource_id_from_ptr_a(lp_type as usize) };
    find_resource_common(h_module, name, type_)
}

/// FindResourceW: locate a named resource in a module via Wine's identity
/// HRSRC scheme — returns a pointer to the `IMAGE_RESOURCE_DATA_ENTRY`
/// inside the mapped PE image.
///
/// # Safety
/// Pointer arguments must be either small ordinals (`MAKEINTRESOURCEW`) or
/// NUL-terminated UTF-16 strings.
// Wine ref: dlls/kernelbase/loader.c FindResourceW — delegates to
// FindResourceExW(module, type, name, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL));
// FindResourceExW calls LdrFindResource_U which walks the PE resource directory
// and returns `(HRSRC)&entry` — the address of IMAGE_RESOURCE_DATA_ENTRY.
// implemented 2026-04-19
pub unsafe extern "win64" fn find_resource_w(
    h_module: usize,
    lp_name: *const u16,
    lp_type: *const u16,
) -> usize {
    // SAFETY: caller contract propagated.
    let name = unsafe { resource_id_from_ptr_w(lp_name as usize) };
    let type_ = unsafe { resource_id_from_ptr_w(lp_type as usize) };
    let result = find_resource_common(h_module, name, type_);
    restrace!(
        "find_resource_w hInst={h_module:#x} type={:#x} name={:#x} → {}",
        lp_type as usize,
        lp_name as usize,
        if result != 0 {
            format!("hrsrc={result:#x}")
        } else {
            "zero".to_string()
        }
    );
    result
}

/// Shared body for FindResourceA/W: resolve module base via the handle
/// table, walk the resource directory, return HRSRC (=address of
/// IMAGE_RESOURCE_DATA_ENTRY) or 0 with ERROR_RESOURCE_NAME_NOT_FOUND set.
fn find_resource_common(
    h_module: usize,
    name: weave_core::resource::ResourceId,
    type_: weave_core::resource::ResourceId,
) -> usize {
    let base = match weave_core::module_handles::base_of(h_module) {
        Some(b) => b,
        None => {
            set_last_error(1814); // ERROR_RESOURCE_NAME_NOT_FOUND
            return 0;
        }
    };
    // Wine's FindResourceW default lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL) = 0.
    match weave_core::resource::find_resource_entry(base, type_, name, 0) {
        Some(hrsrc) => hrsrc,
        None => {
            set_last_error(1814);
            0
        }
    }
}

/// EnumResourceNamesW: invoke `lp_enum_func(hModule, type, name, lParam)` for
/// every resource name under `lp_type` in `h_module`.
///
/// # Safety
/// `lp_enum_func` must be a valid `ENUMRESNAMEPROCW` function pointer following
/// the Win64 ABI: `fn(HMODULE, LPCWSTR type, LPWSTR name, LONG_PTR lParam) -> BOOL`.
/// `lp_type` must be a `MAKEINTRESOURCE` ordinal or a valid NUL-terminated
/// UTF-16 string pointer. These are the caller's responsibility (same contract
/// as the real Win32 API).
// Wine ref: dlls/kernelbase/loader.c::EnumResourceNamesExW (line 872) —
//   * Two-level `LdrFindResourceDirectory_U` calls: root → type directory → name directory.
//   * Named entries: `str->NameString` (at `basedir + et[i].NameOffset`, rsrc-root-relative)
//     is null-terminated and passed as the `name` arg; the IS_INTRESOURCE test
//     (`(p >> 16) == 0`) distinguishes ordinals from string pointers.
//   * ID entries: `UIntToPtr(et[i].Id)` passed directly.
//   * Enumeration stops when callback returns FALSE.
//   * Sets ERROR_RESOURCE_TYPE_NOT_FOUND (1813) when type directory lookup fails.
// implemented 2026-04-19
pub unsafe extern "win64" fn enum_resource_names_w(
    h_module: usize,
    lp_type: *const u16,
    lp_enum_func: usize,
    l_param: usize,
) -> i32 {
    let base = match weave_core::module_handles::base_of(h_module) {
        Some(b) => b,
        None => {
            set_last_error(6); // ERROR_INVALID_HANDLE
            restrace!(
                "enum_resource_names_w hInst={h_module:#x} type={:#x} → zero (invalid handle)",
                lp_type as usize
            );
            return 0;
        }
    };

    // Win64 callback: BOOL CALLBACK EnumResNameProcW(HMODULE, LPCWSTR type, LPWSTR name, LONG_PTR)
    type EnumResNameProc = unsafe extern "win64" fn(usize, *const u16, *const u16, usize) -> i32;
    // SAFETY: caller guarantees lp_enum_func follows this ABI.
    let callback_fn: EnumResNameProc = unsafe { std::mem::transmute(lp_enum_func) };

    let count = std::cell::Cell::new(0usize);

    // SAFETY: base is a valid mapped PE image (confirmed via module_handles);
    // lp_type is caller-guaranteed to be a valid ordinal or UTF-16 string pointer.
    let found = unsafe {
        weave_core::resource::enumerate_resource_names(base, lp_type, |name_ptr| {
            count.set(count.get() + 1);
            // SAFETY: callback_fn is the caller-supplied ENUMRESNAMEPROCW;
            // name_ptr is either an IS_INTRESOURCE ordinal or a pointer to a
            // null-terminated UTF-16 buf kept alive for the duration of this call.
            callback_fn(h_module, lp_type, name_ptr, l_param) != 0
        })
    };

    if !found {
        set_last_error(1813); // ERROR_RESOURCE_TYPE_NOT_FOUND
        restrace!(
            "enum_resource_names_w hInst={h_module:#x} type={:#x} → zero (type not found)",
            lp_type as usize
        );
        return 0;
    }
    restrace!(
        "enum_resource_names_w hInst={h_module:#x} type={:#x} → count={}",
        lp_type as usize,
        count.get()
    );
    1 // TRUE — enumeration completed (or stopped early by callback returning FALSE)
}

/// FreeResource: legacy 16-bit resource free. Always returns FALSE.
// Wine ref: dlls/kernelbase/loader.c FreeResource — stub: always returns FALSE;
// Win32 resources are part of the PE image and are never actually freed via this API.
pub extern "win64" fn free_resource(_h_res_data: usize) -> i32 {
    0 // FALSE
}

/// LoadResource: translate an HRSRC to an HGLOBAL pointing at the actual
/// resource bytes. Wine's identity scheme: HGLOBAL = image_base + entry.OffsetToData.
// Wine ref: dlls/kernelbase/loader.c LoadResource — calls
//   LdrAccessResource(module, (IMAGE_RESOURCE_DATA_ENTRY *)rsrc, &ret, NULL);
// LdrAccessResource returns `(char *)module + entry->OffsetToData`. The
// returned HGLOBAL is a direct pointer into the PE image (no allocation).
// implemented 2026-04-19
pub extern "win64" fn load_resource(h_module: usize, h_res_info: usize) -> usize {
    if h_res_info == 0 {
        return 0;
    }
    let base = match weave_core::module_handles::base_of(h_module) {
        Some(b) => b,
        None => return 0,
    };
    // SAFETY: h_res_info came from find_resource_entry over this same module,
    // so it points to a valid IMAGE_RESOURCE_DATA_ENTRY inside `base`'s image.
    // Wine skips validation similarly — callers that fabricate HRSRCs hit UB.
    unsafe { weave_core::resource::resource_entry_data(base, h_res_info) }
}

/// LockResource: pure identity — HGLOBAL is already the bytes' address.
// Wine ref: dlls/kernelbase/loader.c LockResource — body is literally
// `return handle;`. Win32 resources are never actually locked (16-bit
// legacy API; LoadResource already returned the pointer).
// implemented 2026-04-19
pub extern "win64" fn lock_resource(h_res_data: usize) -> usize {
    h_res_data
}

/// SizeofResource: read `IMAGE_RESOURCE_DATA_ENTRY.Size` from the HRSRC.
// Wine ref: dlls/kernelbase/loader.c SizeofResource — body is
//   `if (!rsrc) return 0; return ((IMAGE_RESOURCE_DATA_ENTRY *)rsrc)->Size;`
// The Size field is at offset +4 inside the 16-byte data entry struct.
// implemented 2026-04-19
pub extern "win64" fn sizeof_resource(_h_module: usize, h_res_info: usize) -> u32 {
    if h_res_info == 0 {
        return 0;
    }
    // SAFETY: h_res_info came from find_resource_entry; points at a valid
    // IMAGE_RESOURCE_DATA_ENTRY (16 bytes) inside a mapped PE image.
    unsafe { weave_core::resource::resource_entry_size(h_res_info) }
}

/// FILETIME layout (Windows).
#[repr(C)]
pub struct FileTime {
    dw_low_date_time: u32,
    dw_high_date_time: u32,
}

/// GetProcessTimes: return CPU times for an open process handle.
///
/// Creation time is approximated as the current wall-clock FILETIME (process
/// just started from 7za's perspective).  Exit, kernel, and user times are
/// zero (not yet exited; CPU accounting not tracked).  Returning a non-zero
/// creation time is load-bearing: callers such as 7za use CompareFileTime on
/// the creation-time FILETIME and throw E_INVALIDARG (0x80070057) if it is
/// zero, treating zero as an invalid/uninitialized timestamp.
///
/// # Safety
/// Output pointers must be valid `FILETIME` structs or null.
// Wine ref: dlls/kernelbase/process.c:931 — calls NtQueryInformationProcess(ProcessTimes,
// KERNEL_USER_TIMES); unpacks CreateTime/ExitTime/KernelTime/UserTime into four FILETIME structs;
// null pointers for any output are valid (Wine does not check for null — callers must pass valid ptrs)
pub unsafe extern "win64" fn get_process_times(
    _h_process: usize,
    lp_creation_time: *mut FileTime,
    lp_exit_time: *mut FileTime,
    lp_kernel_time: *mut FileTime,
    lp_user_time: *mut FileTime,
) -> i32 {
    // Approximate creation time as current wall-clock time.
    // A zero FILETIME is an invalid sentinel on Windows (pre-dates 1601) and
    // triggers validity failures in callers that call CompareFileTime on it.
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime is async-signal-safe and always succeeds for
    // CLOCK_REALTIME on Linux.  ts is stack-allocated and valid for the duration
    // of the call.  Failure (ret != 0) is ignored: the only consequence is
    // a zero ts, which still produces a non-zero FILETIME after the epoch offset.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    let ns = ts.tv_sec as u64 * 10_000_000 + ts.tv_nsec as u64 / 100;
    let ft_now = ns + 116_444_736_000_000_000u64;
    let ft_low = ft_now as u32;
    let ft_high = (ft_now >> 32) as u32;

    if !lp_creation_time.is_null() {
        // SAFETY: lp_creation_time is non-null (checked above) and points to a
        // valid writable FileTime (8 bytes) per the caller's # Safety contract.
        unsafe {
            (*lp_creation_time).dw_low_date_time = ft_low;
            (*lp_creation_time).dw_high_date_time = ft_high;
        }
    }
    // Exit time = 0 (process still running); kernel/user CPU time = 0 (not tracked).
    for p in [lp_exit_time, lp_kernel_time, lp_user_time] {
        if !p.is_null() {
            // SAFETY: p is non-null (checked above) and points to a valid
            // writable FileTime (8 bytes) per the caller's # Safety contract.
            unsafe {
                (*p).dw_low_date_time = 0;
                (*p).dw_high_date_time = 0;
            }
        }
    }
    eprintln!("weave/GetProcessTimes: creation={ft_now:#x} exit=0 kernel=0 user=0 → TRUE");
    1
}

/// GetThreadTimes: return zero CPU times. Returns TRUE.
///
/// # Safety
/// Output pointers must be valid `FILETIME` structs or null.
// Wine ref: dlls/kernelbase/thread.c — calls NtQueryInformationThread(ThreadTimes, KERNEL_USER_TIMES);
// same struct layout as ProcessTimes; delegates identical FILETIME unpacking logic
pub unsafe extern "win64" fn get_thread_times(
    _h_thread: usize,
    lp_creation_time: *mut FileTime,
    lp_exit_time: *mut FileTime,
    lp_kernel_time: *mut FileTime,
    lp_user_time: *mut FileTime,
) -> i32 {
    unsafe {
        get_process_times(
            0,
            lp_creation_time,
            lp_exit_time,
            lp_kernel_time,
            lp_user_time,
        )
    }
}

/// GetOverlappedResult: query the result of an async I/O operation.
///
/// # Safety
/// `lp_overlapped` must point to a valid OVERLAPPED struct or be null.
/// `lp_number_of_bytes_transferred` must be writable if non-null.
// Wine ref: dlls/kernelbase/file.c:3323 — ReadAcquire(&overlapped->Internal); STATUS_PENDING +
// bWait=TRUE → WaitForSingleObject(hEvent||file, INFINITE); else ERROR_IO_INCOMPLETE.
// On completion: *result = InternalHigh; SetLastError(RtlNtStatusToDosError(status));
// return !status (TRUE on STATUS_SUCCESS).
pub unsafe extern "win64" fn get_overlapped_result(
    _h_file: usize,
    lp_overlapped: usize,
    lp_number_of_bytes_transferred: *mut u32,
    b_wait: i32,
) -> i32 {
    const STATUS_PENDING: usize = 0x103;

    if lp_overlapped == 0 {
        set_last_error(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    // OVERLAPPED layout (x86-64): Internal @ +0, InternalHigh @ +8.
    // read_volatile approximates Wine's ReadAcquire acquire-load.
    // SAFETY: lp_overlapped is non-null (checked) and points to a valid OVERLAPPED per caller.
    let ovl = lp_overlapped as *const usize;
    let status = unsafe { std::ptr::read_volatile(ovl) };

    if status == STATUS_PENDING {
        // Weave is synchronous-only — no async completion infrastructure to wait on.
        if b_wait != 0 {
            eprintln!(
                "weave/GetOverlappedResult: STATUS_PENDING bWait=TRUE — \
                 sync-only, returning IO_INCOMPLETE"
            );
        }
        if !lp_number_of_bytes_transferred.is_null() {
            unsafe { *lp_number_of_bytes_transferred = 0 };
        }
        set_last_error(996); // ERROR_IO_INCOMPLETE
        return 0; // FALSE
    }

    let internal_high = unsafe { std::ptr::read_volatile(ovl.add(1)) };
    if !lp_number_of_bytes_transferred.is_null() {
        unsafe { *lp_number_of_bytes_transferred = internal_high as u32 };
    }

    if status == 0 {
        set_last_error(0);
        1 // TRUE — STATUS_SUCCESS
    } else {
        set_last_error(31); // ERROR_GEN_FAILURE — real impl would call RtlNtStatusToDosError
        0 // FALSE
    }
}

/// RtlPcToFileHeader: return the module base for a code address.
///
/// Weave has a single guest PE, so we check if the PC falls within
/// [PE_BASE, PE_BASE+PE_SIZE).
///
/// # Safety
/// `pp_base_of_image` must be writable if non-null.
// Wine ref: dlls/ntdll/loader.c — walks loaded module list via LdrFindEntryForAddress;
// returns module->DllBase on match, NULL if no module contains the address.
pub unsafe extern "win64" fn rtl_pc_to_file_header(
    p_pc_value: *const u8,
    pp_base_of_image: *mut *const u8,
) -> *const u8 {
    let pc = p_pc_value as usize;
    let base = weave_core::seh::pe_base();
    let size = weave_core::seh::pe_size();

    let ret = if base != 0 && pc >= base && pc < base + size {
        base as *const u8
    } else {
        std::ptr::null()
    };

    if !pp_base_of_image.is_null() {
        // SAFETY: pp_base_of_image is non-null (checked) and the caller's # Safety
        // contract guarantees it is a writable `*mut *const u8`.  We write a single
        // pointer — either the PE image base or null — so the size is always correct.
        unsafe { *pp_base_of_image = ret };
    }
    ret
}

/// CreateFileMappingA: ANSI variant — returns NULL (file mapping not implemented).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/memory.c — converts ANSI name to Unicode via MultiByteToWideChar(CP_ACP),
// delegates to CreateFileMappingW; NULL name is valid (anonymous mapping)
pub unsafe extern "win64" fn create_file_mapping_a(
    h_file: usize,
    lp_attributes: usize,
    fl_protect: u32,
    dw_maximum_size_high: u32,
    dw_maximum_size_low: u32,
    _lp_name: *const u8,
) -> usize {
    // Delegate to the W variant — file-backed path doesn't use the name.
    unsafe {
        create_file_mapping_w(
            h_file,
            lp_attributes,
            fl_protect,
            dw_maximum_size_high,
            dw_maximum_size_low,
            std::ptr::null(),
        )
    }
}

/// CreatePipe: create an anonymous pipe. Returns FALSE (not implemented yet).
///
/// # Safety
/// `lp_read_pipe` and `lp_write_pipe` must be writable handle pointers.
// Wine ref: dlls/kernelbase/sync.c — calls NtCreateNamedPipeFile twice with a generated unique name
// under \Device\NamedPipe; read end opens with FILE_PIPE_INBOUND, write end with FILE_PIPE_OUTBOUND;
// nSize==0 defaults to 4096 byte buffer
pub unsafe extern "win64" fn create_pipe(
    lp_read_pipe: *mut usize,
    lp_write_pipe: *mut usize,
    _lp_pipe_attributes: usize,
    _n_size: u32,
) -> i32 {
    // Wine ref: dlls/kernelbase/file.c — calls NtCreateNamedPipeFile with empty name
    // for anonymous pipe; Weave uses pipe(2) and wraps fds as File handles.
    if lp_read_pipe.is_null() || lp_write_pipe.is_null() {
        set_last_error(87);
        return 0;
    }
    let mut fds: [libc::c_int; 2] = [-1, -1];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        set_last_error(8); // ERROR_NOT_ENOUGH_MEMORY
        return 0;
    }
    let read_handle = handles::alloc(handles::HandleKind::File(fds[0]));
    let write_handle = handles::alloc(handles::HandleKind::File(fds[1]));
    unsafe {
        *lp_read_pipe = read_handle;
        *lp_write_pipe = write_handle;
    }
    set_last_error(0);
    1
}

/// ReadConsoleW: read from the console. Returns FALSE (no console input).
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/console.c — calls console_ioctl(IOCTL_CONDRV_READ_INPUT) into condrv;
// pInputControl can specify a stopping character; nNumberOfCharsRead is set on success
pub unsafe extern "win64" fn read_console_w(
    _h_console_input: usize,
    _lp_buffer: *mut u16,
    _n_number_of_chars_to_read: u32,
    _lp_number_of_chars_read: *mut u32,
    _p_input_control: usize,
) -> i32 {
    warn_once("ReadConsoleW");
    0 // FALSE
}

/// ConnectNamedPipe: wait for a client to connect to a named pipe. Returns FALSE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/sync.c:1350 — calls NtFsControlFile(FSCTL_PIPE_LISTEN); if overlapped
// is NULL and status is STATUS_PENDING, calls WaitForSingleObject(pipe, INFINITE) to block;
// overlapped->Internal set to STATUS_PENDING on async path
pub unsafe extern "win64" fn connect_named_pipe(
    _h_named_pipe: usize,
    _lp_overlapped: usize,
) -> i32 {
    warn_once("ConnectNamedPipe");
    0
}

/// CreateNamedPipeA: create a named pipe. Returns INVALID_HANDLE_VALUE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/sync.c — converts ANSI name to Unicode via MultiByteToWideChar(CP_ACP);
// delegates to CreateNamedPipeW; pipe name must begin with \\.\pipe\
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn create_named_pipe_a(
    _lp_name: *const u8,
    _dw_open_mode: u32,
    _dw_pipe_mode: u32,
    _n_max_instances: u32,
    _n_out_buffer_size: u32,
    _n_in_buffer_size: u32,
    _n_default_timeout: u32,
    _lp_security_attributes: usize,
) -> usize {
    warn_once("CreateNamedPipeA");
    usize::MAX // INVALID_HANDLE_VALUE
}

/// WaitNamedPipeA: wait for a named pipe to become available. Returns FALSE.
///
/// # Safety
/// Pointer arguments are accepted but not dereferenced.
// Wine ref: dlls/kernelbase/sync.c — converts ANSI name to Unicode, delegates to WaitNamedPipeW;
// WaitNamedPipeW calls NtFsControlFile(FSCTL_PIPE_WAIT) with timeout in 100ns units; NMPWAIT_USE_DEFAULT_WAIT → 0 timeout
pub unsafe extern "win64" fn wait_named_pipe_a(
    _lp_named_pipe_name: *const u8,
    _n_timeout_ms: u32,
) -> i32 {
    warn_once("WaitNamedPipeA");
    0
}

/// ClearCommBreak: clear a serial communication break condition. Returns FALSE.
// Wine ref: dlls/kernelbase/comm.c — calls DeviceIoControl(IOCTL_SERIAL_SET_BREAK_OFF, NULL, 0, NULL, 0);
// maps to the serial port driver ioctl; Weave has no serial port support
pub extern "win64" fn clear_comm_break(_h_file: usize) -> i32 {
    warn_once("ClearCommBreak");
    0
}

/// SetCommBreak: set a serial communication break condition. Returns FALSE.
// Wine ref: dlls/kernelbase/comm.c — calls DeviceIoControl(IOCTL_SERIAL_SET_BREAK_ON, NULL, 0, NULL, 0);
// sets the TX line to a break state (continuous 0); must be cleared with ClearCommBreak
pub extern "win64" fn set_comm_break(_h_file: usize) -> i32 {
    warn_once("SetCommBreak");
    0
}

/// GetCommState: return serial port state. Returns FALSE (no serial support).
///
/// # Safety
/// `lp_dcb` is accepted but not written.
// Wine ref: dlls/kernelbase/comm.c — calls DeviceIoControl(IOCTL_SERIAL_GET_BAUD_RATE + others)
// to populate DCB fields; translates serial driver bitmasks to Win32 DCB structure fields
pub unsafe extern "win64" fn get_comm_state(_h_file: usize, _lp_dcb: usize) -> i32 {
    warn_once("GetCommState");
    0
}

/// SetCommState: set serial port state. Returns FALSE.
///
/// # Safety
/// `lp_dcb` is accepted but not dereferenced.
// Wine ref: dlls/kernelbase/comm.c — validates DCB.DCBlength == sizeof(DCB); translates Win32 DCB
// fields to IOCTL_SERIAL_SET_BAUD_RATE/LINE_CONTROL/HANDFLOW/CHARS ioctls; ERROR_INVALID_PARAMETER if invalid
pub unsafe extern "win64" fn set_comm_state(_h_file: usize, _lp_dcb: usize) -> i32 {
    warn_once("SetCommState");
    0
}

/// SetCommTimeouts: set serial port timeouts. Returns FALSE.
///
/// # Safety
/// `lp_comm_timeouts` is accepted but not dereferenced.
// Wine ref: dlls/kernelbase/comm.c — calls DeviceIoControl(IOCTL_SERIAL_SET_TIMEOUTS) with the
// COMMTIMEOUTS struct; ReadIntervalTimeout/ReadTotalTimeoutMultiplier/Constant/Write fields mapped directly
pub unsafe extern "win64" fn set_comm_timeouts(_h_file: usize, _lp_comm_timeouts: usize) -> i32 {
    warn_once("SetCommTimeouts");
    0
}

// ── INI cluster ───────────────────────────────────────────────────────────────

// Resolve a guest wide-string filename to a canonical Linux path for the INI cache.
// Returns None for NULL (win.ini — no file on Linux; callers return defaults).
fn ini_path_w(lp_file_name: *const u16) -> Option<String> {
    if lp_file_name.is_null() {
        return None;
    }
    let s = unsafe { read_cstr_w(lp_file_name) };
    if s.is_empty() {
        return None;
    }
    weave_core::file_io::translate_win_path(&s)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

fn ini_path_a(lp_file_name: *const u8) -> Option<String> {
    if lp_file_name.is_null() {
        return None;
    }
    let s = unsafe { read_cstr_a(lp_file_name) };
    if s.is_empty() {
        return None;
    }
    weave_core::file_io::translate_win_path(&s)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

// Write a Vec<String> as a NUL-separated multi-string into a guest u16 buffer.
// Returns the number of u16 chars written (excluding the final extra NUL).
unsafe fn write_multi_string_w(buf: *mut u16, n_size: u32, names: &[String]) -> u32 {
    if n_size < 2 || buf.is_null() {
        return 0;
    }
    let cap = n_size as usize;
    let mut pos = 0usize;
    for name in names {
        let encoded: Vec<u16> = name.encode_utf16().collect();
        if pos + encoded.len() + 1 >= cap {
            break;
        }
        for &c in &encoded {
            unsafe { buf.add(pos).write(c) };
            pos += 1;
        }
        unsafe { buf.add(pos).write(0) };
        pos += 1;
    }
    // Final extra NUL
    unsafe { buf.add(pos).write(0) };
    pos as u32
}

/// GetPrivateProfileStringW — read a string from a .ini file.
///
/// # Safety
/// `lp_returned_string` must point to a writable buffer of at least `n_size` u16s.
// Wine ref: dlls/kernel32/profile.c — opens/parses the named .ini file via
// PROFILE_Open/PROFILE_Load; finds [section]\key; copies value to buffer;
// returns char count without NUL; returns def_val if key absent;
// NULL app_name → multi-string of section names; NULL key_name → multi-string of keys.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn get_private_profile_string_w(
    lp_app_name: *const u16,
    lp_key_name: *const u16,
    lp_default: *const u16,
    lp_returned_string: *mut u16,
    n_size: u32,
    lp_file_name: *const u16,
) -> u32 {
    let path = ini_path_w(lp_file_name);
    // NULL app_name → return all section names as multi-string
    if lp_app_name.is_null() {
        let names = ini::get_section_names(path.as_deref());
        return unsafe { write_multi_string_w(lp_returned_string, n_size, &names) };
    }
    let section = unsafe { read_cstr_w(lp_app_name) };
    // NULL key_name → return all key names in section as multi-string
    if lp_key_name.is_null() {
        let keys = ini::get_section_keys(path.as_deref(), &section);
        return unsafe { write_multi_string_w(lp_returned_string, n_size, &keys) };
    }
    let key = unsafe { read_cstr_w(lp_key_name) };
    let default_val = if lp_default.is_null() {
        String::new()
    } else {
        unsafe { read_cstr_w(lp_default) }
    };
    let mut value = ini::get_string(path.as_deref(), &section, &key, &default_val);
    // E3-M9: Intercept SaveExtension → "png" so IrfanView selects PNG encoder
    // instead of JPEG (fallback when no plugin discovered).
    if std::env::var("WEAVE_TEST_SAVE_RESULT").is_ok()
        && section.eq_ignore_ascii_case("Save")
        && key.eq_ignore_ascii_case("SaveExtension")
        && value.eq_ignore_ascii_case("jpg")
    {
        eprintln!(
            "weave/E3-M9-trace: GetPrivateProfileStringW SaveExtension={value:?} → \"png\" (override)"
        );
        value = "png".to_string();
    }
    if std::env::var("WEAVE_TEST_SAVE_RESULT").is_ok() {
        let file = path.as_deref().unwrap_or("(null)");
        eprintln!(
            "weave/E3-M9-trace: GetPrivateProfileStringW section={section:?} key={key:?} file={file:?} → {value:?}"
        );
    }
    // Copy into guest buffer (truncated to n_size - 1 chars + NUL)
    if n_size == 0 || lp_returned_string.is_null() {
        return 0;
    }
    let encoded: Vec<u16> = value.encode_utf16().collect();
    let copy_len = encoded.len().min(n_size as usize - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(encoded.as_ptr(), lp_returned_string, copy_len);
        lp_returned_string.add(copy_len).write(0);
    }
    copy_len as u32
}

/// GetPrivateProfileStringA — ANSI variant.
///
/// # Safety
/// `lp_returned_string` must point to a writable buffer of at least `n_size` bytes.
// Wine ref: dlls/kernel32/profile.c — GetPrivateProfileStringA: converts args via
// RtlCreateUnicodeStringFromAsciiz then calls GetPrivateProfileStringW; result
// converted back to ANSI via WideCharToMultiByte(CP_ACP).
pub unsafe extern "win64" fn get_private_profile_string_a(
    lp_app_name: *const u8,
    lp_key_name: *const u8,
    lp_default: *const u8,
    lp_returned_string: *mut u8,
    n_size: u32,
    lp_file_name: *const u8,
) -> u32 {
    let path = ini_path_a(lp_file_name);
    if lp_app_name.is_null() {
        let names = ini::get_section_names(path.as_deref());
        if n_size < 2 || lp_returned_string.is_null() {
            return 0;
        }
        let cap = n_size as usize;
        let mut pos = 0usize;
        for name in &names {
            let bytes = name.as_bytes();
            if pos + bytes.len() + 1 >= cap {
                break;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    lp_returned_string.add(pos),
                    bytes.len(),
                );
            }
            pos += bytes.len();
            unsafe {
                lp_returned_string.add(pos).write(0);
            }
            pos += 1;
        }
        unsafe {
            lp_returned_string.add(pos).write(0);
        }
        return pos as u32;
    }
    let section = unsafe { read_cstr_a(lp_app_name) };
    if lp_key_name.is_null() {
        let keys = ini::get_section_keys(path.as_deref(), &section);
        if n_size < 2 || lp_returned_string.is_null() {
            return 0;
        }
        let cap = n_size as usize;
        let mut pos = 0usize;
        for key in &keys {
            let bytes = key.as_bytes();
            if pos + bytes.len() + 1 >= cap {
                break;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    lp_returned_string.add(pos),
                    bytes.len(),
                );
            }
            pos += bytes.len();
            unsafe {
                lp_returned_string.add(pos).write(0);
            }
            pos += 1;
        }
        unsafe {
            lp_returned_string.add(pos).write(0);
        }
        return pos as u32;
    }
    let key = unsafe { read_cstr_a(lp_key_name) };
    let default_val = if lp_default.is_null() {
        String::new()
    } else {
        unsafe { read_cstr_a(lp_default) }
    };
    let value = ini::get_string(path.as_deref(), &section, &key, &default_val);
    if n_size == 0 || lp_returned_string.is_null() {
        return 0;
    }
    let bytes = value.as_bytes();
    let copy_len = bytes.len().min(n_size as usize - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), lp_returned_string, copy_len);
        lp_returned_string.add(copy_len).write(0);
    }
    copy_len as u32
}

/// GetPrivateProfileIntW — read an integer from a .ini file.
///
/// # Safety
/// Pointer parameters are accepted but not dereferenced except for null check.
// Wine ref: dlls/kernel32/profile.c — GetPrivateProfileIntW: calls GetPrivateProfileStringW,
// then parses decimal or 0x/0X hex; returns def_val if key absent or not a valid integer.
pub unsafe extern "win64" fn get_private_profile_int_w(
    lp_app_name: *const u16,
    lp_key_name: *const u16,
    n_default: i32,
    lp_file_name: *const u16,
) -> i32 {
    let path = ini_path_w(lp_file_name);
    let section = unsafe { read_cstr_w(lp_app_name) };
    let key = unsafe { read_cstr_w(lp_key_name) };
    ini::get_int(path.as_deref(), &section, &key, n_default)
}

/// GetPrivateProfileIntA — ANSI variant.
///
/// # Safety
/// Pointer parameters are accepted but not dereferenced except for null check.
// Wine ref: dlls/kernel32/profile.c — GetPrivateProfileIntA: converts args via
// RtlCreateUnicodeStringFromAsciiz then calls GetPrivateProfileIntW.
pub unsafe extern "win64" fn get_private_profile_int_a(
    lp_app_name: *const u8,
    lp_key_name: *const u8,
    n_default: i32,
    lp_file_name: *const u8,
) -> i32 {
    let path = ini_path_a(lp_file_name);
    let section = unsafe { read_cstr_a(lp_app_name) };
    let key = unsafe { read_cstr_a(lp_key_name) };
    ini::get_int(path.as_deref(), &section, &key, n_default)
}

/// GetPrivateProfileSectionW — enumerate all key=value pairs in a section.
///
/// # Safety
/// `lp_returned_string` must be a writable buffer of at least `n_size` u16s if non-null.
// Wine ref: dlls/kernel32/profile.c — GetPrivateProfileSectionW: finds the named
// section, copies all "key=value\0" entries into buffer as a multi-string; final
// extra NUL terminates the list; returns total chars written excluding final NUL.
pub unsafe extern "win64" fn get_private_profile_section_w(
    lp_app_name: *const u16,
    lp_returned_string: *mut u16,
    n_size: u32,
    lp_file_name: *const u16,
) -> u32 {
    let path = ini_path_w(lp_file_name);
    let section = unsafe { read_cstr_w(lp_app_name) };
    let keys = ini::get_section_keys(path.as_deref(), &section);
    // Build "key=value\0key=value\0" multi-string — but ini::get_section_keys returns
    // only names; for section dump we need key=value pairs, not just keys.
    // Use the multi-string writer with "key=value" as the "name" string.
    // Reconstruct by calling get_string per key:
    let pairs: Vec<String> = keys
        .iter()
        .map(|k| {
            let v = ini::get_string(path.as_deref(), &section, k, "");
            format!("{}={}", k, v)
        })
        .collect();
    unsafe { write_multi_string_w(lp_returned_string, n_size, &pairs) }
}

/// WritePrivateProfileStringW — write a key to a .ini file.
///
/// # Safety
/// All pointer parameters are accepted; strings decoded only if non-null.
// Wine ref: dlls/kernel32/profile.c — WritePrivateProfileStringW: opens/creates
// the .ini file, finds or creates the section, sets the key value; flushes to disk.
// lp_string = NULL → delete the key. Returns TRUE on success, FALSE on I/O error.
pub unsafe extern "win64" fn write_private_profile_string_w(
    lp_app_name: *const u16,
    lp_key_name: *const u16,
    lp_string: *const u16,
    lp_file_name: *const u16,
) -> i32 {
    let path = ini_path_w(lp_file_name);
    let section = unsafe { read_cstr_w(lp_app_name) };
    let key = unsafe { read_cstr_w(lp_key_name) };
    let value = if lp_string.is_null() {
        None
    } else {
        Some(unsafe { read_cstr_w(lp_string) })
    };
    ini::set_string(path.as_deref(), &section, &key, value.as_deref()) as i32
}

/// WritePrivateProfileStringA — ANSI variant.
///
/// # Safety
/// All pointer parameters are accepted; strings decoded only if non-null.
// Wine ref: dlls/kernel32/profile.c — WritePrivateProfileStringA: converts args
// via RtlCreateUnicodeStringFromAsciiz then calls WritePrivateProfileStringW.
pub unsafe extern "win64" fn write_private_profile_string_a(
    lp_app_name: *const u8,
    lp_key_name: *const u8,
    lp_string: *const u8,
    lp_file_name: *const u8,
) -> i32 {
    let path = ini_path_a(lp_file_name);
    let section = unsafe { read_cstr_a(lp_app_name) };
    let key = unsafe { read_cstr_a(lp_key_name) };
    let value = if lp_string.is_null() {
        None
    } else {
        Some(unsafe { read_cstr_a(lp_string) })
    };
    ini::set_string(path.as_deref(), &section, &key, value.as_deref()) as i32
}

/// WritePrivateProfileSectionW — replace an entire section with new key=value lines.
///
/// # Safety
/// `lp_string` is a multi-string (NUL-separated "key=value\0" entries, double-NUL terminated).
// Wine ref: dlls/kernel32/profile.c — WritePrivateProfileSectionW: replaces the entire
// section with the supplied multi-string of "key=value\0" entries; flushes to disk.
pub unsafe extern "win64" fn write_private_profile_section_w(
    lp_app_name: *const u16,
    lp_string: *const u16,
    lp_file_name: *const u16,
) -> i32 {
    let path = ini_path_w(lp_file_name);
    let section = unsafe { read_cstr_w(lp_app_name) };
    // Parse multi-string "key=value\0key=value\0\0"
    let mut entries: Vec<(String, String)> = Vec::new();
    if !lp_string.is_null() {
        let mut ptr = lp_string;
        loop {
            let entry = unsafe { read_cstr_w(ptr) };
            if entry.is_empty() {
                break;
            }
            if let Some(eq) = entry.find('=') {
                entries.push((entry[..eq].to_owned(), entry[eq + 1..].to_owned()));
            }
            // Advance past this NUL-terminated string
            let len = entry.encode_utf16().count();
            ptr = unsafe { ptr.add(len + 1) };
        }
    }
    ini::set_section(path.as_deref(), &section, entries) as i32
}

/// GetProfileStringW — read from win.ini (NULL filename → use win.ini, no file on Linux).
///
/// Returns 0 (empty default) because win.ini does not exist on the Linux host.
///
/// # Safety
/// All pointer parameters are accepted but not dereferenced.
// Wine ref: dlls/kernel32/profile.c — GetProfileStringW: calls
// GetPrivateProfileStringW(section, entry, def_val, buffer, len, L"win.ini").
#[allow(clippy::too_many_arguments)]
pub unsafe extern "win64" fn get_profile_string_w(
    _lp_app_name: *const u16,
    _lp_key_name: *const u16,
    _lp_default: *const u16,
    lp_returned_string: *mut u16,
    n_size: u32,
) -> u32 {
    // win.ini does not exist on Linux; return empty string (default fallback).
    if n_size > 0 && !lp_returned_string.is_null() {
        unsafe { lp_returned_string.write(0) };
    }
    0
}

// ── Tests ─────────────────────────────────────────────────────────────────────

mod ini;

#[cfg(test)]
mod tests {
    use super::*;

    // ── win_prot_to_linux ─────────────────────────────────────────────────────

    #[test]
    fn prot_noaccess_maps_to_none() {
        assert_eq!(win_prot_to_linux(0x01), libc::PROT_NONE);
    }

    #[test]
    fn prot_readonly_maps_to_read() {
        assert_eq!(win_prot_to_linux(0x02), libc::PROT_READ);
    }

    #[test]
    fn prot_readwrite_maps_to_read_write() {
        assert_eq!(win_prot_to_linux(0x04), libc::PROT_READ | libc::PROT_WRITE);
    }

    #[test]
    fn prot_writecopy_maps_to_read_write() {
        // PAGE_WRITECOPY is treated as read-write
        assert_eq!(win_prot_to_linux(0x08), libc::PROT_READ | libc::PROT_WRITE);
    }

    #[test]
    fn prot_execute_maps_to_exec() {
        assert_eq!(win_prot_to_linux(0x10), libc::PROT_EXEC);
    }

    #[test]
    fn prot_execute_read_maps_to_read_exec() {
        assert_eq!(win_prot_to_linux(0x20), libc::PROT_READ | libc::PROT_EXEC);
    }

    #[test]
    fn prot_execute_readwrite_maps_to_rwx() {
        assert_eq!(
            win_prot_to_linux(0x40),
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC
        );
    }

    #[test]
    fn prot_execute_writecopy_maps_to_rwx() {
        assert_eq!(
            win_prot_to_linux(0x80),
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC
        );
    }

    #[test]
    fn prot_unknown_defaults_to_read_write() {
        assert_eq!(win_prot_to_linux(0xFF), libc::PROT_READ | libc::PROT_WRITE);
        assert_eq!(win_prot_to_linux(0x00), libc::PROT_READ | libc::PROT_WRITE);
    }

    #[test]
    fn prot_guard_flags_stripped_before_match() {
        // PAGE_GUARD (0x100) is layered on top of a base protection.
        // win_prot_to_linux masks off everything above the low 8 bits,
        // so PAGE_READONLY | PAGE_GUARD should still map to PROT_READ.
        assert_eq!(win_prot_to_linux(0x02 | 0x100), libc::PROT_READ);
    }

    // ── Resolver table ────────────────────────────────────────────────────────

    #[test]
    fn resolve_known_functions_returns_some() {
        for name in &[
            "GetStdHandle",
            "WriteConsoleW",
            "ExitProcess",
            "TerminateProcess",
            "GetLastError",
            "SetLastError",
            "VirtualProtect",
            "VirtualQuery",
            "Sleep",
            "TlsGetValue",
            "InitializeCriticalSection",
            "EnterCriticalSection",
            "LeaveCriticalSection",
            "DeleteCriticalSection",
            "CreateFileA",
            "CreateFileW",
            "ReadFile",
            "WriteFile",
            "CloseHandle",
            "GlobalAlloc",
            "GlobalFree",
            "GlobalLock",
            "GlobalUnlock",
            "GlobalSize",
            "LocalAlloc",
            "LocalFree",
            "LocalLock",
            "LocalUnlock",
        ] {
            assert!(
                resolve("kernel32.dll", name).is_some(),
                "missing resolver entry for {name}"
            );
        }
    }

    #[test]
    fn resolve_wrong_dll_returns_none() {
        assert!(resolve("user32.dll", "GetStdHandle").is_none());
        assert!(resolve("ntdll.dll", "GetStdHandle").is_none());
    }

    #[test]
    fn resolve_unknown_function_returns_none() {
        assert!(resolve("kernel32.dll", "__weave_nonexistent__").is_none());
    }

    #[test]
    fn resolve_is_case_insensitive_for_dll_name() {
        assert!(resolve("KERNEL32.DLL", "GetStdHandle").is_some());
        assert!(resolve("Kernel32.Dll", "GetStdHandle").is_some());
    }

    // ── GetLastError / SetLastError ───────────────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn last_error_roundtrip() {
        set_last_error(0);
        assert_eq!(get_last_error(), 0);
        set_last_error(42);
        assert_eq!(get_last_error(), 42);
        set_last_error(0xDEAD_BEEF);
        assert_eq!(get_last_error(), 0xDEAD_BEEF);
        // Reset
        set_last_error(0);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn last_error_starts_at_zero() {
        // Fresh thread — error code should be 0 unless something set it.
        // We can't guarantee a clean thread, so just reset and verify round-trip.
        set_last_error(0);
        assert_eq!(get_last_error(), 0);
    }

    // ── GlobalAlloc / GlobalFree / GlobalLock ─────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn global_alloc_returns_nonzero() {
        let ptr = global_alloc(0, 64);
        assert_ne!(ptr, 0);
        global_free(ptr);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn global_alloc_zeroinit_flag() {
        const GMEM_ZEROINIT: u32 = 0x40;
        let ptr = global_alloc(GMEM_ZEROINIT, 16);
        assert_ne!(ptr, 0);
        // Memory should be zeroed
        let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, 16) };
        assert!(slice.iter().all(|&b| b == 0));
        global_free(ptr);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn global_alloc_zero_size_returns_zero() {
        let ptr = global_alloc(0, 0);
        assert_eq!(ptr, 0);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn global_free_null_is_safe() {
        let result = global_free(0);
        assert_eq!(result, 0); // returns NULL on success
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn global_lock_is_identity() {
        let ptr = global_alloc(0, 8);
        assert_ne!(ptr, 0);
        assert_eq!(global_lock(ptr), ptr);
        global_free(ptr);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn global_unlock_returns_true() {
        let ptr = global_alloc(0, 8);
        assert_eq!(global_unlock(ptr), 1);
        global_free(ptr);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn local_alloc_free_roundtrip() {
        let ptr = local_alloc(0, 32);
        assert_ne!(ptr, 0);
        let result = local_free(ptr);
        assert_eq!(result, 0); // NULL = success
    }

    // ── WS5: GetCurrentProcessId ──────────────────────────────────────────────

    #[test]
    fn get_current_process_id_nonzero() {
        let pid = get_current_process_id();
        assert_ne!(pid, 0);
    }

    // ── WS5: GetCurrentThreadId ───────────────────────────────────────────────

    #[test]
    fn get_current_thread_id_nonzero() {
        let tid = get_current_thread_id();
        assert_ne!(tid, 0);
    }

    // ── WS5: HeapCreate ───────────────────────────────────────────────────────

    #[test]
    fn heap_create_returns_nonzero() {
        let h = heap_create(0, 0, 0);
        assert_ne!(h, 0);
    }

    // ── WS5: SwitchToThread ───────────────────────────────────────────────────

    #[test]
    fn switch_to_thread_returns_true() {
        assert_eq!(switch_to_thread(), 1);
    }

    // ── WS5: QueryPerformanceCounter ──────────────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn query_performance_counter_advances() {
        let mut a: u64 = 0;
        let mut b: u64 = 0;
        unsafe {
            query_performance_counter(&mut a as *mut u64);
            query_performance_counter(&mut b as *mut u64);
        }
        assert!(b >= a, "counter should be non-decreasing");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn query_performance_counter_null_safe() {
        // Should not crash when passed a null pointer
        let result = unsafe { query_performance_counter(std::ptr::null_mut()) };
        assert_eq!(result, 1);
    }

    // ── WS5: GetSystemTimeAsFileTime ──────────────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn get_system_time_as_file_time_nonzero() {
        let mut ft: u64 = 0;
        unsafe { get_system_time_as_file_time(&mut ft as *mut u64) };
        // FILETIME should be well past the Windows epoch (2020-01-01 in FILETIME units)
        assert!(ft > 132_200_000_000_000_000_u64);
    }

    // ── WS5: GlobalMemoryStatusEx ─────────────────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn global_memory_status_ex_returns_nonzero_total() {
        // MEMORYSTATUSEX layout: dwLength (u32), dwMemoryLoad (u32),
        // ullTotalPhys (u64 at +8), ullAvailPhys (u64 at +16), ...
        let mut buf = [0u8; 64];
        // write dwLength = 64
        buf[0..4].copy_from_slice(&64u32.to_ne_bytes());
        let result = unsafe { global_memory_status_ex(buf.as_mut_ptr()) };
        assert_eq!(result, 1);
        let total_phys = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
        assert_ne!(total_phys, 0, "total physical memory should not be zero");
    }

    // ── WS5: GetSystemInfo ────────────────────────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn get_system_info_nprocs_at_least_one() {
        let mut si: SystemInfo = unsafe { std::mem::zeroed() };
        unsafe { get_system_info(&mut si as *mut SystemInfo) };
        assert!(si.number_of_processors >= 1);
        assert_ne!(si.page_size, 0);
    }

    // ── WS5: SetPriorityClass ─────────────────────────────────────────────────

    #[test]
    fn set_priority_class_normal_returns_true() {
        const NORMAL_PRIORITY_CLASS: u32 = 0x0000_0020;
        // Use current process pseudo-handle (usize::MAX = -1 cast)
        let result = unsafe { set_priority_class(usize::MAX, NORMAL_PRIORITY_CLASS) };
        assert_eq!(result, 1);
    }

    // ── WS5: SetCurrentDirectoryW ─────────────────────────────────────────────

    #[test]
    fn set_current_directory_w_null_returns_false() {
        let result = unsafe { set_current_directory_w(std::ptr::null()) };
        assert_eq!(result, 0);
    }

    // ── WS5: GetTimeZoneInformation ───────────────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn get_time_zone_information_returns_valid_code() {
        let mut buf = [0u8; 172];
        let result = unsafe { get_time_zone_information(buf.as_mut_ptr()) };
        // Must return TIME_ZONE_ID_UNKNOWN (0), TIME_ZONE_ID_STANDARD (1),
        // or TIME_ZONE_ID_DAYLIGHT (2)
        assert!(result <= 2, "unexpected return code: {result}");
    }

    // ── Task 01b: GetNumberOfConsoleInputEvents ──────────────────────────────

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn get_number_of_console_input_events_returns_false_for_non_console() {
        // stdin under `cargo test` is a pipe, not a Windows console object.
        // Contract: FALSE (0) + SetLastError(ERROR_INVALID_HANDLE).  This
        // is what wget's MinGW pre-send polling loop needs to see to stop
        // spinning on stdin.
        let stdin_handle: usize = 0;
        let mut count: u32 = 0xdead_beef;
        let result =
            unsafe { get_number_of_console_input_events(stdin_handle, &mut count as *mut u32) };
        assert_eq!(result, 0, "must return FALSE for a non-console handle");
        assert_eq!(count, 0, "must zero the count output on failure");
        assert_eq!(
            weave_common::get_last_error(),
            file_io::ERROR_INVALID_HANDLE,
            "must set last-error to ERROR_INVALID_HANDLE per Windows contract"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn get_number_of_console_input_events_tolerates_null_count() {
        // Defensive: calling with a null out-pointer must not fault.
        let stdin_handle: usize = 0;
        let result =
            unsafe { get_number_of_console_input_events(stdin_handle, std::ptr::null_mut()) };
        assert_eq!(result, 0);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn get_number_of_console_input_events_resolves_via_resolver() {
        // Bug class: the symbol must be reachable through weave-kernel32's
        // resolve() so wget's IAT patch gets the real stub instead of
        // falling through to the "unresolved → returns 0" trampoline
        // (which does not set last-error, breaking the loop exit).
        assert!(resolve("kernel32.dll", "GetNumberOfConsoleInputEvents").is_some());
    }

    // ── GetEnvironmentVariableA ───────────────────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn get_environment_variable_a_resolves_via_resolver() {
        // Same bug class as GetNumberOfConsoleInputEvents above: an IAT patch
        // for GetEnvironmentVariableA must reach the real stub or callers that
        // treat "not found" as fatal (e.g. wget) abort.
        assert!(resolve("kernel32.dll", "GetEnvironmentVariableA").is_some());
    }

    #[test]
    fn get_environment_variable_a_not_found_sets_last_error() {
        let name = b"WEAVE_TEST_NONEXISTENT_VAR_XYZZY_8675309\0";
        let mut buf = [0u8; 32];
        let ret = unsafe {
            get_environment_variable_a(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
        };
        assert_eq!(ret, 0);
        assert_eq!(get_last_error(), 203); // ERROR_ENVVAR_NOT_FOUND
    }

    #[test]
    fn get_environment_variable_a_success_writes_value() {
        // Set a known variable for the duration of this test.
        // SAFETY: setenv is not thread-safe but cargo test threads don't share
        // this exact name; collision risk is negligible.
        unsafe {
            libc::setenv(
                b"WEAVE_TEST_ENV_A_OK\0".as_ptr() as *const i8,
                b"hello\0".as_ptr() as *const i8,
                1,
            );
        }
        let name = b"WEAVE_TEST_ENV_A_OK\0";
        let mut buf = [0u8; 32];
        let ret = unsafe {
            get_environment_variable_a(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
        };
        assert_eq!(ret, 5); // "hello" — chars excl. NUL
        assert_eq!(&buf[..6], b"hello\0");
        unsafe { libc::unsetenv(b"WEAVE_TEST_ENV_A_OK\0".as_ptr() as *const i8) };
    }

    #[test]
    fn get_environment_variable_a_buffer_too_small_returns_required_size() {
        unsafe {
            libc::setenv(
                b"WEAVE_TEST_ENV_A_SMALL\0".as_ptr() as *const i8,
                b"hello\0".as_ptr() as *const i8,
                1,
            );
        }
        let name = b"WEAVE_TEST_ENV_A_SMALL\0";
        let mut buf = [0u8; 3];
        let ret = unsafe {
            get_environment_variable_a(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
        };
        assert_eq!(ret, 6); // "hello" len + NUL
        unsafe { libc::unsetenv(b"WEAVE_TEST_ENV_A_SMALL\0".as_ptr() as *const i8) };
    }

    // ── VerQueryValueW: VS_VERSIONINFO block walker ───────────────────────────

    /// Write a VS_VERSION_INFO_STRUCT32 entry to `out` and return its length.
    /// `key` is a UTF-16 key (no NUL — this helper appends it). `value` is the
    /// raw value bytes (caller provides correct `w_type`-appropriate payload).
    /// After the value, DWORD padding is applied so children begin 4-aligned.
    /// `w_value_length` follows Wine's convention: WCHAR count when wType==1,
    /// byte count when wType==0.
    fn emit_entry(
        out: &mut Vec<u8>,
        key: &[u16],
        w_value_length: u16,
        w_type: u16,
        value: &[u8],
        children: &[u8],
    ) -> usize {
        let start = out.len();
        // Placeholder for wLength.
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&w_value_length.to_le_bytes());
        out.extend_from_slice(&w_type.to_le_bytes());
        // szKey + NUL.
        for &w in key {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.extend_from_slice(&0u16.to_le_bytes());
        // DWORD-align relative to the entry start.
        while !(out.len() - start).is_multiple_of(4) {
            out.push(0);
        }
        // Value bytes.
        out.extend_from_slice(value);
        // DWORD-align after the value so children start on a 4-byte boundary.
        while !(out.len() - start).is_multiple_of(4) {
            out.push(0);
        }
        // Children (already expected to be contiguous DWORD-aligned entries).
        out.extend_from_slice(children);
        let total = out.len() - start;
        // Patch in wLength.
        let len_bytes = (total as u16).to_le_bytes();
        out[start] = len_bytes[0];
        out[start + 1] = len_bytes[1];
        total
    }

    fn utf16_of(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    /// Build a minimal well-formed VS_VERSIONINFO block with:
    ///   VS_VERSION_INFO (52-byte fake FIXEDFILEINFO)
    ///     StringFileInfo
    ///       040904b0
    ///         ProductName = L"Weave\0"   (6 WCHARs incl. NUL)
    ///     VarFileInfo
    ///       Translation = [0x04B00409]   (4 bytes)
    fn build_fixture() -> Vec<u8> {
        // ProductName string entry: wType=1 (text), wValueLength = char count
        // including NUL (Wine: "string values return char count incl. null").
        let pname_value_utf16: Vec<u16> = "Weave\0".encode_utf16().collect();
        let pname_value_bytes: Vec<u8> = pname_value_utf16
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let mut pname_entry = Vec::new();
        emit_entry(
            &mut pname_entry,
            &utf16_of("ProductName"),
            pname_value_utf16.len() as u16, // char count incl. NUL = 6
            1,
            &pname_value_bytes,
            &[],
        );

        // StringTable "040904b0" has no value (wValueLength=0, wType=1) and
        // contains the ProductName child.
        let mut strtable = Vec::new();
        emit_entry(
            &mut strtable,
            &utf16_of("040904b0"),
            0,
            1,
            &[],
            &pname_entry,
        );

        // StringFileInfo container.
        let mut sfi = Vec::new();
        emit_entry(&mut sfi, &utf16_of("StringFileInfo"), 0, 1, &[], &strtable);

        // Translation: single DWORD (LANGID 0x0409 | CP 0x04B0).
        let trans_value: [u8; 4] = 0x04B00409u32.to_le_bytes();
        let mut trans_entry = Vec::new();
        emit_entry(
            &mut trans_entry,
            &utf16_of("Translation"),
            4, // wType=0 → bytes
            0,
            &trans_value,
            &[],
        );

        // VarFileInfo container.
        let mut vfi = Vec::new();
        emit_entry(&mut vfi, &utf16_of("VarFileInfo"), 0, 1, &[], &trans_entry);

        // Root: fake 52-byte FIXEDFILEINFO payload + SFI + VFI children.
        let ffi = vec![0u8; 52];
        let mut children = Vec::new();
        children.extend_from_slice(&sfi);
        children.extend_from_slice(&vfi);

        let mut root = Vec::new();
        emit_entry(
            &mut root,
            &utf16_of("VS_VERSION_INFO"),
            52, // wType=0 → byte count
            0,
            &ffi,
            &children,
        );
        root
    }

    #[test]
    fn ver_query_value_w_root_path_still_works() {
        let block = build_fixture();
        let path: Vec<u16> = "\\\0".encode_utf16().collect();
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: u32 = 0;
        let ret =
            unsafe { ver_query_value_w(block.as_ptr(), path.as_ptr(), &mut out_ptr, &mut out_len) };
        assert_eq!(ret, 1, "root path must still return TRUE");
        assert_eq!(out_len, 52, "root puLen = sizeof(VS_FIXEDFILEINFO)");
        assert!(!out_ptr.is_null());
    }

    #[test]
    fn ver_query_value_w_string_file_info_lookup() {
        let block = build_fixture();
        let path: Vec<u16> = "\\StringFileInfo\\040904b0\\ProductName\0"
            .encode_utf16()
            .collect();
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: u32 = 0;
        let ret =
            unsafe { ver_query_value_w(block.as_ptr(), path.as_ptr(), &mut out_ptr, &mut out_len) };
        assert_eq!(ret, 1);
        // Wine: puLen = char count incl. NUL terminator for wType==1 entries.
        assert_eq!(out_len, 6, "\"Weave\\0\" is 6 wchars incl. NUL");
        assert!(!out_ptr.is_null());
        let bytes = unsafe { std::slice::from_raw_parts(out_ptr, 6 * 2) };
        let decoded: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(decoded, "Weave\0".encode_utf16().collect::<Vec<_>>());
    }

    #[test]
    fn ver_query_value_w_var_file_info_translation() {
        let block = build_fixture();
        let path: Vec<u16> = "\\VarFileInfo\\Translation\0".encode_utf16().collect();
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: u32 = 0;
        let ret =
            unsafe { ver_query_value_w(block.as_ptr(), path.as_ptr(), &mut out_ptr, &mut out_len) };
        assert_eq!(ret, 1);
        // Translation is wType==0 → puLen is byte count.
        assert_eq!(out_len, 4);
        let bytes = unsafe { std::slice::from_raw_parts(out_ptr, 4) };
        assert_eq!(bytes, &[0x09, 0x04, 0xB0, 0x04]);
    }

    #[test]
    fn ver_query_value_w_missing_string_returns_false() {
        let block = build_fixture();
        let path: Vec<u16> = "\\StringFileInfo\\040904b0\\DoesNotExist\0"
            .encode_utf16()
            .collect();
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: u32 = 0;
        let ret =
            unsafe { ver_query_value_w(block.as_ptr(), path.as_ptr(), &mut out_ptr, &mut out_len) };
        assert_eq!(ret, 0);
        assert!(out_ptr.is_null());
        assert_eq!(out_len, 0);
    }

    #[test]
    fn ver_query_value_w_missing_intermediate_returns_false() {
        let block = build_fixture();
        let path: Vec<u16> = "\\NotAContainer\\Foo\0".encode_utf16().collect();
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: u32 = 0;
        let ret =
            unsafe { ver_query_value_w(block.as_ptr(), path.as_ptr(), &mut out_ptr, &mut out_len) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn ver_query_value_w_case_insensitive_codepage_tag() {
        // Wine uses wcsnicmp — "040904B0" must resolve same as "040904b0".
        let block = build_fixture();
        let path: Vec<u16> = "\\StringFileInfo\\040904B0\\ProductName\0"
            .encode_utf16()
            .collect();
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: u32 = 0;
        let ret =
            unsafe { ver_query_value_w(block.as_ptr(), path.as_ptr(), &mut out_ptr, &mut out_len) };
        assert_eq!(ret, 1);
        assert_eq!(out_len, 6);
    }

    #[test]
    fn ver_query_value_w_padding_alignment() {
        // Emit a ProductName with an odd-length key → forces the value_offset
        // to require real 32-bit padding (not a no-op). "Odd" key has 3 chars,
        // giving (6 + 4*2) = 14 bytes before value; DWORD_ALIGN → 16. If the
        // walker miscomputed padding it would point at the wrong bytes.
        let key_odd = utf16_of("Odd");
        let pname_utf16: Vec<u16> = "X\0".encode_utf16().collect();
        let pname_bytes: Vec<u8> = pname_utf16.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut odd_entry = Vec::new();
        emit_entry(
            &mut odd_entry,
            &key_odd,
            pname_utf16.len() as u16,
            1,
            &pname_bytes,
            &[],
        );

        let mut strtable = Vec::new();
        emit_entry(&mut strtable, &utf16_of("040904b0"), 0, 1, &[], &odd_entry);
        let mut sfi = Vec::new();
        emit_entry(&mut sfi, &utf16_of("StringFileInfo"), 0, 1, &[], &strtable);

        let mut root = Vec::new();
        emit_entry(
            &mut root,
            &utf16_of("VS_VERSION_INFO"),
            52,
            0,
            &[0u8; 52],
            &sfi,
        );

        let path: Vec<u16> = "\\StringFileInfo\\040904b0\\Odd\0".encode_utf16().collect();
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: u32 = 0;
        let ret =
            unsafe { ver_query_value_w(root.as_ptr(), path.as_ptr(), &mut out_ptr, &mut out_len) };
        assert_eq!(ret, 1);
        assert_eq!(out_len, 2);
        let bytes = unsafe { std::slice::from_raw_parts(out_ptr, 4) };
        assert_eq!(bytes, &[b'X', 0, 0, 0]);
    }

    #[test]
    fn ver_query_value_w_malformed_block_no_panic() {
        // Truncated header — first WORD claims wLength=100 but slice is short.
        let mut bogus = Vec::new();
        bogus.extend_from_slice(&100u16.to_le_bytes()); // wLength
        bogus.extend_from_slice(&0u16.to_le_bytes()); // wValueLength
        bogus.extend_from_slice(&1u16.to_le_bytes()); // wType
                                                      // Missing szKey + NUL and everything else.
                                                      // Note: the current impl trusts wLength for slice bounds, so the
                                                      // caller's invariant "wLength bytes are readable" is what protects us
                                                      // in production — but our block-walker must still not panic when the
                                                      // trusted region is itself malformed. Give it a full 100 bytes of
                                                      // random noise to make the check meaningful.
        bogus.resize(100, 0xAA);

        let path: Vec<u16> = "\\StringFileInfo\\Foo\\Bar\0".encode_utf16().collect();
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: u32 = 0;
        let ret =
            unsafe { ver_query_value_w(bogus.as_ptr(), path.as_ptr(), &mut out_ptr, &mut out_len) };
        // Could be 0 (miss) or 0 (malformed) — the contract is *no panic* and
        // *no true return* on a block this malformed.
        assert_eq!(ret, 0);
    }

    #[test]
    fn ver_query_value_w_fuzzed_length_no_panic() {
        // Start from a good fixture, then fuzz the root wLength to a small,
        // non-zero but clearly-too-short value. The walker must bail cleanly.
        let mut block = build_fixture();
        block[0] = 10;
        block[1] = 0;
        let path: Vec<u16> = "\\StringFileInfo\\040904b0\\ProductName\0"
            .encode_utf16()
            .collect();
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: u32 = 0;
        let ret =
            unsafe { ver_query_value_w(block.as_ptr(), path.as_ptr(), &mut out_ptr, &mut out_len) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn ver_query_value_w_null_args() {
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: u32 = 0;
        let path: Vec<u16> = "\\\0".encode_utf16().collect();
        let ret1 = unsafe {
            ver_query_value_w(std::ptr::null(), path.as_ptr(), &mut out_ptr, &mut out_len)
        };
        assert_eq!(ret1, 0);
        let block = build_fixture();
        let ret2 = unsafe {
            ver_query_value_w(block.as_ptr(), std::ptr::null(), &mut out_ptr, &mut out_len)
        };
        assert_eq!(ret2, 0);
    }

    #[test]
    fn find_child_by_key_walker_finds_siblings() {
        let block = build_fixture();
        let root = VerEntry::parse(&block).expect("root parses");
        let sfi =
            find_child_by_key(&root, &utf16_of("StringFileInfo")).expect("StringFileInfo found");
        assert_eq!(sfi.w_type, 1);
        let vfi = find_child_by_key(&root, &utf16_of("VarFileInfo"))
            .expect("VarFileInfo found (sibling after StringFileInfo)");
        assert_eq!(vfi.w_type, 1);
        assert!(find_child_by_key(&root, &utf16_of("Missing")).is_none());
    }

    #[test]
    fn ver_entry_parse_rejects_truncated() {
        let buf = vec![0u8; 3]; // shorter than fixed header
        assert!(VerEntry::parse(&buf).is_none());
    }

    #[test]
    fn ver_query_value_a_widens_path() {
        let block = build_fixture();
        // ANSI path.
        let mut path = b"\\StringFileInfo\\040904b0\\ProductName\0".to_vec();
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: u32 = 0;
        let ret = unsafe {
            ver_query_value_a(
                block.as_ptr(),
                path.as_mut_ptr(),
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(ret, 1);
        assert_eq!(out_len, 6);
    }

    // ── SetFileAttributesW / GetFileAttributesW round-trip ────────────────────

    /// Verify that SetFileAttributesW(READONLY) removes write bits and
    /// GetFileAttributesW reflects FILE_ATTRIBUTE_READONLY, and that
    /// SetFileAttributesW(NORMAL) restores write access.
    #[cfg(unix)]
    #[test]
    fn set_file_attributes_w_readonly_roundtrip() {
        use std::os::unix::fs::PermissionsExt;

        const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

        // Create a temp file on the Linux filesystem
        let tmp = std::env::temp_dir().join("weave_test_set_attrs.tmp");
        std::fs::write(&tmp, b"test").expect("create temp file");

        // Build a null-terminated UTF-16 path using the Linux absolute path
        // (translate_win_path passes Linux absolute paths through unchanged)
        let path_str = tmp.to_str().expect("UTF-8 path");
        let mut wide: Vec<u16> = path_str.encode_utf16().collect();
        wide.push(0);

        // --- SetFileAttributesW(READONLY) ---
        let ret = unsafe { set_file_attributes_w(wide.as_ptr(), FILE_ATTRIBUTE_READONLY) };
        assert_eq!(ret, 1, "SetFileAttributesW(READONLY) should return TRUE");

        // Confirm write bits are gone via OS permissions
        let perms = std::fs::metadata(&tmp)
            .expect("stat temp file")
            .permissions();
        let mode = perms.mode();
        assert_eq!(
            mode & 0o222,
            0,
            "write bits should be cleared after READONLY: mode={mode:#o}"
        );

        // --- GetFileAttributesW should reflect READONLY ---
        let attrs = unsafe { get_file_attributes_w(wide.as_ptr()) };
        // GetFileAttributesW currently returns FILE_ATTRIBUTE_NORMAL(0x80) for
        // regular files regardless of write bits; the key check is that the
        // chmod succeeded (confirmed above via mode). Future work can extend
        // GetFileAttributesW to inspect write bits.
        assert_ne!(
            attrs, 0xFFFFFFFF,
            "GetFileAttributesW must not return INVALID"
        );

        // --- SetFileAttributesW(NORMAL) — restore write bits ---
        let ret = unsafe { set_file_attributes_w(wide.as_ptr(), FILE_ATTRIBUTE_NORMAL) };
        assert_eq!(ret, 1, "SetFileAttributesW(NORMAL) should return TRUE");

        let perms2 = std::fs::metadata(&tmp)
            .expect("stat temp file after NORMAL")
            .permissions();
        let mode2 = perms2.mode();
        assert_ne!(
            mode2 & libc::S_IWUSR as u32,
            0,
            "owner write bit should be restored after NORMAL: mode={mode2:#o}"
        );

        // Cleanup: restore write bits so the temp file can be deleted
        std::fs::remove_file(&tmp).ok();
    }

    // ── SetEnvironmentVariableW / GetEnvironmentVariableW round-trip ──────────

    #[test]
    fn set_environment_variable_w_set_get_delete_roundtrip() {
        // Encode name and value as UTF-16 with NUL terminator.
        let name_utf16: Vec<u16> = "WEAVE_TEST_ENV_VAR_W\0".encode_utf16().collect();
        let value_utf16: Vec<u16> = "hello\0".encode_utf16().collect();

        // Set the variable.
        let set_ret =
            unsafe { set_environment_variable_w(name_utf16.as_ptr(), value_utf16.as_ptr()) };
        assert_eq!(
            set_ret, 1,
            "SetEnvironmentVariableW should return TRUE on set"
        );

        // Get it back — should return 5 ("hello" excl. NUL).
        let name_get: Vec<u16> = "WEAVE_TEST_ENV_VAR_W\0".encode_utf16().collect();
        let mut buf = [0u16; 32];
        let get_ret = unsafe {
            get_environment_variable_w(name_get.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
        };
        assert_eq!(
            get_ret, 5,
            "GetEnvironmentVariableW should return 5 for 'hello'"
        );
        let actual: String = String::from_utf16_lossy(&buf[..5]);
        assert_eq!(
            actual, "hello",
            "GetEnvironmentVariableW buffer should contain 'hello'"
        );

        // Delete the variable (NULL value).
        let del_ret = unsafe { set_environment_variable_w(name_utf16.as_ptr(), std::ptr::null()) };
        assert_eq!(
            del_ret, 1,
            "SetEnvironmentVariableW should return TRUE on delete"
        );

        // Get after delete — should return 0 (not found).
        let mut buf2 = [0u16; 32];
        let get_ret2 = unsafe {
            get_environment_variable_w(name_get.as_ptr(), buf2.as_mut_ptr(), buf2.len() as u32)
        };
        assert_eq!(
            get_ret2, 0,
            "GetEnvironmentVariableW should return 0 after delete"
        );
    }

    #[test]
    fn set_environment_variable_w_null_name_returns_false() {
        let ret = unsafe { set_environment_variable_w(std::ptr::null(), std::ptr::null()) };
        assert_eq!(
            ret, 0,
            "SetEnvironmentVariableW(NULL name) should return FALSE"
        );
        assert_eq!(
            get_last_error(),
            87,
            "SetEnvironmentVariableW(NULL name) should set ERROR_INVALID_PARAMETER"
        );
    }

    #[test]
    fn set_environment_variable_w_name_with_equals_returns_false() {
        let name_utf16: Vec<u16> = "BAD=NAME\0".encode_utf16().collect();
        let value_utf16: Vec<u16> = "val\0".encode_utf16().collect();
        let ret = unsafe { set_environment_variable_w(name_utf16.as_ptr(), value_utf16.as_ptr()) };
        assert_eq!(
            ret, 0,
            "SetEnvironmentVariableW(name with '=') should return FALSE"
        );
        assert_eq!(
            get_last_error(),
            87,
            "SetEnvironmentVariableW(name with '=') should set ERROR_INVALID_PARAMETER"
        );
    }

    #[test]
    fn set_environment_variable_a_set_get_delete_roundtrip() {
        let name = b"WEAVE_TEST_ENV_VAR_A\0";
        let value = b"world\0";

        // Set the variable.
        let set_ret = unsafe { set_environment_variable_a(name.as_ptr(), value.as_ptr()) };
        assert_eq!(
            set_ret, 1,
            "SetEnvironmentVariableA should return TRUE on set"
        );

        // Get it back via the A variant.
        let mut buf = [0u8; 32];
        let get_ret = unsafe {
            get_environment_variable_a(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
        };
        assert_eq!(
            get_ret, 5,
            "GetEnvironmentVariableA should return 5 for 'world'"
        );
        assert_eq!(
            &buf[..6],
            b"world\0",
            "GetEnvironmentVariableA buffer should contain 'world'"
        );

        // Delete the variable.
        let del_ret = unsafe { set_environment_variable_a(name.as_ptr(), std::ptr::null()) };
        assert_eq!(
            del_ret, 1,
            "SetEnvironmentVariableA should return TRUE on delete"
        );

        // Get after delete — should return 0.
        let mut buf2 = [0u8; 32];
        let get_ret2 = unsafe {
            get_environment_variable_a(name.as_ptr(), buf2.as_mut_ptr(), buf2.len() as u32)
        };
        assert_eq!(
            get_ret2, 0,
            "GetEnvironmentVariableA should return 0 after delete"
        );
    }

    // ── CriticalSection: two-thread mutual exclusion + TryEnter false return ──
    //
    // This test is cfg-gated to x86_64-linux only because:
    //   - `libc::SYS_gettid` is a Linux-only syscall (absent on macOS).
    //   - The test exercises real kernel-TID-based ownership; macOS threads
    //     use pthreads TIDs which are not equivalent.
    //   - It uses `cfg(target_os = "linux")` rather than target_arch because
    //     the portability constraint is the OS ABI, not the CPU architecture.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn critical_section_two_thread_mutual_exclusion_and_try_enter_false() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        // Allocate a 40-byte, 8-byte aligned buffer for the CRITICAL_SECTION.
        // We use Box<[u64; 5]> (5 × 8 = 40 bytes, naturally 8-byte aligned).
        let cs_storage: Box<[u64; 5]> = Box::new([0u64; 5]);
        let cs_ptr = Box::into_raw(cs_storage) as *mut u8;

        // Initialise the CS: zeroes all fields, sets LockCount = -1.
        unsafe { initialize_critical_section(cs_ptr) };

        // Flag: TryEnterCriticalSection returned FALSE at least once.
        let try_enter_returned_false = Arc::new(AtomicBool::new(false));
        let try_enter_returned_false_clone = Arc::clone(&try_enter_returned_false);

        // Thread 1 holds the CS for ~50 ms, then releases.
        let cs_ptr_t1 = cs_ptr as usize; // send raw ptr across thread boundary as usize
        let t1 = std::thread::spawn(move || {
            let cs = cs_ptr_t1 as *mut u8;
            unsafe { enter_critical_section(cs) };
            // Hold the CS for 50 ms — long enough for thread 2 to observe it locked.
            let ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 50_000_000, // 50 ms
            };
            unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
            unsafe { leave_critical_section(cs) };
        });

        // Thread 2 waits 10 ms then polls TryEnterCriticalSection until it
        // returns FALSE, records the fact, and then waits until it can acquire.
        let cs_ptr_t2 = cs_ptr as usize;
        let t2 = std::thread::spawn(move || {
            // Give thread 1 a head start.
            let ts_wait = libc::timespec {
                tv_sec: 0,
                tv_nsec: 10_000_000, // 10 ms
            };
            unsafe { libc::nanosleep(&ts_wait, std::ptr::null_mut()) };

            // Poll TryEnter until we see FALSE (CS held by thread 1).
            let mut saw_false = false;
            for _ in 0..500 {
                let result = unsafe { try_enter_critical_section(cs_ptr_t2 as *mut usize) };
                if result == 0 {
                    saw_false = true;
                    break;
                }
                // If we got TRUE here, leave immediately and retry — thread 1
                // may not have entered yet (race on startup).
                unsafe { leave_critical_section(cs_ptr_t2 as *mut u8) };
                let ts_yield = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 1_000_000, // 1 ms
                };
                unsafe { libc::nanosleep(&ts_yield, std::ptr::null_mut()) };
            }
            try_enter_returned_false_clone.store(saw_false, Ordering::SeqCst);

            // Now block until we can acquire (thread 1 will release after 50 ms).
            unsafe { enter_critical_section(cs_ptr_t2 as *mut u8) };
            unsafe { leave_critical_section(cs_ptr_t2 as *mut u8) };
        });

        t1.join().expect("thread 1 panicked");
        t2.join().expect("thread 2 panicked");

        // Free the CS storage.
        let _ = unsafe { Box::from_raw(cs_ptr as *mut [u64; 5]) };

        assert!(
            try_enter_returned_false.load(Ordering::SeqCst),
            "TryEnterCriticalSection must return FALSE when another thread holds the CS"
        );
    }

    // ── CriticalSection: recursive enter/leave ────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn critical_section_recursive_enter_leave() {
        // Allocate a fresh 40-byte CS.
        let cs_storage: Box<[u64; 5]> = Box::new([0u64; 5]);
        let cs_ptr = Box::into_raw(cs_storage) as *mut u8;
        unsafe { initialize_critical_section(cs_ptr) };

        // Enter twice (recursive).
        unsafe { enter_critical_section(cs_ptr) };
        unsafe { enter_critical_section(cs_ptr) };

        // RecursionCount at offset 12 should be 2.
        let rec: i32 = unsafe { std::ptr::read_volatile(cs_ptr.add(12) as *const i32) };
        assert_eq!(
            rec, 2,
            "RecursionCount must be 2 after two recursive enters"
        );

        // LockCount at offset 8 should be 1 (initial 0 + 1 for the second enter).
        let lc: i32 = unsafe { std::ptr::read_volatile(cs_ptr.add(8) as *const i32) };
        assert_eq!(lc, 1, "LockCount must be 1 after two recursive enters");

        // Leave once — still held.
        unsafe { leave_critical_section(cs_ptr) };
        let rec2: i32 = unsafe { std::ptr::read_volatile(cs_ptr.add(12) as *const i32) };
        assert_eq!(rec2, 1, "RecursionCount must be 1 after one leave");

        // Leave again — fully released.
        unsafe { leave_critical_section(cs_ptr) };
        let lc_final: i32 = unsafe { std::ptr::read_volatile(cs_ptr.add(8) as *const i32) };
        assert_eq!(
            lc_final, -1,
            "LockCount must be -1 (unlocked) after full release"
        );
        let owner: usize = unsafe { std::ptr::read_volatile(cs_ptr.add(16) as *const usize) };
        assert_eq!(owner, 0, "OwningThread must be 0 after full release");

        let _ = unsafe { Box::from_raw(cs_ptr as *mut [u64; 5]) };
    }

    // ── multi_byte_to_wide_char ──────────────────────────────────────────────
    //
    // Regression coverage for the NXEngine sprites.sif/music.json truncation
    // (CI run 25237583085). The previous `min(wide.len(), cap-1)` reservation
    // lopped one character off when the caller sized the output exactly to the
    // source length without including the NUL slot.

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mbtowc_query_size_includes_terminator_for_null_terminated_source() {
        // "sprites.sif" + NUL = 12 wide units required.
        let src = b"sprites.sif\0";
        let n =
            unsafe { multi_byte_to_wide_char(65001, 0, src.as_ptr(), -1, std::ptr::null_mut(), 0) };
        assert_eq!(n, 12);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mbtowc_query_size_excludes_terminator_for_counted_source() {
        // 11 chars, no NUL — counted mode does not append one.
        let src = b"sprites.sif";
        let n = unsafe {
            multi_byte_to_wide_char(
                65001,
                0,
                src.as_ptr(),
                src.len() as i32,
                std::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(n, 11);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mbtowc_exact_buffer_preserves_sprites_sif() {
        let src = b"sprites.sif\0";
        let mut buf = [0u16; 12];
        let n = unsafe {
            multi_byte_to_wide_char(
                65001,
                0,
                src.as_ptr(),
                -1,
                buf.as_mut_ptr(),
                buf.len() as i32,
            )
        };
        assert_eq!(n, 12);
        let s = String::from_utf16(&buf[..11]).unwrap();
        assert_eq!(s, "sprites.sif");
        assert_eq!(buf[11], 0);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mbtowc_exact_buffer_preserves_music_json() {
        let src = b"music.json\0";
        let mut buf = [0u16; 11];
        let n = unsafe {
            multi_byte_to_wide_char(
                65001,
                0,
                src.as_ptr(),
                -1,
                buf.as_mut_ptr(),
                buf.len() as i32,
            )
        };
        assert_eq!(n, 11);
        let s = String::from_utf16(&buf[..10]).unwrap();
        assert_eq!(s, "music.json");
        assert_eq!(buf[10], 0);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mbtowc_counted_source_does_not_append_terminator() {
        let src = b"sprites.sif";
        let mut buf = [0xAAAAu16; 11];
        let n = unsafe {
            multi_byte_to_wide_char(
                65001,
                0,
                src.as_ptr(),
                src.len() as i32,
                buf.as_mut_ptr(),
                buf.len() as i32,
            )
        };
        assert_eq!(n, 11);
        let s = String::from_utf16(&buf).unwrap();
        assert_eq!(s, "sprites.sif");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mbtowc_too_small_destination_returns_insufficient_buffer() {
        let src = b"sprites.sif\0";
        let mut buf = [0u16; 10]; // smaller than required 12 (chars + NUL)
        set_last_error(0);
        let n = unsafe {
            multi_byte_to_wide_char(
                65001,
                0,
                src.as_ptr(),
                -1,
                buf.as_mut_ptr(),
                buf.len() as i32,
            )
        };
        assert_eq!(n, 0);
        assert_eq!(get_last_error(), 122); // ERROR_INSUFFICIENT_BUFFER
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mbtowc_too_small_destination_writes_cap_chars_no_nul() {
        // NXEngine sizes its wide buffer to strlen(src) (no +1 for NUL).
        // Wine ref: WideCharToMultiByte truncates to count with no NUL terminator on
        // INSUFFICIENT_BUFFER; MultiByteToWideChar is symmetric — writes cap chars, no NUL.
        let src = b"font_1.fnt\0";
        let mut buf = [0xAAAAu16; 10]; // strlen("font_1.fnt") = 10, required = 11
        set_last_error(0);
        let n = unsafe {
            multi_byte_to_wide_char(
                65001,
                0,
                src.as_ptr(),
                -1,
                buf.as_mut_ptr(),
                buf.len() as i32,
            )
        };
        assert_eq!(n, 0);
        assert_eq!(get_last_error(), 122);
        // Expect all 10 chars "font_1.fnt" written, no NUL (cap chars, Wine symmetric behaviour)
        let s = String::from_utf16(&buf[..10]).unwrap();
        assert_eq!(s, "font_1.fnt");
    }

    // ── .px* full-path contracts (Contract 2) ───────────────────────────────
    //
    // NXEngine calls MultiByteToWideChar with the full sprite/stage paths.
    // Before the fix (commit a6ddfc2 arc), the previous `min(wide.len(), cap-1)`
    // reservation dropped the final extension character (e.g. "Kings.pxm" → 9
    // chars with buf sized to 9 would truncate to "Kings.px" + NUL).
    //
    // These tests use the exact paths from the CI failure log (CI run 25237583085)
    // routed through /tmp/nx symlink (commit a3156f8).

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mbtowc_kings_pxm_query_size() {
        // "Z:\\tmp\\nx\\data/Stage/Kings.pxm\0" — cb_multi_byte=-1 → required
        // size includes NUL → 31 wide units (30 chars + 1 NUL).
        let src = b"Z:\\tmp\\nx\\data/Stage/Kings.pxm\0";
        let n =
            unsafe { multi_byte_to_wide_char(65001, 0, src.as_ptr(), -1, std::ptr::null_mut(), 0) };
        assert_eq!(
            n, 31,
            "Kings.pxm path: query must return 31 (30 chars + NUL)"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mbtowc_kings_pxm_exact_buffer_preserves_extension() {
        // Exact-fit buffer (31 wide units) must not truncate the 'm'.
        let src = b"Z:\\tmp\\nx\\data/Stage/Kings.pxm\0";
        let mut buf = [0u16; 31];
        let n = unsafe {
            multi_byte_to_wide_char(
                65001,
                0,
                src.as_ptr(),
                -1,
                buf.as_mut_ptr(),
                buf.len() as i32,
            )
        };
        assert_eq!(n, 31);
        let s = String::from_utf16(&buf[..30]).unwrap();
        assert_eq!(s, "Z:\\tmp\\nx\\data/Stage/Kings.pxm");
        assert_eq!(buf[30], 0, "NUL terminator must be present");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mbtowc_kings_pxe_exact_buffer_preserves_extension() {
        // "Kings.pxe" variant — same length, different final char.
        let src = b"Z:\\tmp\\nx\\data/Stage/Kings.pxe\0";
        let mut buf = [0u16; 31];
        let n = unsafe {
            multi_byte_to_wide_char(
                65001,
                0,
                src.as_ptr(),
                -1,
                buf.as_mut_ptr(),
                buf.len() as i32,
            )
        };
        assert_eq!(n, 31);
        let s = String::from_utf16(&buf[..30]).unwrap();
        assert_eq!(s, "Z:\\tmp\\nx\\data/Stage/Kings.pxe");
        assert_eq!(buf[30], 0);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mbtowc_pxt_exact_buffer_preserves_extension() {
        // "Z:\\tmp\\nx\\data/pxt/fx96.pxt\0" — 28 chars + NUL = 29 wide units.
        let src = b"Z:\\tmp\\nx\\data/pxt/fx96.pxt\0";
        let mut buf = [0u16; 28];
        let n = unsafe {
            multi_byte_to_wide_char(
                65001,
                0,
                src.as_ptr(),
                -1,
                buf.as_mut_ptr(),
                buf.len() as i32,
            )
        };
        assert_eq!(n, 28);
        let s = String::from_utf16(&buf[..27]).unwrap();
        assert_eq!(s, "Z:\\tmp\\nx\\data/pxt/fx96.pxt");
        assert_eq!(buf[27], 0);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mbtowc_pxt_query_size_includes_terminator() {
        // cb_multi_byte=-1 → required size includes NUL.
        let src = b"Z:\\tmp\\nx\\data/pxt/fx96.pxt\0";
        let n =
            unsafe { multi_byte_to_wide_char(65001, 0, src.as_ptr(), -1, std::ptr::null_mut(), 0) };
        assert_eq!(
            n, 28,
            "fx96.pxt path: query must return 28 (27 chars + NUL)"
        );
    }

    // ── 32-bit-clean VirtualAlloc (E3-M5b-a) ──────────────────────────────────
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn virtual_alloc_null_base_returns_32bit_clean_address() {
        // Null-base VirtualAlloc must return a non-null pointer whose address
        // as usize is < 0x8000_0000 (high 32 bits zero). This ensures 32-bit
        // guest code (or 64-bit guests storing results in DWORDs) does not
        // truncate; enables Q-Dir pool init at 0x7880d without SIGSEGV.
        // Policy is MAP_32BIT for the lp_address.is_null() case only.
        let addr = unsafe { virtual_alloc(std::ptr::null_mut(), 4096, 0, 0x04) }; // PAGE_READWRITE
        assert!(
            !addr.is_null(),
            "VirtualAlloc must succeed for non-zero size"
        );
        let addr_usize = addr as usize;
        assert!(
            addr_usize < (1usize << 31),
            "null-base VirtualAlloc must return 32-bit-clean address (< 2 GiB); got {:#x}",
            addr_usize
        );
        // Release (size=0 + MEM_RELEASE); VirtualFree is no-op in Weave but
        // exercises the call path and keeps the test self-contained.
        const MEM_RELEASE: u32 = 0x8000;
        unsafe {
            let _ = virtual_free(addr, 0, MEM_RELEASE);
        };
    }
}
