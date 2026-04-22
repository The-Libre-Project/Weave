// Wine ref: dlls/shell32/shelllink.c — IShellLinkW_Constructor allocates an IShellLinkImpl
// struct with vtable pointer as first field (COM object layout: object ptr IS the vtable ptr).
// Struct fields: sPath, sArgs, sWorkDir, sDescription, iIcoNdx, iShowCmd, bDirty, ref.
// Each Set* fn (e.g. IShellLinkW_fnSetPath) decodes LPWSTR arg and stores in impl struct,
// marks bDirty=TRUE, returns S_OK. QueryInterface returns S_OK for IShellLinkW / IUnknown /
// IPersistFile and E_NOINTERFACE otherwise.

use std::sync::OnceLock;

// ── CLSID / IID constants ─────────────────────────────────────────────────────

/// CLSID_ShellLink = {00021401-0000-0000-C000-000000000046} (little-endian wire bytes)
pub const CLSID_SHELL_LINK: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x46,
];

/// IID_IShellLinkW = {000214F9-0000-0000-C000-000000000046} (little-endian wire bytes)
pub const IID_ISHELL_LINK_W: [u8; 16] = [
    0xF9, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x46,
];

/// IID_IUnknown = {00000000-0000-0000-C000-000000000046}
const IID_IUNKNOWN: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x46,
];

/// IID_IPersistFile = {0000010B-0000-0000-C000-000000000046}
const IID_IPERSIST_FILE: [u8; 16] = [
    0x0B, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x46,
];

// ── Vtable slot counts ────────────────────────────────────────────────────────

// IShellLinkW vtable slot layout (authoritative):
//   0:  QueryInterface      (IUnknown)
//   1:  AddRef              (IUnknown)
//   2:  Release             (IUnknown)
//   3:  GetPath
//   4:  GetIDList
//   5:  SetIDList
//   6:  GetDescription
//   7:  SetDescription
//   8:  GetWorkingDirectory
//   9:  SetWorkingDirectory
//   10: GetArguments
//   11: SetArguments
//   12: GetHotkey
//   13: SetHotkey
//   14: GetShowCmd
//   15: SetShowCmd
//   16: GetIconLocation
//   17: SetIconLocation
//   18: SetRelativePath
//   19: Resolve
//   20: SetPath
// Total: 21 slots.
const VTABLE_SLOTS: usize = 21;

// IPersistFile inherits IPersist which inherits IUnknown:
//   0: QueryInterface  (IUnknown)
//   1: AddRef          (IUnknown)
//   2: Release         (IUnknown)
//   3: GetClassID      (IPersist)
//   4: IsDirty         (IPersistFile)
//   5: Load            (IPersistFile)
//   6: Save            (IPersistFile) — TASK-9 fills this in
//   7: SaveCompleted   (IPersistFile)
//   8: GetCurFile      (IPersistFile)
// Total: 9 slots.
const PERSIST_FILE_SLOTS: usize = 9;

// ── Static vtable accessors ───────────────────────────────────────────────────

/// Returns a reference to the lazily-initialized IShellLinkW vtable.
///
/// Function-pointer-to-usize casts are not permitted in `const` context in Rust,
/// so the vtable is built once at first use via `OnceLock`.
fn shell_link_vtable() -> &'static [usize; VTABLE_SLOTS] {
    static VTABLE: OnceLock<[usize; VTABLE_SLOTS]> = OnceLock::new();
    VTABLE.get_or_init(|| {
        let mut v = [0usize; VTABLE_SLOTS];
        // Slot 0: QueryInterface
        v[0] = shell_link_query_interface
            as unsafe extern "win64" fn(*mut ShellLinkObject, *const u8, *mut *mut ()) -> u32
            as usize;
        // Slot 1: AddRef
        v[1] =
            shell_link_add_ref as unsafe extern "win64" fn(*mut ShellLinkObject) -> u32 as usize;
        // Slot 2: Release
        v[2] =
            shell_link_release as unsafe extern "win64" fn(*mut ShellLinkObject) -> u32 as usize;
        // Slots 3-6: Get* methods — leave 0 (not called by installers)
        // Slot 7: SetDescription
        v[7] = shell_link_set_description
            as unsafe extern "win64" fn(*mut ShellLinkObject, *const u16) -> u32
            as usize;
        // Slot 8: GetWorkingDirectory — leave 0
        // Slot 9: SetWorkingDirectory
        v[9] = shell_link_set_working_dir
            as unsafe extern "win64" fn(*mut ShellLinkObject, *const u16) -> u32
            as usize;
        // Slot 10: GetArguments — leave 0
        // Slot 11: SetArguments
        v[11] = shell_link_set_arguments
            as unsafe extern "win64" fn(*mut ShellLinkObject, *const u16) -> u32
            as usize;
        // Slots 12-14: GetHotkey, SetHotkey, GetShowCmd — leave 0
        // Slot 15: SetShowCmd
        v[15] = shell_link_set_show_cmd
            as unsafe extern "win64" fn(*mut ShellLinkObject, i32) -> u32
            as usize;
        // Slot 16: GetIconLocation — leave 0
        // Slot 17: SetIconLocation
        v[17] = shell_link_set_icon_location
            as unsafe extern "win64" fn(*mut ShellLinkObject, *const u16, i32) -> u32
            as usize;
        // Slots 18-19: SetRelativePath, Resolve — leave 0
        // Slot 20: SetPath
        v[20] = shell_link_set_path
            as unsafe extern "win64" fn(*mut ShellLinkObject, *const u16) -> u32
            as usize;
        v
    })
}

/// Returns a reference to the lazily-initialized IPersistFile vtable.
///
/// All slots are 0 except Save (slot 6) — TASK-9 fills that in. Built via
/// `OnceLock` for the same reason as `shell_link_vtable`.
fn persist_file_vtable() -> &'static [usize; PERSIST_FILE_SLOTS] {
    static VTABLE: OnceLock<[usize; PERSIST_FILE_SLOTS]> = OnceLock::new();
    VTABLE.get_or_init(|| [0usize; PERSIST_FILE_SLOTS])
}

// ── COM object layout ─────────────────────────────────────────────────────────

/// Data fields of an IShellLink COM object.
///
/// Wine ref: dlls/shell32/shelllink.c — IShellLinkImpl holds sPath, sArgs, sWorkDir,
/// sDescription, sIcoPath, iIcoNdx, iShowCmd, bDirty, ref. We keep the fields needed
/// for shortcut creation (TASK-8 and TASK-9 use these).
pub struct ShellLinkState {
    pub path: Option<String>,
    pub arguments: Option<String>,
    pub working_dir: Option<String>,
    pub icon_path: Option<String>,
    pub icon_index: i32,
    pub description: Option<String>,
    pub show_cmd: i32,
}

/// The on-heap COM object: vtable pointer first (Windows COM ABI), then the
/// IPersistFile vtable pointer (for QueryInterface(IID_IPersistFile)), then state.
///
/// The pointer returned to the caller via `*ppv` points to this struct's first
/// field (`vtable`). When the caller dereferences it to invoke a method, it reads
/// the vtable pointer, indexes into the array, and calls through. `repr(C)` ensures
/// the compiler does not reorder fields.
///
/// For QueryInterface(IID_IPersistFile) the returned pointer is
/// `&raw mut (*this).persist_file_vtable` — the COM caller expects the returned
/// pointer to point directly at the IPersistFile vtable-pointer field.
#[repr(C)]
pub struct ShellLinkObject {
    /// Pointer to the static IShellLinkW vtable array. Must be the first field (COM ABI).
    pub vtable: *const [usize; VTABLE_SLOTS],
    /// Pointer to the static IPersistFile vtable array.
    /// QueryInterface(IID_IPersistFile) returns the address of this field.
    pub persist_file_vtable: *const [usize; PERSIST_FILE_SLOTS],
    /// Reference count (AddRef/Release — simplified: always returns 1).
    pub ref_count: u32,
    /// IShellLink data fields.
    pub state: ShellLinkState,
}

// SAFETY: ShellLinkObject is only accessed through the Win64 COM ABI (single-threaded
// apartment). The vtable pointers are shared statics — immutable after program start.
unsafe impl Send for ShellLinkObject {}
unsafe impl Sync for ShellLinkObject {}

// ── Private helper ────────────────────────────────────────────────────────────

/// Decode a null-terminated UTF-16 string pointer into a Rust String.
///
/// # Safety
/// `ptr` must be null or a valid pointer to a null-terminated u16 sequence.
unsafe fn decode_wide(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

// ── IShellLinkW method implementations ───────────────────────────────────────

// Wine ref: dlls/shell32/shelllink.c — IShellLinkW_fnSetPath: decodes LPWSTR,
// frees old sPath, wcsdup's new value into This->sPath, marks bDirty=TRUE,
// returns S_OK. Handles advertised shortcut detection; we skip that.
unsafe extern "win64" fn shell_link_set_path(
    this: *mut ShellLinkObject,
    psz_file: *const u16,
) -> u32 {
    (*this).state.path = Some(decode_wide(psz_file));
    eprintln!(
        "weave/common: SetPath({:?})",
        (*this).state.path.as_deref().unwrap_or("")
    );
    0 // S_OK
}

// Wine ref: dlls/shell32/shelllink.c — IShellLinkW_fnSetArguments: decodes LPWSTR,
// stores in This->sArgs, marks bDirty=TRUE, returns S_OK.
unsafe extern "win64" fn shell_link_set_arguments(
    this: *mut ShellLinkObject,
    psz_args: *const u16,
) -> u32 {
    (*this).state.arguments = Some(decode_wide(psz_args));
    0 // S_OK
}

// Wine ref: dlls/shell32/shelllink.c — IShellLinkW_fnSetDescription: decodes LPWSTR,
// stores in This->sDescription, marks bDirty=TRUE, returns S_OK.
unsafe extern "win64" fn shell_link_set_description(
    this: *mut ShellLinkObject,
    psz_name: *const u16,
) -> u32 {
    (*this).state.description = Some(decode_wide(psz_name));
    0 // S_OK
}

// Wine ref: dlls/shell32/shelllink.c — IShellLinkW_fnSetWorkingDirectory: decodes LPWSTR,
// stores in This->sWorkDir, marks bDirty=TRUE, returns S_OK.
unsafe extern "win64" fn shell_link_set_working_dir(
    this: *mut ShellLinkObject,
    psz_dir: *const u16,
) -> u32 {
    (*this).state.working_dir = Some(decode_wide(psz_dir));
    0 // S_OK
}

// Wine ref: dlls/shell32/shelllink.c — IShellLinkW_fnSetIconLocation: decodes LPWSTR path,
// stores in This->sIcoPath, stores iIcon in This->iIcoNdx, marks bDirty=TRUE, returns S_OK.
unsafe extern "win64" fn shell_link_set_icon_location(
    this: *mut ShellLinkObject,
    psz_icon_path: *const u16,
    i_icon: i32,
) -> u32 {
    (*this).state.icon_path = Some(decode_wide(psz_icon_path));
    (*this).state.icon_index = i_icon;
    0 // S_OK
}

// Wine ref: dlls/shell32/shelllink.c — IShellLinkW_fnSetShowCmd: stores iShowCmd in
// This->iShowCmd, marks bDirty=TRUE, returns S_OK.
unsafe extern "win64" fn shell_link_set_show_cmd(
    this: *mut ShellLinkObject,
    i_show_cmd: i32,
) -> u32 {
    (*this).state.show_cmd = i_show_cmd;
    0 // S_OK
}

// Wine ref: dlls/shell32/shelllink.c — IShellLinkW_fnQueryInterface: compares riid
// against IID_IShellLinkW, IID_IUnknown, IID_IPersistFile. Returns S_OK + sets *ppv
// on match; E_NOINTERFACE + nulls *ppv otherwise. AddRef on success.
unsafe extern "win64" fn shell_link_query_interface(
    this: *mut ShellLinkObject,
    riid: *const u8,
    ppv_object: *mut *mut (),
) -> u32 {
    const E_NOINTERFACE: u32 = 0x8000_4002;

    if ppv_object.is_null() {
        return E_NOINTERFACE;
    }

    // Read 16-byte IID from caller.
    let iid: [u8; 16] = std::ptr::read_unaligned(riid as *const [u8; 16]);

    if iid == IID_IUNKNOWN || iid == IID_ISHELL_LINK_W {
        // Return base pointer (IShellLinkW interface == base of object).
        *ppv_object = this as *mut ();
        0 // S_OK
    } else if iid == IID_IPERSIST_FILE {
        // Return address of persist_file_vtable field (COM IPersistFile sub-object).
        *ppv_object = std::ptr::addr_of_mut!((*this).persist_file_vtable) as *mut ();
        0 // S_OK
    } else {
        *ppv_object = std::ptr::null_mut();
        E_NOINTERFACE
    }
}

unsafe extern "win64" fn shell_link_add_ref(_this: *mut ShellLinkObject) -> u32 {
    1
}

unsafe extern "win64" fn shell_link_release(_this: *mut ShellLinkObject) -> u32 {
    1
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Create an IShellLink COM object and write its pointer to `*ppv`.
///
/// Called from `weave-ole32::co_create_instance` when the CLSID matches
/// `CLSID_ShellLink`. Allocates a `ShellLinkObject` on the heap and writes the
/// address of its `vtable` field (which IS the COM object pointer per the ABI)
/// into `*ppv`. Returns `S_OK` (0) on success.
///
/// # Safety
/// `ppv` must be a valid writable pointer to a `*mut ()` output slot.
/// `rclsid` and `riid` must be null or valid 16-byte GUID pointers.
///
/// # Wine ref
/// dlls/shell32/shelllink.c — IShellLinkW_Constructor: `LocalAlloc(LMEM_ZEROINIT)`,
/// sets vtable pointer (`sl->IShellLinkW_iface.lpVtbl = &slvtw`) as first usable
/// field. The COM object pointer returned to the caller is the address of the
/// IShellLinkW vtable-pointer field, not the base of the allocation.
pub unsafe extern "win64" fn create_shell_link(
    _rclsid: *const u8,
    _riid: *const u8,
    ppv: *mut *mut (),
) -> u32 {
    const S_OK: u32 = 0;

    if ppv.is_null() {
        return 0x8007_0057; // E_INVALIDARG
    }

    // Allocate the COM object on the heap. Box takes ownership; we immediately
    // leak it because lifetime is managed by COM AddRef/Release.
    let obj = Box::new(ShellLinkObject {
        vtable: shell_link_vtable(),
        persist_file_vtable: persist_file_vtable(),
        ref_count: 1,
        state: ShellLinkState {
            path: None,
            arguments: None,
            working_dir: None,
            icon_path: None,
            icon_index: 0,
            description: None,
            show_cmd: 0,
        },
    });

    // The COM object pointer is the address of the struct's first field (vtable),
    // which is the base of the allocation for a repr(C) struct. Cast to *mut ().
    let raw: *mut ShellLinkObject = Box::into_raw(obj);

    // SAFETY: raw is non-null (just allocated), ppv is non-null (checked above).
    unsafe { *ppv = raw as *mut () };

    eprintln!("weave/common: create_shell_link → ShellLinkObject @ {raw:?} (ref=1)");

    S_OK
}
