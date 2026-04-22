// Wine ref: dlls/shell32/shelllink.c — IShellLinkW_Constructor allocates an IShellLinkImpl
// struct with vtable pointer as first field (COM object layout: object ptr IS the vtable ptr).
// Struct fields: sPath, sArgs, sWorkDir, sDescription, iIcoNdx, iShowCmd, bDirty, ref.
// Vtable is a static array of fn pointers; IShellLinkW slots 0-2 = QI/AddRef/Release,
// slots 3-16 = IShellLinkW methods (all 0 here — filled in by TASK-8).

// ── CLSID / IID constants ─────────────────────────────────────────────────────

/// CLSID_ShellLink = {00021401-0000-0000-C000-000000000046} (little-endian wire bytes)
pub const CLSID_SHELL_LINK: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// IID_IShellLinkW = {000214F9-0000-0000-C000-000000000046} (little-endian wire bytes)
pub const IID_ISHELL_LINK_W: [u8; 16] = [
    0xF9, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

// ── Vtable ────────────────────────────────────────────────────────────────────

// IShellLinkW vtable slot count:
//   Slots 0-2:   IUnknown  — QueryInterface, AddRef, Release
//   Slots 3-16:  IShellLinkW — GetPath, GetIDList, SetIDList, GetDescription,
//                SetDescription, GetWorkingDirectory, SetWorkingDirectory,
//                GetArguments, SetArguments, GetHotkey, SetHotkey,
//                GetIconLocation, SetIconLocation, SetRelativePath,
//                Resolve, SetPath  (Wine: 16 methods, 0-indexed → 13 slots = 3..=16)
// Total: 17 slots.
const VTABLE_SLOTS: usize = 17;

/// Static vtable for IShellLinkW COM objects.
/// All slots are 0 (null) — TASK-8 installs the method implementations.
/// The vtable pointer stored in `ShellLinkObject.vtable` points here.
static SHELL_LINK_VTABLE: [usize; VTABLE_SLOTS] = [0usize; VTABLE_SLOTS];

// ── COM object layout ─────────────────────────────────────────────────────────

/// Data fields of an IShellLink COM object.
///
/// Wine ref: dlls/shell32/shelllink.c — IShellLinkImpl holds sPath, sArgs, sWorkDir,
/// sDescription, iIcoNdx (icon index), iShowCmd, bDirty, ref, plus optional sPathRel,
/// sProduct, sComponent, volume, pPidl. We keep the six fields needed for shortcut
/// creation (TASK-8 and TASK-9 use these).
pub struct ShellLinkState {
    pub path: Option<String>,
    pub arguments: Option<String>,
    pub working_dir: Option<String>,
    pub icon_path: Option<String>,
    pub icon_index: i32,
    pub description: Option<String>,
}

/// The on-heap COM object: vtable pointer first (Windows COM ABI), then the state.
///
/// The pointer returned to the caller via `*ppv` points to this struct's first
/// field (`vtable`). When the caller dereferences it to invoke a method, it reads
/// the vtable pointer, indexes into the array, and calls through. `repr(C)` ensures
/// the compiler does not reorder fields.
#[repr(C)]
pub struct ShellLinkObject {
    /// Pointer to the static vtable array. Must be the first field (COM ABI).
    pub vtable: *const [usize; VTABLE_SLOTS],
    /// Reference count (AddRef/Release — TASK-8 fills these in).
    pub ref_count: u32,
    /// IShellLink data fields.
    pub state: ShellLinkState,
}

// SAFETY: ShellLinkObject is only accessed through the Win64 COM ABI (single-threaded
// apartment). The vtable pointer is a shared static — it is immutable after program
// start and safe to send between threads in terms of aliasing.
unsafe impl Send for ShellLinkObject {}
unsafe impl Sync for ShellLinkObject {}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Create an IShellLink COM object and write its pointer to `*ppv`.
///
/// Called from `weave-ole32::co_create_instance` when the CLSID matches
/// `CLSID_ShellLink`. Allocates a `ShellLinkObject` on the heap and writes the
/// address of its `vtable` field (which IS the COM object pointer per the ABI)
/// into `*ppv`. Returns `S_OK` (0) on success.
///
/// The `riid` argument is accepted but not validated here — TASK-8 will add
/// QueryInterface which will enforce the IID check at runtime.
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
    // leak it because lifetime is managed by COM AddRef/Release (TASK-8).
    let obj = Box::new(ShellLinkObject {
        vtable: &SHELL_LINK_VTABLE,
        ref_count: 1,
        state: ShellLinkState {
            path: None,
            arguments: None,
            working_dir: None,
            icon_path: None,
            icon_index: 0,
            description: None,
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
