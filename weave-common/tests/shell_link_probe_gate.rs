// Only x86_64 supports the "win64" calling convention used by the COM vtables.
// This file is excluded from the aarch64-apple-darwin native test run.
#![cfg(target_arch = "x86_64")]

// Probe gate — TASK-9: IPersistFile::Save callback receives correct shortcut data.
//
// Simulates a full installer shortcut-creation sequence:
//   create_shell_link → SetPath → SetDescription → QI(IPersistFile) → Save
// and asserts the registered callback receives the expected field values.

use std::sync::Mutex;

use weave_common::com::shell_link::{
    create_shell_link, register_save_callback, ShellLinkObject, ShellLinkSaveData,
    CLSID_SHELL_LINK, IID_ISHELL_LINK_W,
};

static CAPTURED: Mutex<Option<ShellLinkSaveData>> = Mutex::new(None);

fn test_callback(data: &ShellLinkSaveData) -> Result<(), String> {
    *CAPTURED.lock().unwrap() = Some(data.clone());
    Ok(())
}

#[test]
fn shell_link_save_callback_receives_correct_data() {
    register_save_callback(test_callback);

    let mut ppv: *mut () = std::ptr::null_mut();

    unsafe {
        // ── create_shell_link ────────────────────────────────────────────────
        let r = create_shell_link(
            CLSID_SHELL_LINK.as_ptr(),
            IID_ISHELL_LINK_W.as_ptr(),
            &mut ppv,
        );
        assert_eq!(r, 0, "create_shell_link must return S_OK");
        assert!(!ppv.is_null(), "ppv must be non-null");

        let obj = ppv as *mut ShellLinkObject;

        // The COM object pointer is the address of the vtable-pointer field (first
        // field of repr(C) ShellLinkObject). Dereference to get the vtable pointer.
        let vtable: *const usize = *obj as *const usize;

        // ── SetPath (slot 20) ────────────────────────────────────────────────
        let path_w: Vec<u16> = "C:\\Program Files\\MyApp\\myapp.exe"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        #[allow(clippy::transmute_ptr_to_ptr)]
        let set_path_fn: unsafe extern "win64" fn(*mut ShellLinkObject, *const u16) -> u32 =
            std::mem::transmute(*vtable.add(20));
        assert_eq!(
            set_path_fn(obj, path_w.as_ptr()),
            0,
            "SetPath must return S_OK"
        );

        // ── SetDescription (slot 7) ──────────────────────────────────────────
        let desc_w: Vec<u16> = "My Application"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        #[allow(clippy::transmute_ptr_to_ptr)]
        let set_desc_fn: unsafe extern "win64" fn(*mut ShellLinkObject, *const u16) -> u32 =
            std::mem::transmute(*vtable.add(7));
        assert_eq!(
            set_desc_fn(obj, desc_w.as_ptr()),
            0,
            "SetDescription must return S_OK"
        );

        // ── QueryInterface(IID_IPersistFile) ─────────────────────────────────
        // IID_IPersistFile = {0000010B-0000-0000-C000-000000000046}
        let iid_persist_file: [u8; 16] = [
            0x0B, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ];
        let mut pfile: *mut () = std::ptr::null_mut();
        #[allow(clippy::transmute_ptr_to_ptr)]
        let qi_fn: unsafe extern "win64" fn(
            *mut ShellLinkObject,
            *const u8,
            *mut *mut (),
        ) -> u32 = std::mem::transmute(*vtable.add(0));
        assert_eq!(
            qi_fn(obj, iid_persist_file.as_ptr(), &mut pfile),
            0,
            "QueryInterface(IID_IPersistFile) must return S_OK"
        );
        assert!(!pfile.is_null(), "QI for IPersistFile must return non-null");

        // ── IPersistFile::Save (slot 6) ──────────────────────────────────────
        // `pfile` points to the `persist_file_vtable` field of ShellLinkObject.
        // Dereference to get the vtable pointer (a *const [usize; 9]), then index
        // slot 6 to get the Save function pointer.
        let pf_vtable_ptr: *const usize = *(pfile as *const *const usize);
        let lnk_w: Vec<u16> = "C:\\Users\\Public\\Desktop\\MyApp.lnk"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        #[allow(clippy::transmute_ptr_to_ptr)]
        let save_fn: unsafe extern "win64" fn(*mut (), *const u16, i32) -> u32 =
            std::mem::transmute(*pf_vtable_ptr.add(6));
        assert_eq!(
            save_fn(pfile, lnk_w.as_ptr(), 1),
            0,
            "IPersistFile::Save must return S_OK"
        );
    }

    // ── Verify callback received correct data ────────────────────────────────
    let captured = CAPTURED.lock().unwrap();
    let data = captured
        .as_ref()
        .expect("IPersistFile::Save callback must have been invoked");

    assert_eq!(
        data.path.as_deref(),
        Some("C:\\Program Files\\MyApp\\myapp.exe"),
        "path must match SetPath argument"
    );
    assert_eq!(
        data.description.as_deref(),
        Some("My Application"),
        "description must match SetDescription argument"
    );
    assert!(
        data.lnk_dest_path.ends_with("MyApp.lnk"),
        "lnk_dest_path must end with the .lnk filename, got: {:?}",
        data.lnk_dest_path
    );
}
