//! Probe gate — E3-M9f: LoadLibrary("COMDLG32.dll") returns a synthetic handle.
//!
//! IrfanView dynamically loads comdlg32 for Save As; without this, LoadLibrary
//! returns NULL and the save path aborts before GetSaveFileNameW.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use weave_kernel32::load_library_w;

#[test]
fn comdlg32_load_library_probe_gate() {
    let name: Vec<u16> = "COMDLG32.dll\0".encode_utf16().collect();
    let h = unsafe { load_library_w(name.as_ptr()) };
    assert_ne!(
        h, 0,
        "LoadLibrary(COMDLG32.dll) must return non-NULL synthetic handle"
    );
    let h2 = unsafe { load_library_w(name.as_ptr()) };
    assert_eq!(h, h2, "second LoadLibrary must return the same handle");
}
