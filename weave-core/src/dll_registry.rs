//! Global registry of PE DLLs loaded into the Weave process.
//!
//! When Weave pre-loads DLLs from the prefix (e.g. DXVK's d3d11.dll), their
//! export tables are registered here. The IAT patcher and runtime
//! `GetProcAddress` both query this registry to resolve imports that aren't
//! handled by Weave's own stub crates.
//!
//! DLL memory is intentionally never unmapped — loaded DLLs live for the
//! entire process lifetime.

use crate::loader::LoadedImage;
use std::collections::HashMap;
use std::mem::ManuallyDrop;
use std::sync::{Mutex, MutexGuard, OnceLock};

struct DllEntry {
    /// Keeps the mapped memory alive. ManuallyDrop prevents munmap on drop —
    /// DLL memory must outlive the process.
    _image: ManuallyDrop<LoadedImage>,
    /// Function name → absolute address in the loaded image.
    exports: HashMap<String, usize>,
}

// Safety: DllEntry fields are only mutated during registration (single-
// threaded startup), after which they are read-only.
unsafe impl Send for DllEntry {}
unsafe impl Sync for DllEntry {}

static REGISTRY: OnceLock<Mutex<HashMap<String, DllEntry>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<String, DllEntry>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_registry<'a>(
    m: &'a Mutex<HashMap<String, DllEntry>>,
) -> Option<MutexGuard<'a, HashMap<String, DllEntry>>> {
    m.lock()
        .map_err(|e| eprintln!("weave: weave-core: dll registry mutex poisoned: {e}"))
        .ok()
}

/// Register a loaded DLL and its export table.
///
/// `name` is the lowercase DLL filename (e.g. `"d3d11.dll"`).
/// Takes ownership of `image` to keep the mapped memory alive; the memory is
/// never freed.
pub fn register(name: String, image: LoadedImage, exports: HashMap<String, usize>) {
    let entry = DllEntry {
        _image: ManuallyDrop::new(image),
        exports,
    };
    if let Some(mut reg) = lock_registry(registry()) {
        reg.insert(name, entry);
    }
}

/// Look up a function exported by a registered DLL.
///
/// `dll` is matched case-insensitively (e.g. `"D3D11.DLL"` finds `"d3d11.dll"`).
/// Returns the absolute address of the function in the loaded image, or `None`
/// if the DLL is not registered or the function is not found.
pub fn lookup(dll: &str, func: &str) -> Option<usize> {
    let reg = lock_registry(registry())?;
    reg.get(&dll.to_lowercase())?.exports.get(func).copied()
}

/// Check whether a DLL is currently registered (regardless of which exports it has).
///
/// Used by the LoadLibrary transitive-load path to avoid re-mapping a DLL that's
/// already been loaded into the process address space.
pub fn is_registered(dll: &str) -> bool {
    if let Some(reg) = lock_registry(registry()) {
        reg.contains_key(&dll.to_lowercase())
    } else {
        false
    }
}
