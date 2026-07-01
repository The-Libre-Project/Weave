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
use std::collections::{HashMap, HashSet, VecDeque};
use std::mem::ManuallyDrop;
use std::sync::{Mutex, MutexGuard, OnceLock};

struct DllEntry {
    /// Keeps the mapped memory alive. ManuallyDrop prevents munmap on drop —
    /// DLL memory must outlive the process.
    _image: ManuallyDrop<LoadedImage>,
    /// Function name → absolute address in the loaded image.
    exports: HashMap<String, usize>,
    /// Native DllMain entry point address (from the PE's AddressOfEntryPoint),
    /// or None if the DLL has no DllMain.
    entry_point: Option<usize>,
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
    let entry_point = if image.entry_point.is_null() {
        None
    } else {
        Some(image.entry_point as usize)
    };
    let entry = DllEntry {
        _image: ManuallyDrop::new(image),
        exports,
        entry_point,
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

/// Return the native DllMain function pointer for a registered PE DLL.
///
/// Returns `Some(absolute_address)` if the DLL is registered and has a
/// non-null AddressOfEntryPoint, or `None` if it has no DllMain.
pub fn get_entry_point(dll: &str) -> Option<usize> {
    let reg = lock_registry(registry())?;
    reg.get(&dll.to_lowercase())?.entry_point
}

/// Return the loaded base address of a registered PE DLL.
pub fn get_base(dll: &str) -> Option<usize> {
    let reg = lock_registry(registry())?;
    reg.get(&dll.to_lowercase())
        .map(|e| e._image.base as usize)
}

// ── Import dependency graph for DllMain call ordering ──────────────────────
//
// Each entry maps a registered DLL (lowercase name) to the set of DLLs it
// imports from.  The graph is built incrementally during the loading phase
// and consumed by `dllmain_order()` to produce a topological sort.

static DEP_GRAPH: OnceLock<Mutex<HashMap<String, HashSet<String>>>> = OnceLock::new();

fn dep_graph() -> &'static Mutex<HashMap<String, HashSet<String>>> {
    DEP_GRAPH.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record which DLLs `dll` imports from.
///
/// `deps` are the lowercase DLL names that appear in `dll`'s import table.
/// Call this once per loaded DLL during the loading phase, immediately
/// after `register`.  The dependency edge direction is `dll` → dep (dll
/// depends on dep), so dep's DllMain must run before dll's DllMain.
pub fn register_imports(dll: &str, deps: &[String]) {
    let dll_lower = dll.to_lowercase();
    if let Ok(mut g) = dep_graph().lock() {
        let entry = g.entry(dll_lower).or_default();
        for dep in deps {
            entry.insert(dep.to_lowercase());
        }
    }
}

/// Return all registered DLLs in dependency order for DllMain dispatch.
///
/// Uses Kahn's algorithm (BFS topological sort) on the import dependency
/// graph.  Dependencies come before dependents — kernel32 → ntdll → ucrt
/// → ... → leaf DLLs — so that a forward scan calling DllMain on each
/// entry guarantees every DLL's imports are already initialised.
///
/// DLLs that import from unregistered DLLs (e.g. a Weave stub crate) are
/// ordered only by their registered-DLL dependencies; the unknown imports
/// produce no ordering constraint.
///
/// Returns an empty vec if no DLLs have been registered.
pub fn dllmain_order() -> Vec<String> {
    let reg = match lock_registry(registry()) {
        Some(r) => r,
        None => return Vec::new(),
    };
    let g = match dep_graph().lock() {
        Ok(g) => g,
        Err(_) => return Vec::new(),
    };

    // Every registered DLL is a graph node, even if it imports nothing.
    let all_dlls: HashSet<&str> = reg.keys().map(|s| s.as_str()).collect();

    // Kahn's algorithm.  in_degree[dll] = number of registered DLLs that
    // dll imports from (deps that are themselves registered).  Nodes with
    // in_degree 0 depend on nothing → they go first.
    let mut in_degree: HashMap<&str, usize> = HashMap::new();
    let mut reverse_adj: HashMap<&str, Vec<&str>> = HashMap::new();

    for dll in &all_dlls {
        in_degree.entry(dll).or_insert(0);
        if let Some(deps) = g.get(*dll) {
            for dep in deps {
                reverse_adj.entry(dep.as_str()).or_default().push(dll);
                if all_dlls.contains(dep.as_str()) {
                    *in_degree.entry(dll).or_insert(0) += 1;
                }
            }
        }
    }

    let mut result: Vec<String> = Vec::with_capacity(all_dlls.len());
    let mut queue: VecDeque<&str> = VecDeque::new();

    for dll in &all_dlls {
        if in_degree[dll] == 0 {
            queue.push_back(dll);
        }
    }

    while let Some(dll) = queue.pop_front() {
        result.push(dll.to_string());
        if let Some(dependents) = reverse_adj.get(dll) {
            for dep in dependents {
                let deg = in_degree.get_mut(dep).unwrap();
                *deg = deg.saturating_sub(1);
                if *deg == 0 {
                    queue.push_back(dep);
                }
            }
        }
    }

    // If a cycle exists, remaining nodes won't have been emitted.
    // Append them in arbitrary order so the caller always gets a
    // complete list (cycles are pathological in real Windows DLLs).
    if result.len() < all_dlls.len() {
        let emitted: HashSet<String> = result.iter().cloned().collect();
        for dll in &all_dlls {
            if !emitted.contains(*dll) {
                result.push(dll.to_string());
            }
        }
    }

    result
}

/// Test helper: register a dummy DLL with no exports and no entry point.
/// Only available in test builds.
#[cfg(test)]
pub(crate) fn register_for_test(name: String) {
    if let Some(mut reg) = lock_registry(registry()) {
        reg.insert(
            name,
            DllEntry {
                _image: ManuallyDrop::new(unsafe { std::mem::zeroed() }),
                exports: HashMap::new(),
                entry_point: None,
            },
        );
    }
}

#[cfg(test)]
mod dep_tests {
    use super::*;

    #[test]
    fn empty_graph_returns_empty() {
        let order = dllmain_order();
        // Tests share global state, so we can't assert is_empty() —
        // just verify no panics and no duplicates.
        let mut seen = std::collections::HashSet::new();
        for dll in &order {
            assert!(seen.insert(dll.as_str()), "duplicate entry: {dll}");
        }
    }

    #[test]
    fn single_dll_no_imports() {
        let _ = registry().lock().map(|mut r| {
            r.insert("single_test_only.dll".to_string(), DllEntry {
                _image: ManuallyDrop::new(unsafe { std::mem::zeroed() }),
                exports: HashMap::new(),
                entry_point: None,
            });
        });
        let order = dllmain_order();
        // Tests share global state with parallel siblings, so we can only
        // assert that our DLL is present (exact count is unpredictable).
        assert!(order.contains(&"single_test_only.dll".to_string()));
    }

    #[test]
    fn linear_chain() {
        // chain_b.dll imports from chain_a.dll → a must come first.
        let _ = registry().lock().map(|mut r| {
            r.insert("chain_a.dll".to_string(), DllEntry {
                _image: ManuallyDrop::new(unsafe { std::mem::zeroed() }),
                exports: HashMap::new(),
                entry_point: None,
            });
            r.insert("chain_b.dll".to_string(), DllEntry {
                _image: ManuallyDrop::new(unsafe { std::mem::zeroed() }),
                exports: HashMap::new(),
                entry_point: None,
            });
        });
        register_imports("chain_b.dll", &["chain_a.dll".to_string()]);
        let order = dllmain_order();
        let a_pos = order.iter().position(|d| d == "chain_a.dll").unwrap();
        let b_pos = order.iter().position(|d| d == "chain_b.dll").unwrap();
        assert!(a_pos < b_pos, "chain_a.dll must be before chain_b.dll");
    }

    #[test]
    fn diamond_dependency() {
        // d depends on b and c; b depends on a; c depends on a.
        // Valid orders: a, b, c, d or a, c, b, d.
        // Note: tests share global state, so other DLLs may also be present.
        let _ = registry().lock().map(|mut r| {
            for name in &["diamond_a.dll", "diamond_b.dll", "diamond_c.dll", "diamond_d.dll"] {
                r.insert(name.to_string(), DllEntry {
                    _image: ManuallyDrop::new(unsafe { std::mem::zeroed() }),
                    exports: HashMap::new(),
                    entry_point: None,
                });
            }
        });
        register_imports("diamond_b.dll", &["diamond_a.dll".to_string()]);
        register_imports("diamond_c.dll", &["diamond_a.dll".to_string()]);
        register_imports("diamond_d.dll", &["diamond_b.dll".to_string(), "diamond_c.dll".to_string()]);

        let order = dllmain_order();
        let a_pos = order.iter().position(|d| d == "diamond_a.dll").unwrap();
        let b_pos = order.iter().position(|d| d == "diamond_b.dll").unwrap();
        let c_pos = order.iter().position(|d| d == "diamond_c.dll").unwrap();
        let d_pos = order.iter().position(|d| d == "diamond_d.dll").unwrap();
        assert!(a_pos < b_pos && a_pos < c_pos, "diamond_a must precede diamond_b and diamond_c");
        assert!(b_pos < d_pos, "diamond_b must precede diamond_d");
        assert!(c_pos < d_pos, "diamond_c must precede diamond_d");
    }

    #[test]
    fn unregistered_import_does_not_block() {
        // orphan_b depends on missing.dll (not registered) → orphan_b must appear.
        let _ = registry().lock().map(|mut r| {
            r.insert("orphan_b.dll".to_string(), DllEntry {
                _image: ManuallyDrop::new(unsafe { std::mem::zeroed() }),
                exports: HashMap::new(),
                entry_point: None,
            });
        });
        register_imports("orphan_b.dll", &["missing.dll".to_string()]);
        let order = dllmain_order();
        assert!(order.contains(&"orphan_b.dll".to_string()));
    }
}
