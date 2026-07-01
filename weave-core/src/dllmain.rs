//! DllMain dispatch for Weave.
//!
//! Two tiers of DllMain callbacks:
//!   1. Rust stub crates (weave-kernel32, etc.) — registered explicitly via
//!      `register_stub`, receive hinst=0 (no real PE image).
//!   2. PE DLLs loaded from disk (DXVK, SDL2, etc.) — dispatched from their
//!      native AddressOfEntryPoint via `dll_registry`, receive the actual
//!      loaded base address as hinst.
//!
//! All dispatch follows the topological order from `dll_registry::dllmain_order`.
//! Rust stub crates are dispatched first since they are not in the dependency
//! graph — they provide the runtime substrate that PE DLLs depend on.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;
const DLL_THREAD_ATTACH: u32 = 2;
const DLL_THREAD_DETACH: u32 = 3;

// The extern "win64" ABI is only valid on x86-64 Linux (our target).
// On other platforms (macOS dev builds) we define a compatible but
// non-functional API so the crate compiles without cfg gates at every
// call site — the PE loader is never exercised on macOS anyway.
#[cfg(target_os = "linux")]
type DllMainAbi = extern "win64" fn(usize, u32, usize) -> i32;

#[cfg(not(target_os = "linux"))]
type DllMainAbi = extern "C" fn(usize, u32, usize) -> i32;

/// A Win32 DllMain — BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID).
pub type DllMainFn = DllMainAbi;

/// Registry for Rust stub crate DllMain callbacks.
static STUB_REGISTRY: OnceLock<Mutex<HashMap<String, DllMainFn>>> = OnceLock::new();

fn stub_registry() -> &'static Mutex<HashMap<String, DllMainFn>> {
    STUB_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock_stubs() -> Option<MutexGuard<'static, HashMap<String, DllMainFn>>> {
    stub_registry()
        .lock()
        .map_err(|e| eprintln!("weave: dllmain stub-registry mutex poisoned: {e}"))
        .ok()
}

/// Register a DllMain callback for a Rust stub DLL crate.
///
/// `name` is the lowercase DLL filename (e.g. `"kernel32.dll"`).
/// The callback will be called at process attach/detach and thread attach/detach.
pub fn register_stub(name: &str, func: DllMainFn) {
    if let Some(mut reg) = lock_stubs() {
        reg.insert(name.to_lowercase(), func);
    }
}

/// Default no-op DllMain that returns TRUE. Use for crates that don't need
/// any initialisation.
#[cfg(target_os = "linux")]
pub extern "win64" fn default_dll_main(_hinst: usize, _reason: u32, _reserved: usize) -> i32 {
    1
}

#[cfg(not(target_os = "linux"))]
pub extern "C" fn default_dll_main(_hinst: usize, _reason: u32, _reserved: usize) -> i32 {
    1
}

/// Dispatch DLL_PROCESS_ATTACH to every registered DLL (stubs then PE) in
/// dependency order.
///
/// Logs FALSE returns but continues (Windows tolerates failed DllMains during
/// process attach).
///
/// Also registers an atexit handler to call `process_detach` on normal exit.
pub fn process_attach() {
    let order = crate::dll_registry::dllmain_order();
    let stubs = lock_stubs();

    // Rust stub crates first (they are the runtime layer that PE DLLs use).
    if let Some(ref s) = stubs {
        for dll in &order {
            if let Some(func) = s.get(dll) {
                let ok = func(0, DLL_PROCESS_ATTACH, 0);
                if ok == 0 {
                    eprintln!("weave: {dll} DllMain(DLL_PROCESS_ATTACH) returned FALSE");
                }
            }
        }
    }

    // PE DLLs loaded from disk — call their native entry points.
    #[cfg(target_os = "linux")]
    pe_dispatch(DLL_PROCESS_ATTACH, &order);

    #[cfg(not(target_os = "linux"))]
    let _ = &order;

    // Register an atexit handler for process detach.
    // Use a thread-local flag to register only once (the main thread).
    std::thread_local! {
        static DETACH_REGISTERED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    DETACH_REGISTERED.with(|r| {
        if !r.replace(true) {
            extern "C" fn detach_handler() {
                process_detach();
            }
            unsafe { libc::atexit(detach_handler as extern "C" fn()) };
        }
    });
}

/// Dispatch DLL_PROCESS_DETACH to every registered DLL in reverse dependency
/// order (PE DLLs first, then Rust stubs).
///
/// Safe to call multiple times — subsequent calls are no-ops.
pub fn process_detach() {
    static DETACHED: AtomicBool = AtomicBool::new(false);
    if DETACHED.swap(true, Ordering::SeqCst) {
        return;
    }
    let order = crate::dll_registry::dllmain_order();
    let stubs = lock_stubs();

    // PE DLLs first (reverse order — dependencies last).
    #[cfg(target_os = "linux")]
    pe_dispatch_rev(DLL_PROCESS_DETACH, &order);

    #[cfg(not(target_os = "linux"))]
    let _ = &order;

    // Rust stubs last (reverse order).
    if let Some(ref s) = stubs {
        for dll in order.iter().rev() {
            if let Some(func) = s.get(dll) {
                func(0, DLL_PROCESS_DETACH, 0);
            }
        }
    }
}

/// Dispatch DLL_THREAD_ATTACH to all registered DLLs in forward order.
pub fn thread_attach() {
    let order = crate::dll_registry::dllmain_order();
    let stubs = lock_stubs();

    if let Some(ref s) = stubs {
        for dll in &order {
            if let Some(func) = s.get(dll) {
                func(0, DLL_THREAD_ATTACH, 0);
            }
        }
    }

    #[cfg(target_os = "linux")]
    pe_dispatch(DLL_THREAD_ATTACH, &order);

    #[cfg(not(target_os = "linux"))]
    let _ = &order;
}

/// Dispatch DLL_THREAD_DETACH to all registered DLLs in forward order.
pub fn thread_detach() {
    let order = crate::dll_registry::dllmain_order();
    let stubs = lock_stubs();

    if let Some(ref s) = stubs {
        for dll in &order {
            if let Some(func) = s.get(dll) {
                func(0, DLL_THREAD_DETACH, 0);
            }
        }
    }

    #[cfg(target_os = "linux")]
    pe_dispatch(DLL_THREAD_DETACH, &order);

    #[cfg(not(target_os = "linux"))]
    let _ = &order;
}

/// Call native PE DllMain entry points in forward order.
#[cfg(target_os = "linux")]
fn pe_dispatch(reason: u32, order: &[String]) {
    for dll in order {
        let entry = crate::dll_registry::get_entry_point(dll);
        let base = crate::dll_registry::get_base(dll);
        if let (Some(ep), Some(b)) = (entry, base) {
            // Wine ref: dlls/ntdll/loader.c — LdrpCallInitRoutine calls the
            // DLL entry point with hinst = module base, reason, and lpReserved
            // = 1 for static loads or 0 for dynamic loads / thread notifications.
            let reserved = if reason == DLL_PROCESS_ATTACH { 1 } else { 0 };
            type DllMain = unsafe extern "win64" fn(usize, u32, usize) -> i32;
            let func: DllMain = unsafe { std::mem::transmute(ep) };
            let ok = unsafe { func(b, reason, reserved) };
            if ok == 0 {
                eprintln!("weave: {dll} DllMain(reason={reason}) returned FALSE");
            }
        }
    }
}

/// Call native PE DllMain entry points in reverse order (for process detach).
#[cfg(target_os = "linux")]
fn pe_dispatch_rev(reason: u32, order: &[String]) {
    for dll in order.iter().rev() {
        let entry = crate::dll_registry::get_entry_point(dll);
        let base = crate::dll_registry::get_base(dll);
        if let (Some(ep), Some(b)) = (entry, base) {
            type DllMain = unsafe extern "win64" fn(usize, u32, usize) -> i32;
            let func: DllMain = unsafe { std::mem::transmute(ep) };
            let _ = unsafe { func(b, reason, 0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_FLAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    #[cfg(target_os = "linux")]
    extern "win64" fn test_dll_main(_hinst: usize, reason: u32, _reserved: usize) -> i32 {
        if reason == DLL_PROCESS_ATTACH {
            TEST_FLAG.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        1
    }

    #[cfg(not(target_os = "linux"))]
    extern "C" fn test_dll_main(_hinst: usize, reason: u32, _reserved: usize) -> i32 {
        if reason == DLL_PROCESS_ATTACH {
            TEST_FLAG.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        1
    }

    #[test]
    fn stub_dllmain_process_attach_sets_flag() {
        TEST_FLAG.store(false, std::sync::atomic::Ordering::SeqCst);

        let _ = crate::dll_registry::register_for_test(
            "test_dllmain_attach.dll".to_string(),
        );
        crate::dll_registry::register_imports("test_dllmain_attach.dll", &[]);

        register_stub("test_dllmain_attach.dll", test_dll_main);
        process_attach();

        assert!(
            TEST_FLAG.load(std::sync::atomic::Ordering::SeqCst),
            "DllMain(DLL_PROCESS_ATTACH) should have set TEST_FLAG"
        );
    }

    #[test]
    fn noop_default_returns_true() {
        let ret = default_dll_main(0, DLL_PROCESS_ATTACH, 0);
        assert_eq!(ret, 1, "default_dll_main must return TRUE");
        let ret = default_dll_main(0, DLL_PROCESS_DETACH, 0);
        assert_eq!(ret, 1, "default_dll_main must return TRUE on detach too");
    }
}
