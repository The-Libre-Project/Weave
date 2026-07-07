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

/// All Rust DLL crate filenames that Weave registers as DllMain stubs.
/// Each entry is the canonical lowercase DLL name for a `weave-*` crate.
pub const ALL_RUST_DLL_NAMES: &[&str] = &[
    "ntdll.dll",
    "kernel32.dll",
    "advapi32.dll",
    "user32.dll",
    "gdi32.dll",
    "shell32.dll",
    "ole32.dll",
    "mmdevapi.dll",
    "xinput1_3.dll",
    "winmm.dll",
    "setupapi.dll",
    "ucrtbase.dll",
    "msvcp140.dll",
    "mfc140u.dll",
    "vulkan-1.dll",
    "ws2_32.dll",
    "comctl32.dll",
    "oleaut32.dll",
    "imm32.dll",
    "shlwapi.dll",
    "gdiplus.dll",
    "dwrite.dll",
    "ddraw.dll",
    "crypt32.dll",
    "wldap32.dll",
    "normaliz.dll",
    "secur32.dll",
    "bcrypt.dll",
    "bcryptprimitives.dll",
    "powrprof.dll",
];

/// Register `default_dll_main` for every known Rust DLL crate.
/// Call once during process startup, before `process_attach()`.
pub fn register_all_default_stubs() {
    for dll in ALL_RUST_DLL_NAMES {
        register_stub(dll, default_dll_main);
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
    pe_dispatch(DLL_PROCESS_ATTACH, &order, stubs.as_deref());

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
    pe_dispatch_rev(DLL_PROCESS_DETACH, &order, stubs.as_deref());

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
    pe_dispatch(DLL_THREAD_ATTACH, &order, stubs.as_deref());

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
    pe_dispatch(DLL_THREAD_DETACH, &order, stubs.as_deref());

    #[cfg(not(target_os = "linux"))]
    let _ = &order;
}

/// Call native PE DllMain entry points in forward order.
/// Skips DLLs that have a registered Rust stub (our crate handles them).
/// Takes the already-locked stub registry to avoid deadlock on the same mutex.
#[cfg(target_os = "linux")]
fn pe_dispatch(reason: u32, order: &[String], stubs: Option<&HashMap<String, DllMainFn>>) {
    for dll in order {
        // Skip DLLs handled by a Rust stub crate — their DllMain is our
        // default_dll_main (or a custom implementation).  Calling the real
        // PE DllMain would cause CRT init crashes for CRT DLLs like
        // MSVCP140.dll (RVA 0x300f null-deref) while providing no benefit
        // since the stub handles all exports.
        if let Some(s) = stubs {
            if s.contains_key(dll) {
                continue;
            }
        }
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
/// Skips DLLs that have a registered Rust stub.
/// Takes the already-locked stub registry to avoid deadlock.
#[cfg(target_os = "linux")]
fn pe_dispatch_rev(reason: u32, order: &[String], stubs: Option<&HashMap<String, DllMainFn>>) {
    for dll in order.iter().rev() {
        if let Some(s) = stubs {
            if s.contains_key(dll) {
                continue;
            }
        }
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
    use std::sync::atomic::AtomicU32;

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

        let _ = crate::dll_registry::register_for_test("test_dllmain_attach.dll".to_string());
        crate::dll_registry::register_imports("test_dllmain_attach.dll", &[]);

        register_stub("test_dllmain_attach.dll", test_dll_main);
        process_attach();

        assert!(
            TEST_FLAG.load(std::sync::atomic::Ordering::SeqCst),
            "DllMain(DLL_PROCESS_ATTACH) should have set TEST_FLAG"
        );
    }

    #[test]
    fn all_rust_dll_names_are_registered() {
        register_all_default_stubs();
        if let Some(reg) = lock_stubs() {
            for dll in ALL_RUST_DLL_NAMES {
                assert!(reg.contains_key(*dll), "DllMain not registered for {dll}");
            }
        } else {
            panic!("could not lock stub registry");
        }
    }

    #[test]
    fn noop_default_returns_true() {
        let ret = default_dll_main(0, DLL_PROCESS_ATTACH, 0);
        assert_eq!(ret, 1, "default_dll_main must return TRUE");
        let ret = default_dll_main(0, DLL_PROCESS_DETACH, 0);
        assert_eq!(ret, 1, "default_dll_main must return TRUE on detach too");
    }

    // ── Thread attach / detach dispatch ──────────────────────────────────

    static S_ATT: AtomicU32 = AtomicU32::new(0);
    static S_DET: AtomicU32 = AtomicU32::new(0);

    #[cfg(not(target_os = "linux"))]
    extern "C" fn th_single(_hinst: usize, reason: u32, _reserved: usize) -> i32 {
        match reason {
            DLL_THREAD_ATTACH => {
                S_ATT.fetch_add(1, Ordering::SeqCst);
            }
            DLL_THREAD_DETACH => {
                S_DET.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        1
    }

    #[cfg(target_os = "linux")]
    extern "win64" fn th_single(_hinst: usize, reason: u32, _reserved: usize) -> i32 {
        match reason {
            DLL_THREAD_ATTACH => {
                S_ATT.fetch_add(1, Ordering::SeqCst);
            }
            DLL_THREAD_DETACH => {
                S_DET.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        1
    }

    #[test]
    fn thread_attach_detach_single_dll() {
        let _ = crate::dll_registry::register_for_test("th_single.dll".to_string());
        crate::dll_registry::register_imports("th_single.dll", &[]);
        register_stub("th_single.dll", th_single);

        let ab = S_ATT.load(Ordering::SeqCst);
        let db = S_DET.load(Ordering::SeqCst);

        let h = std::thread::spawn(|| {
            thread_attach();
            std::thread::yield_now();
            thread_detach();
        });
        h.join().expect("thread panicked");

        assert!(
            S_ATT.load(Ordering::SeqCst) > ab,
            "DLL_THREAD_ATTACH must fire for a registered stub"
        );
        assert!(
            S_DET.load(Ordering::SeqCst) > db,
            "DLL_THREAD_DETACH must fire for a registered stub"
        );
    }

    static MA_ATT: AtomicU32 = AtomicU32::new(0);
    static MA_DET: AtomicU32 = AtomicU32::new(0);
    static MB_ATT: AtomicU32 = AtomicU32::new(0);
    static MB_DET: AtomicU32 = AtomicU32::new(0);

    #[cfg(not(target_os = "linux"))]
    extern "C" fn th_multi_a(_hinst: usize, reason: u32, _reserved: usize) -> i32 {
        match reason {
            DLL_THREAD_ATTACH => {
                MA_ATT.fetch_add(1, Ordering::SeqCst);
            }
            DLL_THREAD_DETACH => {
                MA_DET.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        1
    }

    #[cfg(target_os = "linux")]
    extern "win64" fn th_multi_a(_hinst: usize, reason: u32, _reserved: usize) -> i32 {
        match reason {
            DLL_THREAD_ATTACH => {
                MA_ATT.fetch_add(1, Ordering::SeqCst);
            }
            DLL_THREAD_DETACH => {
                MA_DET.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        1
    }

    #[cfg(not(target_os = "linux"))]
    extern "C" fn th_multi_b(_hinst: usize, reason: u32, _reserved: usize) -> i32 {
        match reason {
            DLL_THREAD_ATTACH => {
                MB_ATT.fetch_add(1, Ordering::SeqCst);
            }
            DLL_THREAD_DETACH => {
                MB_DET.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        1
    }

    #[cfg(target_os = "linux")]
    extern "win64" fn th_multi_b(_hinst: usize, reason: u32, _reserved: usize) -> i32 {
        match reason {
            DLL_THREAD_ATTACH => {
                MB_ATT.fetch_add(1, Ordering::SeqCst);
            }
            DLL_THREAD_DETACH => {
                MB_DET.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        1
    }

    #[test]
    fn thread_attach_detach_multi_dll() {
        let _ = crate::dll_registry::register_for_test("th_multi_a.dll".to_string());
        let _ = crate::dll_registry::register_for_test("th_multi_b.dll".to_string());
        crate::dll_registry::register_imports("th_multi_a.dll", &[]);
        crate::dll_registry::register_imports("th_multi_b.dll", &[]);
        register_stub("th_multi_a.dll", th_multi_a);
        register_stub("th_multi_b.dll", th_multi_b);

        let ab_a = MA_ATT.load(Ordering::SeqCst);
        let db_a = MA_DET.load(Ordering::SeqCst);
        let ab_b = MB_ATT.load(Ordering::SeqCst);
        let db_b = MB_DET.load(Ordering::SeqCst);

        let h = std::thread::spawn(|| {
            thread_attach();
            std::thread::yield_now();
            thread_detach();
        });
        h.join().expect("thread panicked");

        assert!(
            MA_ATT.load(Ordering::SeqCst) > ab_a,
            "DLL_THREAD_ATTACH must fire for DLL A"
        );
        assert!(
            MA_DET.load(Ordering::SeqCst) > db_a,
            "DLL_THREAD_DETACH must fire for DLL A"
        );
        assert!(
            MB_ATT.load(Ordering::SeqCst) > ab_b,
            "DLL_THREAD_ATTACH must fire for DLL B"
        );
        assert!(
            MB_DET.load(Ordering::SeqCst) > db_b,
            "DLL_THREAD_DETACH must fire for DLL B"
        );
    }

    #[test]
    fn thread_detach_without_attach_is_safe() {
        // Register a DLL but only call thread_detach with no preceding thread_attach.
        // This should not panic — Windows DllMain dispatch tolerates unbalanced calls.
        let _ = crate::dll_registry::register_for_test("th_detach_only.dll".to_string());
        crate::dll_registry::register_imports("th_detach_only.dll", &[]);
        register_stub("th_detach_only.dll", default_dll_main);

        let h = std::thread::spawn(|| {
            thread_detach();
        });
        h.join().expect("thread must not panic on detach-only");
    }

    #[test]
    fn thread_attach_empty_dispatch_noop() {
        // Call thread_attach and thread_detach with no DLLs in the registry.
        // Must not panic and must not deadlock.
        let h = std::thread::spawn(|| {
            thread_attach();
            std::thread::yield_now();
            thread_detach();
        });
        h.join().expect("empty dispatch must not panic");
    }

    static TT_ATT: AtomicU32 = AtomicU32::new(0);
    static TT_DET: AtomicU32 = AtomicU32::new(0);

    #[cfg(not(target_os = "linux"))]
    extern "C" fn th_two(_hinst: usize, reason: u32, _reserved: usize) -> i32 {
        match reason {
            DLL_THREAD_ATTACH => {
                TT_ATT.fetch_add(1, Ordering::SeqCst);
            }
            DLL_THREAD_DETACH => {
                TT_DET.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        1
    }

    #[cfg(target_os = "linux")]
    extern "win64" fn th_two(_hinst: usize, reason: u32, _reserved: usize) -> i32 {
        match reason {
            DLL_THREAD_ATTACH => {
                TT_ATT.fetch_add(1, Ordering::SeqCst);
            }
            DLL_THREAD_DETACH => {
                TT_DET.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        1
    }

    #[test]
    fn thread_attach_detach_two_threads() {
        let _ = crate::dll_registry::register_for_test("th_two.dll".to_string());
        crate::dll_registry::register_imports("th_two.dll", &[]);
        register_stub("th_two.dll", th_two);

        let ab = TT_ATT.load(Ordering::SeqCst);
        let db = TT_DET.load(Ordering::SeqCst);

        let h1 = std::thread::spawn(|| {
            thread_attach();
            thread_detach();
        });
        let h2 = std::thread::spawn(|| {
            thread_attach();
            thread_detach();
        });
        h1.join().expect("thread 1 panicked");
        h2.join().expect("thread 2 panicked");

        assert!(
            TT_ATT.load(Ordering::SeqCst) >= ab + 2,
            "two threads must both receive DLL_THREAD_ATTACH"
        );
        assert!(
            TT_DET.load(Ordering::SeqCst) >= db + 2,
            "two threads must both receive DLL_THREAD_DETACH"
        );
    }
}
