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

/// Patch a known-crashing instruction in a loaded CRT DLL so that its
/// native DllMain can complete without SIGSEGV.
///
/// MSVCP140.dll at RVA 0x300f has a SIMD memcpy loop that reads the source
/// pointer from RAX.  During DllMain, RAX is null → the first `movups xmm0,
/// [rax]` faults.  The previous fix wrote RET (0xC3), but that skipped the
/// entire copy, leaving the destination uninitialized → the caller used the
/// stale stack data as a vtable → jumped to stack (SIGSEGV with this=4).
///
/// New fix: redirect RAX to a safe zero-filled page before the copy, so the
/// destination is zero-initialised and the caller gets valid (empty) data.
/// Uses an mmap'd executable trampoline to set RAX, perform the first two
/// movups instructions, then jmp back into the original loop at RVA 0x3015.
///
/// The page is made writable via mprotect.
#[cfg(target_os = "linux")]
fn patch_crt_rva(dll: &str, base: usize) {
    if dll.eq_ignore_ascii_case("msvcp140.dll") {
        let crash_rva: usize = 0x300f;
        let crash_addr = base + crash_rva;
        let page_size = 4096usize;
        let page_start = crash_addr & !(page_size - 1);
        unsafe {
            libc::mprotect(
                page_start as *mut libc::c_void,
                page_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            );

            // Allocate a zero-filled page for the redirected source read.
            // MAP_ANONYMOUS pages are zero-initialised by the kernel.
            let zero_buf = libc::mmap(
                std::ptr::null_mut(),
                256,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if zero_buf == libc::MAP_FAILED {
                eprintln!("weave: msvcp140 zero_buf mmap failed — falling back to RET");
                std::ptr::write(crash_addr as *mut u8, 0xC3u8);
                return;
            }

            // Allocate an executable page for the trampoline.
            let trampoline = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if trampoline == libc::MAP_FAILED {
                eprintln!("weave: msvcp140 trampoline mmap failed — falling back to RET");
                libc::munmap(zero_buf, 256);
                std::ptr::write(crash_addr as *mut u8, 0xC3u8);
                return;
            }

            let tramp_addr = trampoline as usize;
            let zero_addr = zero_buf as usize;

            // Build trampoline at tramp_addr:
            //   [ 0] 48 b8 <8-byte addr LE>   mov rax, zero_buf       ; 10 bytes
            //   [10] 0f 10 00                 movups xmm0, [rax]      ;  3 bytes
            //   [13] 0f 11 07                 movups [rdi], xmm0      ;  3 bytes
            //   [16] e9 <4-byte rel32>        jmp base+0x3015         ;  5 bytes
            // Total: 21 bytes

            // Return target after our two restored movups: RVA 0x3015
            let ret_target: i64 = (base + 0x3015) as i64;
            // The jmp at tramp+16 (5 bytes) has next-instr at tramp+21
            let jmp_back_off = ret_target.wrapping_sub((tramp_addr + 21) as i64) as i32;

            let tramp_src: &[u8] = &[
                0x48,
                0xb8, // mov rax, imm64
                zero_addr as u8,
                (zero_addr >> 8) as u8,
                (zero_addr >> 16) as u8,
                (zero_addr >> 24) as u8,
                (zero_addr >> 32) as u8,
                (zero_addr >> 40) as u8,
                (zero_addr >> 48) as u8,
                (zero_addr >> 56) as u8,
                0x0f,
                0x10,
                0x00, // movups xmm0, [rax]
                0x0f,
                0x11,
                0x07, // movups [rdi], xmm0
                0xe9, // jmp rel32
                jmp_back_off as u8,
                (jmp_back_off >> 8) as u8,
                (jmp_back_off >> 16) as u8,
                (jmp_back_off >> 24) as u8,
            ];
            std::ptr::copy_nonoverlapping(
                tramp_src.as_ptr(),
                tramp_addr as *mut u8,
                tramp_src.len(),
            );

            // Patch RVA 0x300f: jmp rel32 (5 bytes) to trampoline + nop (1 byte pad).
            // The jmp rel32 offset = tramp_addr - (crash_addr + 5).
            let jmp_off = (tramp_addr as i64).wrapping_sub((crash_addr + 5) as i64) as i32;
            let patch_src: &[u8] = &[
                0xe9,
                jmp_off as u8,
                (jmp_off >> 8) as u8,
                (jmp_off >> 16) as u8,
                (jmp_off >> 24) as u8,
                0x90, // nop — fills byte that was part of original movups [rdi],xmm0
            ];
            std::ptr::copy_nonoverlapping(
                patch_src.as_ptr(),
                crash_addr as *mut u8,
                patch_src.len(),
            );

            eprintln!(
                "weave: patched msvcp140.dll RVA 0x{crash_rva:x} (zero-buf copy) at base={base:#x}"
            );
            eprintln!("weave: msvcp140 zero_buf={zero_addr:#x} trampoline={tramp_addr:#x}");
        }
    } else if dll.eq_ignore_ascii_case("lib-utility.dll") {
        // RVA 0x763c: `mov [r14], rcx` with null-this (rcx=1).  The msvcp140 locale
        // stubs return 0, cascading into null-this in lib-utility.dll's locale code.
        // Patch: `xor eax, eax; ret` — function returns 0 immediately.
        let crash_rva: usize = 0x763c;
        let crash_addr = base + crash_rva;
        let page_size = 4096usize;
        let page_start = crash_addr & !(page_size - 1);
        unsafe {
            libc::mprotect(
                page_start as *mut libc::c_void,
                page_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            );
            let patch: &[u8] = &[0x31, 0xc0, 0xc3];
            std::ptr::copy_nonoverlapping(patch.as_ptr(), crash_addr as *mut u8, patch.len());
            eprintln!("weave: patched lib-utility.dll RVA 0x{crash_rva:x} at base={base:#x}");
        }
    } else if dll.eq_ignore_ascii_case("msvcp140.dll") {
        // RVA 0x4f74: NULL-pointer string strlen in internal locale helper (rbx=0
        // → `cmp byte ptr [rbx], 0` faults).  The native DllMain calls this during
        // CRT locale init after our `_Init` stub returns the fake _Locimp.
        // Patch: `xor eax, eax; ret` — returns NULL for the string lookup,
        // which the caller handles as a not-found result.
        let crash_rva: usize = 0x4f74;
        let crash_addr = base + crash_rva;
        let page_size = 4096usize;
        let page_start = crash_addr & !(page_size - 1);
        unsafe {
            libc::mprotect(
                page_start as *mut libc::c_void,
                page_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            );
            let patch: &[u8] = &[0x31, 0xc0, 0xc3];
            std::ptr::copy_nonoverlapping(patch.as_ptr(), crash_addr as *mut u8, patch.len());
            eprintln!("weave: patched msvcp140.dll RVA 0x{crash_rva:x} at base={base:#x}");
        }
    }
}

/// Call native PE DllMain entry points in forward order.
/// CRT DLLs are loaded as PEs (their exports are used by side-by-side DLLs)
/// but their DllMain may crash at known sites.  We patch those sites with
/// RET before calling DllMain, then let the DllMain complete so CRT locale
/// and TLS data is initialized.
#[cfg(target_os = "linux")]
fn pe_dispatch(reason: u32, order: &[String], _stubs: Option<&HashMap<String, DllMainFn>>) {
    // wxWidgets and Audacity lib DLLs crash in DllMain during locale/CRT init
    // (C++ locale facet stub returns 0 → null-this vtable dispatch). Their
    // DllMain only runs CRT static initializers, not window/GUI setup.
    // Safe to skip — fix the underlying msvcp140 stubs in Phase C.
    let skip_dlls: &[&str] = &[
        // MSVCP140 — DllMain locale init crashes with our _Init stub.
        "msvcp140.dll",
        "msvcp140_1.dll",
        "msvcp140_2.dll",
        "msvcp140_atomic_wait.dll",
        "msvcp140_codecvt_ids.dll",
        // wxWidgets DLLs — locale/CRT init crashes in DllMain
        "wxbase313u_net_vc_x64_custom.dll",
        "wxbase313u_vc_x64_custom.dll",
        "wxbase313u_xml_vc_x64_custom.dll",
        "wxmsw313u_adv_vc_x64_custom.dll",
        "wxmsw313u_aui_vc_x64_custom.dll",
        "wxmsw313u_core_vc_x64_custom.dll",
        "wxmsw313u_html_vc_x64_custom.dll",
        "wxmsw313u_qa_vc_x64_custom.dll",
        "wxmsw313u_xrc_vc_x64_custom.dll",
        // Audacity lib DLLs — DllMain crashes in locale init (patched for lib-utility).
        "lib-audacity-application-logic.dll",
        "lib-audio-devices.dll",
        "lib-audio-graph.dll",
        "lib-audio-io.dll",
        "lib-basic-ui.dll",
        "lib-builtin-effects.dll",
        "lib-channel.dll",
        "lib-cloud-audiocom.dll",
        "lib-command-parameters.dll",
        "lib-components.dll",
        "lib-concurrency.dll",
        "lib-crashpad-configurer.dll",
        "lib-crypto.dll",
        "lib-dynamic-range-processor.dll",
        "lib-effects.dll",
        "lib-exceptions.dll",
        "lib-export-ui.dll",
        "lib-ffmpeg-support.dll",
        "lib-fft.dll",
        "lib-file-formats.dll",
        "lib-files.dll",
        "lib-graphics.dll",
        "lib-import-export.dll",
        "lib-ipc.dll",
        "lib-label-track.dll",
        "lib-lv2.dll",
        "lib-math.dll",
        "lib-menus.dll",
        "lib-mixer.dll",
        "lib-module-manager.dll",
        "lib-musehub.dll",
        "lib-music-information-retrieval.dll",
        "lib-network-manager.dll",
        "lib-note-track.dll",
        "lib-numeric-formats.dll",
        "lib-nyquist-effects.dll",
        "lib-playable-track.dll",
        "lib-preferences.dll",
        "lib-project.dll",
        "lib-project-file-io.dll",
        "lib-project-history.dll",
        "lib-project-rate.dll",
        "lib-realtime-effects.dll",
        "lib-registries.dll",
        "lib-sample-track.dll",
        "lib-screen-geometry.dll",
        "lib-sentry-reporting.dll",
        "lib-shuttlegui.dll",
        "lib-snapping.dll",
        "lib-sqlite-helpers.dll",
        "lib-stretching-sequence.dll",
        "lib-string-utils.dll",
        "lib-strings.dll",
        "lib-tags.dll",
        "lib-theme.dll",
        "lib-theme-resources.dll",
        "lib-time-and-pitch.dll",
        "lib-time-frequency-selection.dll",
        "lib-time-track.dll",
        "lib-track.dll",
        "lib-track-selection.dll",
        "lib-transactions.dll",
        "lib-url-schemes.dll",
        "lib-uuid.dll",
        "lib-viewport.dll",
        "lib-vst.dll",
        "lib-vst3.dll",
        "lib-wave-track.dll",
        "lib-wave-track-fft.dll",
        "lib-wave-track-paint.dll",
        "lib-wave-track-settings.dll",
        "lib-wx-init.dll",
        "lib-wx-wrappers.dll",
        "lib-xml.dll",
    ];
    for dll in order {
        if skip_dlls.contains(&dll.as_str()) {
            eprintln!("weave: pe_dispatch DLL_PROCESS_ATTACH -> {dll} (skipped — DllMain not required for Phase B)");
            continue;
        }
        // Patch known CRT crash sites before calling DllMain.
        let base = crate::dll_registry::get_base(dll);
        if let Some(b) = base {
            patch_crt_rva(dll, b);
        }
        eprintln!("weave: pe_dispatch DLL_PROCESS_ATTACH -> {dll}");
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
/// Same policy as pe_dispatch: no blanket skip for stubbed DLLs.
#[cfg(target_os = "linux")]
fn pe_dispatch_rev(reason: u32, order: &[String], _stubs: Option<&HashMap<String, DllMainFn>>) {
    let skip_dlls: &[&str] = &[
        "wxbase313u_vc_x64_custom.dll",
        "wxbase313u_xml_vc_x64_custom.dll",
        "wxmsw313u_aui_vc_x64_custom.dll",
        "wxmsw313u_core_vc_x64_custom.dll",
        "wxmsw313u_html_vc_x64_custom.dll",
        "wxmsw313u_qa_vc_x64_custom.dll",
    ];
    for dll in order.iter().rev() {
        if skip_dlls.contains(&dll.as_str()) {
            continue;
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
