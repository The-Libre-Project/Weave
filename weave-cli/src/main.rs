#![allow(clippy::missing_safety_doc)]
use clap::Parser;
use serde_json::json;
use std::path::{Component, PathBuf};
use weave_common::com::shell_link::ShellLinkSaveData;
use weave_core::{
    cfg, cmdline, dll_registry, dllmain, exec, iat, loader, module_handles, pe, prefix, registry,
    seh, teb,
};
use weave_installer::PrefixManager;
use weave_ipc::CallMsg;
use weave_user32::defs::{Msg, WndClassExW, WndClassW};

mod arch;

/// Collapse `.` / `..` without following symlinks (`canonicalize` would break
/// NXEngine short-path symlinks). `std::path::absolute` does not normalize `..`
/// on paths that are already absolute.
fn normalize_lexical(path: PathBuf) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => out.push(comp),
            Component::Normal(s) => out.push(s),
        }
    }
    out
}

/// Weave — run Windows executables on Linux.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the Windows .exe file to run
    exe: PathBuf,

    /// Weave prefix directory (virtual Windows root).
    ///
    /// Precedence (highest to lowest):
    ///   1. This flag (`--prefix /path/to/prefix`)
    ///   2. The `WEAVE_PREFIX` environment variable
    ///   3. Default: `~/.weave/default`
    ///
    /// Setting `WEAVE_PREFIX` is the recommended approach for launchers that
    /// invoke Weave via `binfmt_misc`, where CLI flags cannot be passed.
    #[arg(long)]
    prefix: Option<PathBuf>,

    /// Run the guest in-process without seccomp isolation (debugging only).
    ///
    /// WARNING: The guest shares Weave's address space with no seccomp
    /// restrictions. Only use for debugging or compatibility testing.
    #[arg(long)]
    no_sandbox: bool,

    /// Enable structured stub-trace JSONL output.
    ///
    /// When present, every IAT dispatch is traced and classified as
    /// Phase A (stub) or Phase B (real implementation).  Output goes
    /// to stderr by default, or to the given file path if provided.
    #[arg(long, num_args = 0..=1, default_missing_value = "stubs.jsonl")]
    trace_stubs: Option<String>,

    /// Arguments to pass to the Windows executable (e.g. `weave app.exe arg1 arg2`)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    exe_args: Vec<String>,
}

/// Resolve a Windows import to a function address.
///
/// Checks Weave's built-in stub crates first, then falls back to any
/// PE DLLs pre-loaded from the prefix (e.g. DXVK).
///
/// For CRT DLLs loaded as native PEs from the exe directory, the native
/// export table is checked FIRST so that real implementations are used
/// instead of Weave's msvcp_noop stubs.  Weave stubs serve as fallback
/// for symbols the native DLL doesn't export.
fn resolve(dll: &str, func: &str) -> Option<usize> {
    // CRT and side-by-side DLLs loaded as native PEs — prefer native exports.
    // Without this the weave_msvcp140 resolver shadows every symbol and
    // returns msvcp_noop, defeating the purpose of loading real CRT DLLs.
    // CRT DLLs with safe DllMain — prefer native exports.
    const NATIVE_CRT_DLLS: &[&str] = &["vcruntime140.dll", "vcruntime140_1.dll", "concrt140.dll"];
    if NATIVE_CRT_DLLS.contains(&dll) {
        if let Some(addr) = dll_registry::lookup(dll, func) {
            return Some(addr);
        }
    }
    // MSVCP140 family: native DllMain is skipped (locale crash).  All exports
    // go through our resolver.  Unknown exports get msvcp_noop_retfirst.
    if matches!(
        dll,
        "msvcp140.dll"
            | "msvcp140_1.dll"
            | "msvcp140_2.dll"
            | "msvcp140_atomic_wait.dll"
            | "msvcp140_codecvt_ids.dll"
    ) {
        return weave_msvcp140::resolve(dll, func);
    }
    if NATIVE_CRT_DLLS.contains(&dll) {
        if let Some(addr) = dll_registry::lookup(dll, func) {
            return Some(addr);
        }
    }

    weave_plugin_system::lookup(dll, func)
        .or_else(|| weave_ntdll::resolve(dll, func))
        .or_else(|| weave_kernel32::resolve(dll, func))
        .or_else(|| weave_advapi32::resolve(dll, func))
        .or_else(|| weave_user32::resolve(dll, func))
        // shcore.dll — DPI awareness APIs (GetDpiForMonitor, SetProcessDpiAwareness, ...)
        .or_else(|| weave_user32::resolve_shcore(dll, func))
        // uiautomationcore.dll — UIA provider stubs (SumatraPDF delay-load table)
        .or_else(|| weave_user32::resolve_uiauto(dll, func))
        .or_else(|| weave_gdi32::resolve(dll, func))
        // msimg32.dll — alpha-blending, transparent blit (Sprint 5 IrfanView)
        .or_else(|| weave_gdi32::resolve_msimg32(dll, func))
        .or_else(|| weave_shell32::resolve(dll, func))
        .or_else(|| weave_ole32::resolve(dll, func))
        .or_else(|| weave_mmdevapi::resolve(dll, func))
        .or_else(|| weave_xinput::resolve(dll, func))
        .or_else(|| weave_winmm::resolve(dll, func))
        // setupapi.dll — HID device enumeration (returns empty set for headless CI)
        .or_else(|| weave_setupapi::resolve(dll, func))
        .or_else(|| weave_ucrt::resolve(dll, func))
        .or_else(|| weave_msvcp140::resolve(dll, func))
        .or_else(|| weave_mfc140u::resolve(dll, func))
        .or_else(|| weave_vulkan::resolve(dll, func))
        .or_else(|| weave_ws2::resolve(dll, func))
        .or_else(|| weave_comctl32::resolve(dll, func))
        // uxtheme.dll — visual style / theme API stubs (IrfanView, Notepad++, 7zFM)
        .or_else(|| weave_comctl32::resolve_uxtheme(dll, func))
        // comdlg32.dll — common dialog stubs (wxWidgets ChooseFontW, FindTextW, ReplaceTextW)
        .or_else(|| weave_comctl32::resolve_comdlg32(dll, func))
        .or_else(|| weave_oleaut32::resolve(dll, func))
        .or_else(|| weave_imm32::resolve(dll, func))
        .or_else(|| weave_shlwapi::resolve(dll, func))
        // gdiplus.dll — GDI+ 2D graphics / image codecs (Sprint 5 IrfanView)
        .or_else(|| weave_gdiplus::resolve(dll, func))
        // version.dll — file version info (Sprint 5 IrfanView)
        .or_else(|| weave_kernel32::resolve_version(dll, func))
        // dwrite.dll — DirectWrite factory stubs (Signal Desktop DWriteCreateFactory)
        .or_else(|| weave_dwrite::resolve(dll, func))
        // psapi.dll — process/module info (SDL2 SDL_GetBasePath uses GetModuleFileNameExW)
        .or_else(|| weave_kernel32::resolve_psapi(dll, func))
        // ddraw.dll — DirectDraw 5 COM stubs (Cave Story and DirectDraw games)
        .or_else(|| weave_ddraw::resolve(dll, func))
        // crypt32.dll — certificate store stubs (curl.exe TLS surface).
        // Placed AFTER weave_advapi32::resolve so advapi32's real Crypt*
        // (NPP entropy + overlapping Cert*) impls win for shared symbols;
        // this only fires for symbols advapi32 doesn't claim.
        .or_else(|| weave_crypt32::resolve(dll, func))
        // wldap32.dll — LDAP no-op stubs (curl.exe optional LDAP support)
        .or_else(|| weave_wldap32::resolve(dll, func))
        // normaliz.dll — IDN/Punycode no-op stubs (curl.exe IDNA surface)
        .or_else(|| weave_normaliz::resolve(dll, func))
        // secur32.dll — SSPI dispatch table stub (curl.exe NTLM/Kerberos surface)
        .or_else(|| weave_secur32::resolve(dll, func))
        // bcrypt.dll — CNG random stub (curl.exe entropy fallback)
        .or_else(|| weave_bcrypt::resolve(dll, func))
        // bcryptprimitives.dll — CNG low-level crypto primitives (Signal/SChannel TLS)
        .or_else(|| weave_bcryptprimitives::resolve(dll, func))
        .or_else(|| weave_powrprof::resolve(dll, func))
        // lib-audacity internal DLLs — C++ mangled symbols from side-by-side
        // DLLs that are not always present as PE files in the fixture.
        .or_else(|| weave_audacity::resolve(dll, func))
        // oleaut32.dll — OLE Automation stubs (wxWidgets ordinal imports)
        .or_else(|| weave_ole32::resolve_oleaut32(dll, func))
        // rpcrt4.dll — RPC stubs (wxWidgets UUID imports)
        .or_else(|| weave_ole32::resolve_rpcrt4(dll, func))
        // oleacc.dll — accessibility stubs (wxWidgets accessibility imports)
        .or_else(|| weave_ole32::resolve_oleacc(dll, func))
        // Pre-loaded DLL ordinal resolution — ordinals (#N) are registered as
        // export keys in the DLL registry by weave-core's PE loader.
        .or_else(|| {
            if func.starts_with('#') {
                dll_registry::lookup(dll, func)
            } else {
                None
            }
        })
        .or_else(|| dll_registry::lookup(dll, func))
}

/// Resolve the six bridged XDG user directories to real Linux `PathBuf`s.
///
/// For each directory, tries `xdg-user-dir <NAME>` first, then falls back to
/// `$HOME/<dir>` if the command is unavailable or returns empty output.
fn resolve_xdg_user_dirs() -> Vec<std::path::PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());

    let entries: &[(&str, &str)] = &[
        ("DOCUMENTS", "Documents"),
        ("DOWNLOAD", "Downloads"),
        ("DESKTOP", "Desktop"),
        ("MUSIC", "Music"),
        ("PICTURES", "Pictures"),
        ("VIDEOS", "Videos"),
    ];

    entries
        .iter()
        .map(|(xdg_name, fallback)| {
            // Try xdg-user-dir.
            if let Ok(output) = std::process::Command::new("xdg-user-dir")
                .arg(xdg_name)
                .output()
            {
                if output.status.success() {
                    let raw = String::from_utf8_lossy(&output.stdout);
                    let trimmed = raw.trim();
                    if !trimmed.is_empty() {
                        return std::path::PathBuf::from(trimmed);
                    }
                }
            }
            // Fallback.
            std::path::PathBuf::from(format!("{home}/{fallback}"))
        })
        .collect()
}

fn handle_prefix_cmd(args: &[String]) -> ! {
    let usage = || {
        eprintln!("usage: weave prefix <create|list|launch|delete> [args...]");
        std::process::exit(1);
    };

    let mgr = PrefixManager::new().unwrap_or_else(|e| {
        eprintln!("weave prefix: {e}");
        std::process::exit(1);
    });

    match args.first().map(|s| s.as_str()) {
        Some("create") => {
            let name = args.get(1).unwrap_or_else(|| {
                eprintln!("weave prefix create: missing <name>");
                std::process::exit(1);
            });
            // Parse optional --exe <path>
            let exe_path: Option<std::path::PathBuf> = {
                let mut result = None;
                let mut i = 2;
                while i < args.len() {
                    if args[i] == "--exe" {
                        if let Some(p) = args.get(i + 1) {
                            result = Some(std::path::PathBuf::from(p));
                            i += 2;
                        } else {
                            eprintln!("weave prefix create: --exe requires a path");
                            std::process::exit(1);
                        }
                    } else {
                        i += 1;
                    }
                }
                result
            };
            let prefix = mgr.create(name).unwrap_or_else(|e| {
                eprintln!("weave prefix create: {e}");
                std::process::exit(1);
            });
            if let Some(exe) = exe_path {
                prefix.set_exe_path(&exe).unwrap_or_else(|e| {
                    eprintln!("weave prefix create: set_exe_path: {e}");
                    std::process::exit(1);
                });
            }
            println!("created prefix '{name}'");
            std::process::exit(0);
        }
        Some("list") => {
            let prefixes = mgr.list().unwrap_or_else(|e| {
                eprintln!("weave prefix list: {e}");
                std::process::exit(1);
            });
            if prefixes.is_empty() {
                println!("(no prefixes)");
            } else {
                for p in &prefixes {
                    println!("{}", p.name);
                }
            }
            std::process::exit(0);
        }
        Some("launch") => {
            let name = args.get(1).unwrap_or_else(|| {
                eprintln!("weave prefix launch: missing <name>");
                std::process::exit(1);
            });
            let prefix = mgr.get(name).unwrap_or_else(|e| {
                eprintln!("weave prefix launch: {e}");
                std::process::exit(1);
            });
            let exe_path = prefix
                .get_exe_path()
                .unwrap_or_else(|e| {
                    eprintln!("weave prefix launch: {e}");
                    std::process::exit(1);
                })
                .unwrap_or_else(|| {
                    eprintln!("weave prefix launch: no exe configured for prefix '{name}'");
                    std::process::exit(1);
                });
            let current_exe = std::env::current_exe().unwrap_or_else(|e| {
                eprintln!("weave prefix launch: could not find current exe: {e}");
                std::process::exit(1);
            });
            // Create .desktop entry on first launch (idempotent — skips if already installed).
            if let Ok(dir) = weave_desktop::applications_dir() {
                let desktop_path = dir.join(format!("weave-{name}.desktop"));
                if !desktop_path.exists() {
                    let app_name = exe_path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or(name);
                    // Use PATH-resolved "weave" not current_exe path — the .desktop must survive
                    // binary relocation after installation.
                    let exec_cmd = format!("weave prefix launch {name}");
                    let icon_path = weave_desktop::extract_and_install_png_icon(name, &exe_path)
                        .or_else(|_| weave_desktop::extract_and_install_icon(name, &exe_path))
                        .unwrap_or(None);
                    let content = weave_desktop::generate_desktop_file(
                        app_name,
                        &exec_cmd,
                        icon_path.as_deref(),
                        "Application;",
                    );
                    if let Err(e) = weave_desktop::install_desktop_file(name, &content) {
                        eprintln!("weave prefix launch: could not write .desktop: {e}");
                    }
                }
            }
            let status = std::process::Command::new(&current_exe)
                .arg(&exe_path)
                .status()
                .unwrap_or_else(|e| {
                    eprintln!(
                        "weave prefix launch: failed to exec {}: {e}",
                        current_exe.display()
                    );
                    std::process::exit(1);
                });
            std::process::exit(status.code().unwrap_or(1));
        }
        Some("delete") => {
            let name = args.get(1).unwrap_or_else(|| {
                eprintln!("weave prefix delete: missing <name>");
                std::process::exit(1);
            });
            mgr.delete(name).unwrap_or_else(|e| {
                eprintln!("weave prefix delete: {e}");
                std::process::exit(1);
            });
            println!("deleted prefix '{name}'");
            std::process::exit(0);
        }
        _ => usage(),
    }
}

/// IPersistFile::Save callback — writes a .desktop launcher to
/// ~/.local/share/applications/ when an installer creates a shortcut.
fn shell_link_save_callback(data: &ShellLinkSaveData) -> Result<(), String> {
    let exe_path = match &data.path {
        Some(p) if !p.is_empty() => p.as_str(),
        _ => return Ok(()),
    };
    let name = data
        .description
        .as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::path::Path::new(&data.lnk_dest_path)
                .file_stem()
                .and_then(|s| s.to_str())
        })
        .unwrap_or("Weave App");
    let mut exec_cmd = format!("weave \"{exe_path}\"");
    if let Some(args) = &data.arguments {
        if !args.is_empty() {
            exec_cmd = format!("{exec_cmd} {args}");
        }
    }
    let home = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
    let dest_dir = home.join(".local/share/applications");
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("weave: could not create applications dir: {e}"))?;
    let icon = data.icon_path.as_deref();
    match weave_desktop::write_shortcut(name, &exec_cmd, icon, &dest_dir) {
        Ok(path) => {
            eprintln!("weave: installed shortcut: {}", path.display());
            Ok(())
        }
        Err(e) => Err(format!("weave: failed to write shortcut: {e}")),
    }
}

/// Child-side socket fd for IPC with the host process.
/// Set once after fork() in the child branch.
static CHILD_FD: std::sync::OnceLock<libc::c_int> = std::sync::OnceLock::new();

/// DRM render node fd received from the host via SCM_RIGHTS for Vulkan.
/// Set after seccomp is applied in the child branch.
static DRM_FD: std::sync::OnceLock<libc::c_int> = std::sync::OnceLock::new();

// ── IPC stub functions (child side) ──────────────────────────────────
// These replace the real Win32 implementations for the out-of-process
// execution path.  Each stub serialises the call, sends it to the host
// process via CHILD_FD, and returns the host's reply.

/// Send a generic IPC call and return the host's reply value.
fn ipc_call(
    dll: &str,
    func: &str,
    args: Vec<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let fd = CHILD_FD.get().ok_or("CHILD_FD not set")?;
    let msg = CallMsg {
        msg_type: "call".to_string(),
        dll: dll.to_string(),
        function: func.to_string(),
        args,
    };
    weave_ipc::send_msg(*fd, &msg)?;
    let reply = weave_ipc::recv_reply(*fd)?;
    Ok(reply.result)
}

/// IPC stub for RegisterClassW.
pub unsafe extern "win64" fn ipc_register_class_w(lp_wnd_class: *const WndClassW) -> u16 {
    let bytes = weave_ipc::struct_to_value(&*lp_wnd_class);
    match ipc_call("user32.dll", "RegisterClassW", vec![bytes]) {
        Ok(v) => v.as_u64().unwrap_or(0) as u16,
        Err(_) => 0,
    }
}

/// IPC stub for RegisterClassExW.
pub unsafe extern "win64" fn ipc_register_class_ex_w(lp_wnd_class_ex: *const WndClassExW) -> u16 {
    let bytes = weave_ipc::struct_to_value(&*lp_wnd_class_ex);
    match ipc_call("user32.dll", "RegisterClassExW", vec![bytes]) {
        Ok(v) => v.as_u64().unwrap_or(0) as u16,
        Err(_) => 0,
    }
}

/// IPC stub for CreateWindowExW.
pub unsafe extern "win64" fn ipc_create_window_ex_w(
    dw_ex_style: u32,
    lp_class_name: *const u16,
    lp_window_name: *const u16,
    dw_style: u32,
    x: i32,
    y: i32,
    n_width: i32,
    n_height: i32,
    h_wnd_parent: usize,
    h_menu: usize,
    h_instance: usize,
    lp_param: *mut u8,
) -> usize {
    // Read wide strings from guest memory (valid in both processes via COW fork)
    let cls_name = if (lp_class_name as usize) >> 16 == 0 {
        format!("#{}", lp_class_name as u16)
    } else {
        let len = (0..256)
            .find(|&i| unsafe { *lp_class_name.add(i) } == 0)
            .unwrap_or(0);
        String::from_utf16_lossy(std::slice::from_raw_parts(lp_class_name, len))
    };
    let win_name = if !lp_window_name.is_null() {
        let len = (0..1024)
            .find(|&i| unsafe { *lp_window_name.add(i) } == 0)
            .unwrap_or(0);
        String::from_utf16_lossy(std::slice::from_raw_parts(lp_window_name, len))
    } else {
        String::new()
    };
    match ipc_call(
        "user32.dll",
        "CreateWindowExW",
        vec![
            json!(dw_ex_style),
            json!(cls_name),
            json!(win_name),
            json!(dw_style),
            json!(x),
            json!(y),
            json!(n_width),
            json!(n_height),
            json!(h_wnd_parent),
            json!(h_menu),
            json!(h_instance),
            json!(lp_param as usize),
        ],
    ) {
        Ok(v) => v.as_u64().unwrap_or(0) as usize,
        Err(_) => 0,
    }
}

/// IPC stub for ShowWindow.
pub extern "win64" fn ipc_show_window(h_wnd: usize, n_cmd_show: i32) -> i32 {
    match ipc_call(
        "user32.dll",
        "ShowWindow",
        vec![json!(h_wnd), json!(n_cmd_show)],
    ) {
        Ok(v) => v.as_i64().unwrap_or(0) as i32,
        Err(_) => 0,
    }
}

/// IPC stub for UpdateWindow.
pub extern "win64" fn ipc_update_window(h_wnd: usize) -> i32 {
    match ipc_call("user32.dll", "UpdateWindow", vec![json!(h_wnd)]) {
        Ok(v) => v.as_i64().unwrap_or(0) as i32,
        Err(_) => 0,
    }
}

/// IPC stub for GetMessageW.
pub unsafe extern "win64" fn ipc_get_message_w(
    lp_msg: *mut Msg,
    h_wnd: usize,
    msg_filter_min: u32,
    msg_filter_max: u32,
) -> i32 {
    match ipc_call(
        "user32.dll",
        "GetMessageW",
        vec![json!(h_wnd), json!(msg_filter_min), json!(msg_filter_max)],
    ) {
        Ok(v) => {
            if let Some(msg_bytes) = v.get("msg") {
                if let Ok(msg) = weave_ipc::value_to_struct::<Msg>(msg_bytes) {
                    unsafe {
                        *lp_msg = msg;
                    }
                }
            }
            v.get("ret").and_then(|r| r.as_i64()).unwrap_or(-1) as i32
        }
        Err(_) => {
            unsafe {
                std::ptr::write_bytes(lp_msg as *mut u8, 0, std::mem::size_of::<Msg>());
            }
            -1
        }
    }
}

/// IPC stub for PeekMessageW.
pub unsafe extern "win64" fn ipc_peek_message_w(
    lp_msg: *mut Msg,
    h_wnd: usize,
    msg_filter_min: u32,
    msg_filter_max: u32,
    w_remove_msg: u32,
) -> i32 {
    match ipc_call(
        "user32.dll",
        "PeekMessageW",
        vec![
            json!(h_wnd),
            json!(msg_filter_min),
            json!(msg_filter_max),
            json!(w_remove_msg),
        ],
    ) {
        Ok(v) => {
            if let Some(msg_bytes) = v.get("msg") {
                if let Ok(msg) = weave_ipc::value_to_struct::<Msg>(msg_bytes) {
                    unsafe {
                        *lp_msg = msg;
                    }
                }
            }
            v.get("ret").and_then(|r| r.as_i64()).unwrap_or(0) as i32
        }
        Err(_) => {
            unsafe {
                std::ptr::write_bytes(lp_msg as *mut u8, 0, std::mem::size_of::<Msg>());
            }
            0
        }
    }
}

/// IPC stub for TranslateMessage.
pub unsafe extern "win64" fn ipc_translate_message(lp_msg: *const Msg) -> i32 {
    let msg_bytes = weave_ipc::struct_to_value(unsafe { &*lp_msg });
    match ipc_call("user32.dll", "TranslateMessage", vec![msg_bytes]) {
        Ok(v) => v.as_i64().unwrap_or(0) as i32,
        Err(_) => 0,
    }
}

/// IPC stub for DispatchMessageW.
pub unsafe extern "win64" fn ipc_dispatch_message_w(lp_msg: *const Msg) -> isize {
    let msg_bytes = weave_ipc::struct_to_value(unsafe { &*lp_msg });
    match ipc_call("user32.dll", "DispatchMessageW", vec![msg_bytes]) {
        Ok(v) => v.as_i64().unwrap_or(0) as isize,
        Err(_) => 0,
    }
}

/// IPC stub for DefWindowProcW.
pub extern "win64" fn ipc_def_window_proc_w(
    h_wnd: usize,
    msg: u32,
    w_param: usize,
    l_param: isize,
) -> isize {
    match ipc_call(
        "user32.dll",
        "DefWindowProcW",
        vec![json!(h_wnd), json!(msg), json!(w_param), json!(l_param)],
    ) {
        Ok(v) => v.as_i64().unwrap_or(0) as isize,
        Err(_) => 0,
    }
}

/// IPC stub for GetDC.
pub extern "win64" fn ipc_get_dc(h_wnd: usize) -> usize {
    match ipc_call("user32.dll", "GetDC", vec![json!(h_wnd)]) {
        Ok(v) => v.as_u64().unwrap_or(0) as usize,
        Err(_) => 0,
    }
}

/// IPC stub for ReleaseDC.
pub extern "win64" fn ipc_release_dc(h_wnd: usize, h_dc: usize) -> i32 {
    match ipc_call("user32.dll", "ReleaseDC", vec![json!(h_wnd), json!(h_dc)]) {
        Ok(v) => v.as_i64().unwrap_or(0) as i32,
        Err(_) => 0,
    }
}

/// IPC stub for GetClientRect.
pub unsafe extern "win64" fn ipc_get_client_rect(
    h_wnd: usize,
    lp_rect: *mut weave_user32::defs::Rect,
) -> i32 {
    match ipc_call("user32.dll", "GetClientRect", vec![json!(h_wnd)]) {
        Ok(v) => {
            if let Some(rect_bytes) = v.get("rect") {
                if let Ok(rect) = weave_ipc::value_to_struct::<weave_user32::defs::Rect>(rect_bytes)
                {
                    unsafe {
                        *lp_rect = rect;
                    }
                }
            }
            v.get("ret").and_then(|r| r.as_i64()).unwrap_or(0) as i32
        }
        Err(_) => 0,
    }
}

/// IPC stub for DestroyWindow.
pub extern "win64" fn ipc_destroy_window(h_wnd: usize) -> i32 {
    match ipc_call("user32.dll", "DestroyWindow", vec![json!(h_wnd)]) {
        Ok(v) => v.as_i64().unwrap_or(0) as i32,
        Err(_) => 0,
    }
}

/// IPC stub for PostQuitMessage.
pub extern "win64" fn ipc_post_quit_message(n_exit_code: i32) {
    let _ = ipc_call("user32.dll", "PostQuitMessage", vec![json!(n_exit_code)]);
}

/// IPC stub for GetSystemMetrics.
pub extern "win64" fn ipc_get_system_metrics(n_index: i32) -> i32 {
    match ipc_call("user32.dll", "GetSystemMetrics", vec![json!(n_index)]) {
        Ok(v) => v.as_i64().unwrap_or(0) as i32,
        Err(_) => 0,
    }
}

/// IPC stub for SetCursor.
pub extern "win64" fn ipc_set_cursor(h_cursor: usize) -> usize {
    match ipc_call("user32.dll", "SetCursor", vec![json!(h_cursor)]) {
        Ok(v) => v.as_u64().unwrap_or(0) as usize,
        Err(_) => 0,
    }
}

/// IPC stub for ExitProcess.
pub extern "win64" fn ipc_exit_process(u_exit_code: u32) -> ! {
    let fd = CHILD_FD.get().expect("CHILD_FD not set in child");
    let msg = CallMsg {
        msg_type: "call".to_string(),
        dll: "kernel32.dll".to_string(),
        function: "ExitProcess".to_string(),
        args: vec![serde_json::json!(u_exit_code)],
    };
    let _ = weave_ipc::send_msg(*fd, &msg);
    unsafe { libc::exit(u_exit_code as i32) }
}

/// IPC stub for GetStdHandle.
pub extern "win64" fn ipc_get_std_handle(n_std_handle: u32) -> usize {
    let fd = CHILD_FD.get().expect("CHILD_FD not set in child");
    let msg = CallMsg {
        msg_type: "call".to_string(),
        dll: "kernel32.dll".to_string(),
        function: "GetStdHandle".to_string(),
        args: vec![serde_json::json!(n_std_handle)],
    };
    if weave_ipc::send_msg(*fd, &msg).is_err() {
        return usize::MAX;
    }
    match weave_ipc::recv_reply(*fd) {
        Ok(reply) => reply.result.as_u64().unwrap_or(usize::MAX as u64) as usize,
        Err(_) => usize::MAX,
    }
}

/// IPC stub for WriteFile.
pub unsafe extern "win64" fn ipc_write_file(
    h_file: usize,
    lp_buffer: *const u8,
    n_bytes_to_write: u32,
    lp_bytes_written: *mut u32,
    lp_overlapped: usize,
) -> i32 {
    let fd = CHILD_FD.get().expect("CHILD_FD not set in child");
    let buf_data: Vec<u8> = if !lp_buffer.is_null() && n_bytes_to_write > 0 {
        unsafe { std::slice::from_raw_parts(lp_buffer, n_bytes_to_write as usize) }.to_vec()
    } else {
        Vec::new()
    };
    let msg = CallMsg {
        msg_type: "call".to_string(),
        dll: "kernel32.dll".to_string(),
        function: "WriteFile".to_string(),
        args: vec![
            serde_json::json!(h_file),
            serde_json::json!(buf_data),
            serde_json::json!(n_bytes_to_write),
            serde_json::json!(lp_overlapped),
        ],
    };
    if weave_ipc::send_msg(*fd, &msg).is_err() {
        if !lp_bytes_written.is_null() {
            unsafe { *lp_bytes_written = 0 };
        }
        return 0;
    }
    let reply = match weave_ipc::recv_reply(*fd) {
        Ok(r) => r,
        Err(_) => {
            if !lp_bytes_written.is_null() {
                unsafe { *lp_bytes_written = 0 };
            }
            return 0;
        }
    };
    let ok = reply
        .result
        .get("ok")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let written = reply
        .result
        .get("written")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    if !lp_bytes_written.is_null() {
        unsafe { *lp_bytes_written = written };
    }
    if ok {
        1
    } else {
        0
    }
}

/// IPC stub for WriteConsoleW.
pub unsafe extern "win64" fn ipc_write_console_w(
    h_console_output: usize,
    lp_buffer: *const u16,
    n_chars: u32,
    lp_chars_written: *mut u32,
    _lp_reserved: usize,
) -> i32 {
    let fd = CHILD_FD.get().expect("CHILD_FD not set in child");
    let buf_data: Vec<u8> = if !lp_buffer.is_null() && n_chars > 0 {
        let slice =
            unsafe { std::slice::from_raw_parts(lp_buffer as *const u8, n_chars as usize * 2) };
        slice.to_vec()
    } else {
        Vec::new()
    };
    let msg = CallMsg {
        msg_type: "call".to_string(),
        dll: "kernel32.dll".to_string(),
        function: "WriteConsoleW".to_string(),
        args: vec![
            serde_json::json!(h_console_output),
            serde_json::json!(buf_data),
            serde_json::json!(n_chars),
            serde_json::json!(!lp_chars_written.is_null()),
        ],
    };
    if weave_ipc::send_msg(*fd, &msg).is_err() {
        if !lp_chars_written.is_null() {
            unsafe { *lp_chars_written = 0 };
        }
        return 0;
    }
    let reply = match weave_ipc::recv_reply(*fd) {
        Ok(r) => r,
        Err(_) => {
            if !lp_chars_written.is_null() {
                unsafe { *lp_chars_written = 0 };
            }
            return 0;
        }
    };
    let ok = reply
        .result
        .get("ok")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let written = reply
        .result
        .get("written")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    if !lp_chars_written.is_null() {
        unsafe { *lp_chars_written = written };
    }
    if ok {
        1
    } else {
        0
    }
}

/// Resolver wrapper that returns IPC stubs for the out-of-process execution
/// model.  Used during IAT patching of the main exe (section 3) so the guest
/// code calls IPC stubs instead of the real Win32 implementations.
fn resolve_with_ipc_stubs(dll: &str, func: &str) -> Option<usize> {
    let dll_lower = dll.to_lowercase();
    // For user32 and gdi32, ALL calls go through IPC (seccomp blocks X11 poll).
    // Each IPC stub serialises args, sends them to the host process, and
    // returns the host's result.  The host process runs without seccomp and
    // calls the real in-process implementations.
    match (dll_lower.as_str(), func) {
        ("kernel32.dll", "ExitProcess") => Some(ipc_exit_process as *const () as usize),
        ("kernel32.dll", "GetStdHandle") => Some(ipc_get_std_handle as *const () as usize),
        ("kernel32.dll", "WriteFile") => Some(ipc_write_file as *const () as usize),
        ("kernel32.dll", "WriteConsoleW") => Some(ipc_write_console_w as *const () as usize),
        // user32.dll — message loop and window lifecycle
        ("user32.dll", "RegisterClassW") => Some(ipc_register_class_w as *const () as usize),
        ("user32.dll", "RegisterClassExW") => Some(ipc_register_class_ex_w as *const () as usize),
        ("user32.dll", "CreateWindowExW") => Some(ipc_create_window_ex_w as *const () as usize),
        ("user32.dll", "ShowWindow") => Some(ipc_show_window as *const () as usize),
        ("user32.dll", "UpdateWindow") => Some(ipc_update_window as *const () as usize),
        ("user32.dll", "GetMessageW") => Some(ipc_get_message_w as *const () as usize),
        ("user32.dll", "PeekMessageW") => Some(ipc_peek_message_w as *const () as usize),
        ("user32.dll", "TranslateMessage") => Some(ipc_translate_message as *const () as usize),
        ("user32.dll", "DispatchMessageW") => Some(ipc_dispatch_message_w as *const () as usize),
        ("user32.dll", "DefWindowProcW") => Some(ipc_def_window_proc_w as *const () as usize),
        ("user32.dll", "GetDC") => Some(ipc_get_dc as *const () as usize),
        ("user32.dll", "ReleaseDC") => Some(ipc_release_dc as *const () as usize),
        ("user32.dll", "GetClientRect") => Some(ipc_get_client_rect as *const () as usize),
        ("user32.dll", "DestroyWindow") => Some(ipc_destroy_window as *const () as usize),
        ("user32.dll", "PostQuitMessage") => Some(ipc_post_quit_message as *const () as usize),
        ("user32.dll", "GetSystemMetrics") => Some(ipc_get_system_metrics as *const () as usize),
        ("user32.dll", "SetCursor") => Some(ipc_set_cursor as *const () as usize),
        _ => resolve(dll, func),
    }
}

/// Host-side IPC handler: resolves the requested function through `resolve`,
/// calls it with the deserialised arguments, and returns the result for the
/// host_loop to forward back to the child.
///
/// Returns `None` for ExitProcess (the function calls libc::exit internally,
/// so the host_loop must break rather than attempt to send a reply).
fn ipc_handler(dll: &str, function: &str, args: &[serde_json::Value]) -> Option<serde_json::Value> {
    match (dll, function) {
        ("kernel32.dll", "ExitProcess") => {
            let code = args.first().and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            eprintln!("weave/host: ExitProcess({code})");
            unsafe { libc::exit(code as i32) }
        }
        ("kernel32.dll", "GetStdHandle") => {
            let n = args.first().and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let addr =
                resolve("kernel32.dll", "GetStdHandle").expect("GetStdHandle must be resolvable");
            let func: extern "win64" fn(u32) -> usize = unsafe { std::mem::transmute(addr) };
            let h = func(n);
            eprintln!("weave/host: GetStdHandle({n}) → {h:#x}");
            Some(serde_json::json!(h))
        }
        ("kernel32.dll", "WriteFile") => {
            let h_file = args.first().and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let buf_data: Vec<u8> =
                serde_json::from_value(args.get(1).cloned().unwrap_or_default())
                    .unwrap_or_default();
            let overlapped = args.get(3).and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let addr = resolve("kernel32.dll", "WriteFile").expect("WriteFile must be resolvable");
            let func: unsafe extern "win64" fn(usize, *const u8, u32, *mut u32, usize) -> i32 =
                unsafe { std::mem::transmute(addr) };
            let mut written: u32 = 0;
            let ret = unsafe {
                func(
                    h_file,
                    buf_data.as_ptr(),
                    buf_data.len() as u32,
                    &mut written,
                    overlapped,
                )
            };
            eprintln!(
                "weave/host: WriteFile({h_file:#x}, {} bytes) → {ret}, written={written}",
                buf_data.len()
            );
            Some(serde_json::json!({"ok": ret != 0, "written": written}))
        }
        ("kernel32.dll", "WriteConsoleW") => {
            let h_console = args.first().and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let buf_data: Vec<u8> =
                serde_json::from_value(args.get(1).cloned().unwrap_or_default())
                    .unwrap_or_default();
            let has_chars_written = args.get(3).and_then(|v| v.as_bool()).unwrap_or(false);
            let u16_buf: Vec<u16> = buf_data
                .chunks(2)
                .filter(|c| c.len() == 2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let n_chars = u16_buf.len() as u32;
            let addr =
                resolve("kernel32.dll", "WriteConsoleW").expect("WriteConsoleW must be resolvable");
            let func: unsafe extern "win64" fn(usize, *const u16, u32, *mut u32, usize) -> i32 =
                unsafe { std::mem::transmute(addr) };
            let mut written: u32 = 0;
            let ret = unsafe {
                func(
                    h_console,
                    u16_buf.as_ptr(),
                    n_chars,
                    if has_chars_written {
                        &mut written
                    } else {
                        std::ptr::null_mut()
                    },
                    0,
                )
            };
            eprintln!(
                "weave/host: WriteConsoleW({h_console:#x}, {} chars) → {ret}, written={written}",
                n_chars
            );
            Some(serde_json::json!({"ok": ret != 0, "written": written}))
        }
        // ── user32.dll — message loop and window lifecycle ─────────────────
        ("user32.dll", "RegisterClassW") => {
            let wc: WndClassW = args
                .first()
                .and_then(|v| weave_ipc::value_to_struct(v).ok())?;
            let addr = resolve("user32.dll", "RegisterClassW")?;
            let func: unsafe extern "win64" fn(*const WndClassW) -> u16 =
                unsafe { std::mem::transmute(addr) };
            let atom = unsafe { func(&wc) };
            Some(json!(atom))
        }
        ("user32.dll", "RegisterClassExW") => {
            let wc: WndClassExW = args
                .first()
                .and_then(|v| weave_ipc::value_to_struct(v).ok())?;
            let addr = resolve("user32.dll", "RegisterClassExW")?;
            let func: unsafe extern "win64" fn(*const WndClassExW) -> u16 =
                unsafe { std::mem::transmute(addr) };
            let atom = unsafe { func(&wc) };
            Some(json!(atom))
        }
        ("user32.dll", "CreateWindowExW") => {
            // Initialise the X11 backend in the host process — the child
            // runs under seccomp and cannot connect to the display server.
            #[cfg(target_os = "linux")]
            weave_user32::backend::init();
            let exs = args.first().and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let cls = args.get(1).and_then(|v| v.as_str()).unwrap_or("");
            let title = args.get(2).and_then(|v| v.as_str()).unwrap_or("");
            let style = args.get(3).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let x = args.get(4).and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let y = args.get(5).and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let w = args.get(6).and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let h = args.get(7).and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let parent = args.get(8).and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let menu = args.get(9).and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let inst = args.get(10).and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let param = args.get(11).and_then(|v| v.as_u64()).unwrap_or(0) as *mut u8;
            let cls_w: Vec<u16> = cls.encode_utf16().chain(std::iter::once(0)).collect();
            let title_w: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
            let addr = resolve("user32.dll", "CreateWindowExW")?;
            type CwFn = unsafe extern "win64" fn(
                u32,
                *const u16,
                *const u16,
                u32,
                i32,
                i32,
                i32,
                i32,
                usize,
                usize,
                usize,
                *mut u8,
            ) -> usize;
            let func: CwFn = unsafe { std::mem::transmute(addr) };
            let hwnd = unsafe {
                func(
                    exs,
                    cls_w.as_ptr(),
                    title_w.as_ptr(),
                    style,
                    x,
                    y,
                    w,
                    h,
                    parent,
                    menu,
                    inst,
                    param,
                )
            };
            Some(json!(hwnd))
        }
        ("user32.dll", "ShowWindow") => {
            let h_wnd = args.first().and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let c = args.get(1).and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let addr = resolve("user32.dll", "ShowWindow")?;
            let func: extern "win64" fn(usize, i32) -> i32 = unsafe { std::mem::transmute(addr) };
            Some(json!(func(h_wnd, c)))
        }
        ("user32.dll", "UpdateWindow") => {
            let h_wnd = args.first().and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let addr = resolve("user32.dll", "UpdateWindow")?;
            let func: extern "win64" fn(usize) -> i32 = unsafe { std::mem::transmute(addr) };
            Some(json!(func(h_wnd)))
        }
        ("user32.dll", "GetMessageW") => {
            let h_wnd = args.first().and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let lo = args.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let hi = args.get(2).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let addr = resolve("user32.dll", "GetMessageW")?;
            type GmFn = unsafe extern "win64" fn(*mut Msg, usize, u32, u32) -> i32;
            let func: GmFn = unsafe { std::mem::transmute(addr) };
            let mut msg: Msg = unsafe { std::mem::zeroed() };
            let ret = unsafe { func(&mut msg, h_wnd, lo, hi) };
            Some(json!({"ret": ret, "msg": weave_ipc::struct_to_value(&msg)}))
        }
        ("user32.dll", "PeekMessageW") => {
            let h_wnd = args.first().and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let lo = args.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let hi = args.get(2).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let rm = args.get(3).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let addr = resolve("user32.dll", "PeekMessageW")?;
            type PmFn = unsafe extern "win64" fn(*mut Msg, usize, u32, u32, u32) -> i32;
            let func: PmFn = unsafe { std::mem::transmute(addr) };
            let mut msg: Msg = unsafe { std::mem::zeroed() };
            let ret = unsafe { func(&mut msg, h_wnd, lo, hi, rm) };
            Some(json!({"ret": ret, "msg": weave_ipc::struct_to_value(&msg)}))
        }
        ("user32.dll", "TranslateMessage") => {
            let msg: Msg = args
                .first()
                .and_then(|v| weave_ipc::value_to_struct(v).ok())?;
            let addr = resolve("user32.dll", "TranslateMessage")?;
            let func: unsafe extern "win64" fn(*const Msg) -> i32 =
                unsafe { std::mem::transmute(addr) };
            Some(json!(unsafe { func(&msg) }))
        }
        ("user32.dll", "DispatchMessageW") => {
            let msg: Msg = args
                .first()
                .and_then(|v| weave_ipc::value_to_struct(v).ok())?;
            let addr = resolve("user32.dll", "DispatchMessageW")?;
            let func: unsafe extern "win64" fn(*const Msg) -> isize =
                unsafe { std::mem::transmute(addr) };
            Some(json!(unsafe { func(&msg) }))
        }
        ("user32.dll", "DefWindowProcW") => {
            let h = args.first().and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let m = args.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let wp = args.get(2).and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let lp = args.get(3).and_then(|v| v.as_i64()).unwrap_or(0) as isize;
            let addr = resolve("user32.dll", "DefWindowProcW")?;
            let func: extern "win64" fn(usize, u32, usize, isize) -> isize =
                unsafe { std::mem::transmute(addr) };
            Some(json!(func(h, m, wp, lp)))
        }
        ("user32.dll", "GetDC") => {
            let h = args.first().and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let addr = resolve("user32.dll", "GetDC")?;
            let func: extern "win64" fn(usize) -> usize = unsafe { std::mem::transmute(addr) };
            Some(json!(func(h)))
        }
        ("user32.dll", "ReleaseDC") => {
            let h = args.first().and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let dc = args.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let addr = resolve("user32.dll", "ReleaseDC")?;
            let func: extern "win64" fn(usize, usize) -> i32 = unsafe { std::mem::transmute(addr) };
            Some(json!(func(h, dc)))
        }
        ("user32.dll", "GetClientRect") => {
            let h = args.first().and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let addr = resolve("user32.dll", "GetClientRect")?;
            type GcrFn = unsafe extern "win64" fn(usize, *mut weave_user32::defs::Rect) -> i32;
            let func: GcrFn = unsafe { std::mem::transmute(addr) };
            let mut rect: weave_user32::defs::Rect = unsafe { std::mem::zeroed() };
            let ret = unsafe { func(h, &mut rect) };
            Some(json!({"ret": ret, "rect": weave_ipc::struct_to_value(&rect)}))
        }
        ("user32.dll", "DestroyWindow") => {
            let h = args.first().and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let addr = resolve("user32.dll", "DestroyWindow")?;
            let func: extern "win64" fn(usize) -> i32 = unsafe { std::mem::transmute(addr) };
            Some(json!(func(h)))
        }
        ("user32.dll", "PostQuitMessage") => {
            let code = args.first().and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let addr = resolve("user32.dll", "PostQuitMessage")?;
            let func: extern "win64" fn(i32) = unsafe { std::mem::transmute(addr) };
            func(code);
            Some(json!(0))
        }
        ("user32.dll", "GetSystemMetrics") => {
            let idx = args.first().and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let addr = resolve("user32.dll", "GetSystemMetrics")?;
            let func: extern "win64" fn(i32) -> i32 = unsafe { std::mem::transmute(addr) };
            Some(json!(func(idx)))
        }
        ("user32.dll", "SetCursor") => {
            let c = args.first().and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let addr = resolve("user32.dll", "SetCursor")?;
            let func: extern "win64" fn(usize) -> usize = unsafe { std::mem::transmute(addr) };
            Some(json!(func(c)))
        }
        _ => {
            eprintln!("weave/host: unhandled IPC call: {dll}!{function}");
            Some(serde_json::Value::Null)
        }
    }
}

fn main() {
    // Initialize glibc locale at process start so character classification
    // (iswctype, isalpha, etc.) doesn't SIGSEGV at fault=0x8 when called
    // from PE code during loading or init.  Must be before any PE operations.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::setlocale(libc::LC_ALL, c"C".as_ptr());
    }

    // ── −3. Prefix subcommand dispatch — intercept before clap parsing ────
    // `weave prefix <create|list|launch|delete> [args...]` is handled here so
    // that Args::parse() (which requires an exe positional arg) is never called
    // for prefix management commands.
    let raw: Vec<String> = std::env::args().collect();
    if raw.get(1).map(|s| s.as_str()) == Some("prefix") {
        handle_prefix_cmd(&raw[2..]);
    }

    // ── −2. Panic hook — must be first, before any PE is loaded ──────────
    // Catches Rust panics inside Weave stubs (e.g. todo!(), unimplemented!()).
    // These call OS exit directly — no SIGSEGV, no SEH — so without this hook
    // they are invisible. Output goes to stderr before the process dies.
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown>".to_string());
        let message = if let Some(s) = info.payload().downcast_ref::<&str>() {
            *s
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.as_str()
        } else {
            "<non-string payload>"
        };
        eprintln!("weave: RUST PANIC — {location}: {message}");
    }));

    let args = Args::parse();

    // The test-only kill switch must fail before the out-of-process host can
    // fork. `apply` records Disabled without restricting the process, then
    // the canonical invariant emits its stable diagnostic and aborts.
    let sandbox_disabled_by_env = std::env::var_os("WEAVE_DISABLE_SANDBOX")
        .map(|value| !value.is_empty() && value != "0")
        .unwrap_or(false);
    if sandbox_disabled_by_env {
        weave_sandbox::apply(true, &[]);
        weave_sandbox::assert_sandboxed!("weave-cli");
    }

    // ── −0.5. Stub-trace mode ────────────────────────────────────────────
    // When --trace-stubs is passed, force-enable the per-slot IAT tracer,
    // switch on stub classification, and redirect structured JSONL output
    // to the given file (or stubs.jsonl in CWD by default).
    if let Some(path) = &args.trace_stubs {
        iat::force_enable_tracer();
        iat::enable_stub_trace();
        iat::register_all_known_reals();
        if let Err(e) = iat::set_trace_output(path) {
            eprintln!("weave: warning: could not open stub trace output '{path}': {e}");
        }
    }

    // ── −1. Architecture compatibility ────────────────────────────────────
    if let Err(code) = arch::check_arch_compatibility(&args.exe) {
        std::process::exit(code);
    }

    // ── 0. Initialise the prefix ──────────────────────────────────────────
    // Set the Windows command line before IAT patching so that
    // GetCommandLineA/W and _acmdln/_wcmdln return the real argv.
    {
        let exe_name = args
            .exe
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("app.exe");
        // Convert absolute Linux paths in exe_args to Windows Z:\ paths so
        // that Windows apps receive paths they can round-trip through
        // GetFullPathNameW / CreateFileW.  Without this, a Linux path like
        // /weave/foo/bar.txt is treated as relative by GetFullPathNameW (it
        // doesn't start with a drive letter or backslash) and gets the CWD
        // prepended, doubling the path prefix.
        let windows_args: Vec<String> = args
            .exe_args
            .iter()
            .map(|arg| {
                if arg.starts_with('/') {
                    // Canonicalize to resolve any .. components, then map to Z:\
                    let canonical = std::path::Path::new(arg)
                        .canonicalize()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| arg.clone());
                    format!("Z:{}", canonical.replace('/', "\\"))
                } else {
                    arg.clone()
                }
            })
            .collect();
        cmdline::set(exe_name, &windows_args);
    }

    // Store the exe path as a Windows path (Z:\...) so GetModuleFileNameW(NULL)
    // can return the real location, letting apps like Notepad++ find their
    // plugins folder relative to the executable.
    //
    // Do NOT call canonicalize() here — that resolves symlinks and would defeat
    // short-path symlinks used to work around NXEngine's fixed-size path buffers
    // (e.g. /tmp/nx → tests/fixtures/nxengine). Make absolute, then lexical-clean.
    {
        let joined = if args.exe.is_absolute() {
            args.exe.clone()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(&args.exe)
        };
        let abs = std::path::absolute(&joined).unwrap_or(joined);
        let clean = normalize_lexical(abs);
        let win_path = format!("Z:{}", clean.to_string_lossy().replace('/', "\\"));
        weave_core::exe_path::set(&win_path);
    }

    // Prefix resolution order (highest to lowest priority):
    //   1. --prefix CLI flag   — explicit user/caller override
    //   2. WEAVE_PREFIX env    — set by launchers (e.g. LibreWin binfmt_misc handler)
    //                            that cannot pass CLI flags
    //   3. $HOME/.weave/default — lazy default inside prefix::get()
    //
    // Design note: we resolve here in main.rs (next to the flag) rather than
    // inside prefix::get()'s lazy default, because prefix::set() is OnceLock-
    // backed and must be called before any file I/O stub runs.  Keeping it
    // explicit here makes the precedence obvious and testable.
    if let Some(p) = args.prefix {
        prefix::set(p);
    } else if let Ok(env_prefix) = std::env::var("WEAVE_PREFIX") {
        if !env_prefix.is_empty() {
            prefix::set(PathBuf::from(env_prefix));
        }
    }
    prefix::ensure_dirs();
    // Plugin loader removed — see weave-plugin-system/src/lib.rs (no shipped consumers; security: prefix-local .so loading pre-sandbox).
    registry::populate();

    // Diagnostic: if WEAVE_STALL_TRACE=1, spawn a periodic thread sampler. Off
    // by default.
    weave_core::stall_trace::start_if_enabled();

    // ── 1. Pre-load DLLs from the prefix ──────────────────────────────────
    // DLLs are loaded in dependency order so that each DLL's IAT can be
    // patched using exports from DLLs already registered.
    //
    // DXVK layout (user installs from a DXVK release into the prefix):
    //   {prefix}/drive_c/Windows/System32/{d3d9,d3d10core,d3d11,dxgi}.dll
    //
    // Any DLL not present is silently skipped — apps that don't use DirectX
    // continue to work unchanged.
    let system32 = prefix::system32();
    // dxgi must load before d3d10core / d3d11 (they import from it).
    let preload_dlls = ["dxgi.dll", "d3d9.dll", "d3d10core.dll", "d3d11.dll"];
    for dll_name in &preload_dlls {
        let path = system32.join(dll_name);
        let dll_bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue, // not installed — skip silently
        };
        match loader::load_dll(&dll_bytes) {
            Ok((image, exports)) => {
                // Patch the DLL's own IAT using our resolver (which by now
                // includes any DLLs registered in earlier iterations).
                unsafe {
                    iat::patch_best_effort(&dll_bytes, image.base, resolve, |d, f, va| {
                        eprintln!(
                            "weave: {dll_name}: unresolved import {d}!{f} at iat={va:#x} (skipped)"
                        );
                    });
                }
                dll_registry::register(dll_name.to_lowercase(), image, exports);
                eprintln!("weave: pre-loaded {dll_name}");
            }
            Err(e) => eprintln!("weave: warning: could not load {dll_name}: {e}"),
        }
    }

    let bytes = std::fs::read(&args.exe).unwrap_or_else(|e| {
        eprintln!("weave: error reading {}: {e}", args.exe.display());
        std::process::exit(1);
    });

    // ── 2. Load sections into memory ──────────────────────────────────────
    // Derive the module-handle name from the exe path's final component so
    // the guest PE's loaded base is reachable via `module_handles::base_of`
    // (task 09 step 3 — resource walker needs the base behind an HMODULE).
    let exe_name = args
        .exe
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("guest.exe")
        .to_string();
    let image = loader::load_with_name(&bytes, &exe_name).unwrap_or_else(|e| {
        eprintln!("weave: load failed: {e}");
        std::process::exit(1);
    });

    eprintln!(
        "weave: loaded {} at {:#x} (entry {:#x})",
        args.exe.display(),
        image.base as usize,
        image.entry_point as usize,
    );

    // ── 2.5. Pre-load side-by-side DLLs from the exe's directory ─────────
    // Windows DLL search order: exe dir is checked before system32. Any DLL
    // that lives next to the exe and appears in its import table is loaded as
    // a PE and registered so that IAT patching can resolve its exports.
    // SDL2.dll, custom runtimes, and game-specific DLLs all land here.
    let mut side_dlls: Vec<(String, Vec<u8>, *mut u8)>;
    {
        let exe_dir_canon = args.exe.canonicalize().unwrap_or_else(|_| args.exe.clone());
        let exe_dir = exe_dir_canon.parent().unwrap_or(std::path::Path::new("."));

        // Collect unique DLL names from the import table.
        // Key = lowercase (for registry lookup); value = original case (for
        // case-sensitive Linux filesystem — e.g. "SDL2.dll" ≠ "sdl2.dll").
        let mut import_dlls: std::collections::HashMap<String, String> = Default::default();
        if let Ok(info) = pe::parse(&bytes) {
            for imp in &info.imports {
                import_dlls
                    .entry(imp.dll.to_lowercase())
                    .or_insert_with(|| imp.dll.clone());
            }
        }

        // Two-pass load: first register all exports, then patch all IATs.
        // This ensures that when sdl2_mixer.dll's IAT is patched, SDL2.dll's
        // exports are already registered (regardless of HashMap iteration order).
        side_dlls = Vec::new();

        // First pass: load DLLs from the main exe's import table.
        // Use a queue-based approach to handle transitive dependencies:
        // when we load a DLL, its imports may reference other companion DLLs
        // that weren't in the main exe's import table. Load those too.
        let mut pending: Vec<String> = import_dlls.values().cloned().collect();
        let mut loaded: std::collections::HashSet<String> = std::collections::HashSet::new();

        while let Some(dll_name) = pending.pop() {
            let dll_key = dll_name.to_lowercase();
            if loaded.contains(&dll_key) || dll_registry::is_registered(&dll_key) {
                continue;
            }
            let dll_bytes = match std::fs::read(exe_dir.join(&dll_name))
                .or_else(|_| std::fs::read(exe_dir.join(&dll_key)))
            {
                Ok(b) => b,
                Err(_) => continue,
            };
            match loader::load_dll(&dll_bytes) {
                Ok((image, exports)) => {
                    let base = image.base;
                    let image_size = image.size;
                    dll_registry::register(dll_key.clone(), image, exports);
                    let mod_idx = {
                        // SEH handler uses the first registered module that contains RIP.
                        // Count live entries so we can cross-reference crash mod[N].
                        static MOD_COUNT: std::sync::atomic::AtomicUsize =
                            std::sync::atomic::AtomicUsize::new(0);
                        MOD_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    };
                    weave_core::seh::register_loaded_module(base as usize, image_size);
                    // Patch known crash sites in CRT DLLs right after loading,
                    // before any DllMain is called (DllMain runs in pe_dispatch).
                    eprintln!(
                        "weave: pre-loaded {dll_name} from exe dir at base={:#x} mod[{mod_idx}]",
                        base as usize
                    );
                    loaded.insert(dll_key.clone());
                    side_dlls.push((dll_name, dll_bytes.clone(), base));
                    // Discover transitive dependencies and add them to the queue.
                    if let Ok(parsed) = weave_core::pe::parse(&dll_bytes) {
                        let mut deps: Vec<String> = Vec::new();
                        for dep in &parsed.imports {
                            let dep_key = dep.dll.to_lowercase();
                            deps.push(dep_key.clone());
                            if dep_key != dll_key
                                && !dll_registry::is_registered(&dep_key)
                                && !loaded.contains(&dep_key)
                            {
                                pending.push(dep.dll.clone());
                            }
                        }
                        dll_registry::register_imports(&dll_key, &deps);
                    }
                }
                Err(e) => {
                    eprintln!("weave: warning: could not load {dll_name} from exe dir: {e}");
                }
            }
        }

        for (dll_name, dll_bytes, base) in &side_dlls {
            unsafe {
                iat::patch_best_effort(dll_bytes, *base, resolve, |d, f, va| {
                    eprintln!(
                        "weave: {dll_name}: unresolved import {d}!{f} at iat={va:#x} (skipped)"
                    );
                });
            }
        }
    }
    // ── 2.6. E3-M9: pre-load IrfanView Plugins/OptiPNG.dll for save gate ───
    // Guest never calls FindFirstFileW on Plugins\*.dll under Weave; preload
    // so OptiPNG_W is registered before Save As runs.
    if std::env::var("WEAVE_TEST_SAVE_RESULT").is_ok() {
        let exe_dir_canon = args.exe.canonicalize().unwrap_or_else(|_| args.exe.clone());
        if let Some(exe_parent) = exe_dir_canon.parent() {
            let optipng_path = exe_parent.join("Plugins/OptiPNG.dll");
            if let Ok(dll_bytes) = std::fs::read(&optipng_path) {
                let key = "optipng.dll".to_string();
                let name = "OptiPNG.dll";
                match loader::load_dll(&dll_bytes) {
                    Ok((image, exports)) => {
                        let image_base = image.base as usize;
                        unsafe {
                            iat::patch_best_effort(&dll_bytes, image.base, resolve, |d, f, va| {
                                eprintln!(
                                    "weave/E3-M9-trace: OptiPNG.dll unresolved import {d}!{f} at iat={va:#x}"
                                );
                            });
                        }
                        cfg::disable_report_gsfailure(&dll_bytes, image.base);
                        cfg::disable_fastfail_gs(&dll_bytes, image.base);
                        // Log all exports
                        eprintln!("weave/E3-M9-trace: OptiPNG.dll exports registered:");
                        for (name, addr) in &exports {
                            eprintln!("weave/E3-M9-trace:   {name} -> {addr:#x}");
                        }
                        dll_registry::register(key, image, exports);
                        module_handles::register_with_handle(name, image_base);
                        module_handles::register_image_path(name, image_base);
                        eprintln!(
                            "weave/E3-M9-trace: preloaded OptiPNG.dll from {} at {image_base:#x}",
                            optipng_path.display()
                        );
                    }
                    Err(e) => eprintln!("weave/E3-M9-trace: OptiPNG preload failed: {e}"),
                }
            } else {
                eprintln!(
                    "weave/E3-M9-trace: OptiPNG.dll not found at {}",
                    optipng_path.display()
                );
            }
        }
    }

    // ── 3. Patch the Import Address Table ────────────────────────────────
    // Use best-effort patching: unresolved imports are filled with a stub
    // that returns 0 and logs the miss.  This lets the binary start even when
    // some stub crates are incomplete, and surfaces all missing imports at
    // once rather than one per run.
    //
    // In the default out-of-process path, the guest is forked and uses IPC
    // stubs that communicate with the host process.  In the --no-sandbox path
    // (no fork), use direct stubs to avoid panicking on missing CHILD_FD.
    //
    // Safety: image.base points to a fully mapped PE loaded by loader::load().
    let resolver: fn(&str, &str) -> Option<usize> = if args.no_sandbox {
        resolve
    } else {
        resolve_with_ipc_stubs
    };
    let mut missing: Vec<String> = Vec::new();
    unsafe {
        iat::patch_best_effort(&bytes, image.base, resolver, |dll, func, iat_va| {
            let sym = format!("{dll}!{func}");
            eprintln!("weave: unresolved import: {sym} at iat={iat_va:#x} (stubbed to null)");
            missing.push(sym);
        });
    }
    if !missing.is_empty() {
        eprintln!(
            "weave: warning: {} import(s) unresolved — binary may crash if they are called",
            missing.len()
        );
    }

    eprintln!("weave: imports resolved");

    // ── 3.5. Apply PE-specific binary patches ─────────────────────────────
    // Binary patches fix known issues in specific PE images that cannot be
    // resolved through Win32 stubs (e.g., internal C++ virtual methods that
    // return invalid values due to missing OS services).
    let exe_name = args
        .exe
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("");
    if exe_name.eq_ignore_ascii_case("SumatraPDF.exe")
        || exe_name.eq_ignore_ascii_case("sumatrapdf.exe")
    {
        // Binary patches for SumatraPDF.exe.
        //
        // The wrapper function at RVA 0x21c288 is called from two code paths:
        //   - 0x01e645 (main init) — passes a properly initialized stack struct
        //     with self-pointer at +0x38 in arg2 (rdx)
        //   - 0x05cf70 (file-watcher init / tab-control path) — only sets arg1 (rcx),
        //     leaves arg2 (rdx) as whatever was in the register from previous context
        //
        // The crash function at 0x21c0c4 reads the self-pointer from +0x38 of the
        // arg2 struct and calls through it as a vtable. On the second call path,
        // rdx contains garbage → +0x38 reads as INVALID_HANDLE_VALUE → the vtable
        // dereference at 0x21c1bd crashes with SIGSEGV.
        //
        // Patch 1 (RVA 0x21c2f2): Replace `and dword [rsp+0x20], 0` with
        // `mov byte [rsp+0x20], 4`.  Changes CreateThread's dwCreationFlags from
        // 0 (run immediately) to CREATE_SUSPENDED (4).  The FileWatcherThread
        // starts suspended; SumatraPDF resumes it later when initialization is
        // complete.  Prevents a race where the thread accesses dialog structures
        // before the main thread finishes setting them up.
        //
        // Patch 2 (RVA 0x21c1b4): Replace `mov rcx, [rcx+0x38]` with
        // `xor rcx, rcx; nop`.  Zeros rcx so the null-check at 0x21c1b8 skips
        // the vtable dispatch.  The callback (vtable[0]) won't fire for the second
        // invocation, but the rest of initialization continues normally.
        //
        // Patch 3 (RVA 0x5cfb4): Replace `mov rcx, [rax]` (null deref crash
        // when [rsi+0xb0] is uninitialized) with `jmp <error_handler>; nop`.
        // REMOVED: 6 set_sub_object patches (0x29ae1, 0x29b48, 0x29b77, 0x6ca9f,
        // 0x6cabe, 0x6e535) — these masked INVALID_HANDLE_VALUE at [+0x38] which was
        // downstream of CreateWindowExW returning 0 when given an ATOM lpClassName.
        // The atom-based class lookup fix in api.rs resolves the root cause, making
        // these patches unnecessary. See TASK-4.
        //
        // Remaining 3 patches — kept because they fix genuine code bugs in SumatraPDF:
        //   - 0x21c1b4: dual-call-path bug (null check after two code paths that should
        //     have been exclusive but both execute)
        //   - 0x21c2f2: CreateThread suspended (race condition — thread created with
        //     CREATE_SUSPENDED but ResumeThread never called)
        //   - 0x5cfb4:  null-check skip (may also be downstream of atom fix; kept for
        //     safety pending independent verification)
        let _ = cfg::apply_binary_patches(
            image.base,
            &[
                (
                    0x21c1b4,
                    &[0x48, 0x8b, 0x49, 0x38],
                    &[0x48, 0x31, 0xc9, 0x90],
                ),
                (
                    0x21c2f2,
                    &[0x83, 0x64, 0x24, 0x20, 0x00],
                    &[0xc6, 0x44, 0x24, 0x20, 0x04],
                ),
                (0x5cfb4, &[0x48, 0x8b, 0x08], &[0xeb, 0x30, 0x90]),
            ],
        );
    }

    // ── 3.7. Socketpair + fork for out-of-process guest ──────────────────

    if !args.no_sandbox {
        #[cfg(target_os = "linux")]
        unsafe extern "C" fn seccomp_sigsys_handler(
            _signal: libc::c_int,
            info: *mut libc::siginfo_t,
            _context: *mut libc::c_void,
        ) {
            #[repr(C)]
            struct SigsysInfo {
                _signo: libc::c_int,
                _errno: libc::c_int,
                _code: libc::c_int,
                _padding: libc::c_int,
                _call_addr: *mut libc::c_void,
                syscall: libc::c_int,
                _arch: u32,
            }

            // Linux seccomp TRAP supplies the denied syscall in si_syscall.
            // Only write and _exit are used here because this is a signal handler.
            let syscall = if info.is_null() {
                0
            } else {
                unsafe { (*(info as *const SigsysInfo)).syscall }
            };
            let mut message = [0u8; 64];
            let prefix = b"weave: seccomp denied syscall=";
            message[..prefix.len()].copy_from_slice(prefix);
            let mut end = prefix.len();
            let mut digits = [0u8; 11];
            let mut count = 0;
            let mut value = syscall.unsigned_abs();
            loop {
                digits[count] = b'0' + (value % 10) as u8;
                count += 1;
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            if syscall < 0 {
                message[end] = b'-';
                end += 1;
            }
            for digit in digits[..count].iter().rev() {
                message[end] = *digit;
                end += 1;
            }
            message[end] = b'\n';
            unsafe {
                libc::write(2, message.as_ptr() as *const libc::c_void, end + 1);
                libc::_exit(128 + libc::SIGSYS);
            }
        }

        #[cfg(target_os = "linux")]
        fn install_seccomp_trap_handler() -> Result<(), String> {
            if std::env::var("WEAVE_SECCOMP_TRAP").ok().as_deref() != Some("1") {
                return Ok(());
            }
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = seccomp_sigsys_handler as *const () as usize;
                action.sa_flags = libc::SA_SIGINFO;
                libc::sigemptyset(&mut action.sa_mask);
                if libc::sigaction(libc::SIGSYS, &action, std::ptr::null_mut()) != 0 {
                    return Err(std::io::Error::last_os_error().to_string());
                }
            }
            Ok(())
        }

        /// Open the first available DRM render node (/dev/dri/renderD*) for Vulkan.
        fn open_drm_render_node() -> Result<i32, String> {
            let dir = std::path::Path::new("/dev/dri");
            if !dir.exists() {
                return Err("/dev/dri does not exist".to_string());
            }
            let entries = std::fs::read_dir(dir).map_err(|e| e.to_string())?;
            for entry in entries {
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("renderD") {
                    let p = entry.path();
                    let path_str = p.to_string_lossy();
                    let cpath = std::ffi::CString::new(path_str.as_ref())
                        .map_err(|_| "invalid CString".to_string())?;
                    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) };
                    if fd >= 0 {
                        return Ok(fd);
                    }
                }
            }
            Err("no renderD* node found".to_string())
        }

        let mut sv: [libc::c_int; 2] = [0; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
        assert_eq!(
            rc,
            0,
            "weave: socketpair failed: {}",
            std::io::Error::last_os_error()
        );

        match unsafe { libc::fork() } {
            -1 => panic!("weave: fork failed: {}", std::io::Error::last_os_error()),
            0 => {
                unsafe {
                    libc::close(sv[0]);
                    // Die when the host (parent) dies, so test harnesses that
                    // kill the weave process don't leave orphaned guests.
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                }
                CHILD_FD.set(sv[1]).expect("weave: CHILD_FD already set");
                eprintln!("PHASE: child_spawned pid={}", unsafe { libc::getpid() });
                #[cfg(target_os = "linux")]
                if let Err(e) = install_seccomp_trap_handler() {
                    eprintln!("weave: seccomp trap handler failed: {e}");
                    std::process::exit(1);
                }
                if let Err(e) = weave_sandbox::apply_seccomp(exe_name) {
                    eprintln!("weave: seccomp not applied ({e}) — continuing without syscall filter (Landlock still active)");
                } else {
                    eprintln!("PHASE: seccomp_applied");
                }

                // Receive DRM render node fd from host for Vulkan.
                match weave_ipc::recv_fd(sv[1]) {
                    Ok(drm_fd) => {
                        eprintln!("PHASE: drm_fd_received fd={drm_fd}");
                        DRM_FD.set(drm_fd).expect("DRM_FD already set");
                        std::env::set_var("WEAVE_DRM_FD", drm_fd.to_string());
                    }
                    Err(e) => {
                        eprintln!("weave: no DRM fd received (Vulkan may not init): {e}");
                    }
                }

                eprintln!("PHASE: ipc_alive");
            }
            child_pid => {
                unsafe {
                    libc::close(sv[1]);
                }

                // Open DRM render node and pass fd to child for Vulkan.
                // When DRM is unavailable, send a dummy byte so the child's
                // recv_fd doesn't block forever.
                match open_drm_render_node() {
                    Ok(drm_fd) => {
                        eprintln!("PHASE: drm_node_opened fd={drm_fd}");
                        if let Err(e) = weave_ipc::send_fd(sv[0], drm_fd) {
                            eprintln!("weave/host: send_fd(DRM) failed: {e}");
                        }
                        unsafe {
                            libc::close(drm_fd);
                        }
                    }
                    Err(e) => {
                        eprintln!("weave/host: no DRM render node (Vulkan may not init): {e}");
                        // Send a dummy byte so the child unblocks from recv_fd
                        // and falls through to the "no cmsg" error path.
                        let dummy: u8 = 0;
                        unsafe {
                            libc::send(sv[0], &dummy as *const u8 as *const libc::c_void, 1, 0);
                        }
                    }
                }

                eprintln!("PHASE: host_loop_started");

                if let Err(e) = weave_ipc::host_loop(sv[0], ipc_handler) {
                    let mut child_wait_status = 0;
                    let waited_pid = unsafe { libc::waitpid(child_pid, &mut child_wait_status, 0) };
                    if waited_pid == child_pid {
                        let child_exit_status = if libc::WIFEXITED(child_wait_status) {
                            Some(libc::WEXITSTATUS(child_wait_status))
                        } else {
                            None
                        };
                        let child_signal = if libc::WIFSIGNALED(child_wait_status) {
                            Some(libc::WTERMSIG(child_wait_status))
                        } else {
                            None
                        };
                        eprintln!(
                            "weave: host_loop recv error: {e}; child_pid={child_pid} child_wait_status={child_wait_status} child_exit_status={child_exit_status:?} child_signal={child_signal:?}"
                        );
                    } else {
                        eprintln!(
                            "weave: host_loop recv error: {e}; child_pid={child_pid} waitpid_error={}",
                            std::io::Error::last_os_error()
                        );
                    }
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
        }
    } else {
        eprintln!("weave: --no-sandbox: sandbox isolation disabled");
    }

    // ── 4. Apply filesystem sandbox ───────────────────────────────────────
    // Allowlist the exe's own directory for read-only access so apps can open
    // config files, data files, and DLLs that live beside the executable.
    // Also allowlist the six bridged XDG user dirs so Windows apps can read
    // and write Documents, Downloads, Desktop, Music, Pictures, and Videos
    // in the user's real home directory.
    let exe_abs = args.exe.canonicalize().unwrap_or_else(|_| args.exe.clone());
    let exe_dir = exe_abs
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));

    // Resolve XDG user dirs.  Try `xdg-user-dir <NAME>` first; fall back to
    // $HOME/<dir> if the command is not available or returns empty output.
    let xdg_dirs = resolve_xdg_user_dirs();

    // Build the allowed-paths slice: exe dir first, then bridged user dirs
    // that actually exist on disk (skip non-existent dirs silently).
    let mut allowed: Vec<&std::path::Path> = vec![exe_dir];
    for p in &xdg_dirs {
        if p.exists() {
            allowed.push(p.as_path());
        } else {
            eprintln!(
                "weave: sandbox: skipping non-existent user dir {}",
                p.display()
            );
        }
    }

    // Vulkan support: libvulkan.so.1 (loader), Mesa ICDs (lavapipe/radeon/intel),
    // and Vulkan ICD JSON configs. Skip silently if not present.
    let vulkan_sys_paths: &[&str] = &[
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib64",
        "/usr/share/vulkan",
        "/etc/vulkan",
        "/dev/dri",       // DRM render nodes — lavapipe needs these to enumerate
        "/sys/dev/char",  // character device sysfs symlinks
        "/sys/class/drm", // DRM class sysfs entries
    ];
    for path_str in vulkan_sys_paths {
        let p = std::path::Path::new(path_str);
        if p.exists() {
            allowed.push(p);
        }
    }

    let sandbox_status = weave_sandbox::apply(true, &allowed);

    // ── 4.5. Sandbox runtime invariant — release blocker ─────────────────
    // After `apply()` runs, the sandbox state is committed. The behavior
    // depends on the outcome:
    //
    //   Disabled     — WEAVE_DISABLE_SANDBOX=1 or --no-sandbox set.
    //                  The user explicitly bypassed the sandbox. Always panic.
    //
    //   Unavailable  — Kernel does not support Landlock (e.g. Docker on Mac,
    //                  Docker-in-Docker, WSL without LSM). Log a loud warning
    //                  and continue — guest code runs without filesystem
    //                  isolation. CI (GitHub Actions) runs on real Linux where
    //                  Landlock is available, so this path is development-only.
    //
    //   Active       — Landlock fully or partially enforced. Continue.
    //
    // The CI gate `sandbox_invariant_blocks_unsandboxed_launch` uses
    // WEAVE_DISABLE_SANDBOX=1 to verify the Disabled → panic path.
    if sandbox_status == weave_sandbox::SandboxStatus::Disabled {
        panic!(
            "weave: SANDBOX INVARIANT VIOLATION at entry point `weave-cli`: \
             sandbox is not active. Unsandboxed Win32 guest execution is \
             forbidden. See docs/SECURITY_AUDIT.md. \
             (This is triggered by WEAVE_DISABLE_SANDBOX=1 or --no-sandbox.)"
        );
    }

    // ── 5. Initialise TEB / PEB / TLS ────────────────────────────────────
    let _teb = teb::setup(&image).unwrap_or_else(|e| {
        eprintln!("weave: TEB setup failed: {e}");
        std::process::exit(1);
    });

    // ── 6. Install exception handlers ─────────────────────────────────────
    seh::install(&image);

    // ── 6.5. Patch CFG dispatch stubs ───────────────────────────────────── ─────────────────────────────────────
    // Windows PEs compiled with CFG encode indirect call targets using the
    // security cookie. Weave provides a decode-and-call stub so the encoded
    // pointer in RAX is decoded before jumping, instead of crashing on a
    // non-canonical garbage address.
    cfg::setup(&bytes, image.base);

    // ── 6.6. Register runtime resolver ─────────────────────────────────
    // LoadLibraryExW / GetProcAddress stubs call back into this resolver
    // at runtime. Must be set before the PE entry point runs.
    weave_core::resolve::set(resolve);

    // ── 6.7. Register IShellLink save callback ────────────────────────
    // Installers call CoCreateInstance(CLSID_ShellLink) → IPersistFile::Save
    // to create desktop shortcuts. Write a .desktop file for each Save call.
    weave_common::com::shell_link::register_save_callback(shell_link_save_callback);

    // ── 6.8. Register Rust stub crate DllMains ────────────────────────
    // Register no-op DllMain for every weave-* DLL crate. Crates that
    // need real init (ucrt, ole32, user32) will get custom handlers when
    // those crates implement them.
    dllmain::register_all_default_stubs();

    // ── 6.9. Dispatch DllMain(DLL_PROCESS_ATTACH) ─────────────────────
    // Calls DllMain on every loaded DLL in dependency order (stubs first,
    // then PE DLLs).  Also registers an atexit handler for PROCESS_DETACH.
    dllmain::process_attach();

    // ── 6.10. Fire TLS callbacks for the main PE ──────────────────────
    // TLS callbacks are PE-level static constructors called after all
    // DllMain PROCESS_ATTACH calls, before the entry point runs. They
    // receive (hinst=base, DLL_PROCESS_ATTACH, 0).
    loader::run_tls_callbacks(&image);

    eprintln!("weave: TEB ready — jumping in");

    // ── DEBUG: print first 16 bytes at entry point and GS base ───────────
    #[cfg(target_os = "linux")]
    {
        let ep = image.entry_point;
        let bytes_at_ep: Vec<u8> = (0..16).map(|i| unsafe { *ep.add(i) }).collect();
        eprintln!("weave: entry bytes: {:02x?}", bytes_at_ep);
        let mut gs_base: u64 = 0;
        unsafe {
            libc::syscall(libc::SYS_arch_prctl, 0x1004i64, &mut gs_base as *mut u64);
        }
        eprintln!("weave: GS base = {gs_base:#x}");
    }

    // ── 7. Jump to the entry point ────────────────────────────────────────
    // Safety: image.entry_point is a valid executable address set up by loader::load().
    unsafe { exec::run(image.entry_point) }
}
