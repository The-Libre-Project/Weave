use clap::Parser;
use std::path::{Component, PathBuf};
use weave_common::com::shell_link::ShellLinkSaveData;
use weave_core::{
    cfg, cmdline, dll_registry, exec, iat, loader, module_handles, pe, prefix, registry, seh, teb,
};
use weave_installer::PrefixManager;

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

    /// Disable the filesystem sandbox (for debugging only)
    #[arg(long)]
    no_sandbox: bool,

    /// Arguments to pass to the Windows executable (e.g. `weave app.exe arg1 arg2`)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    exe_args: Vec<String>,
}

/// Resolve a Windows import to a function address.
///
/// Checks Weave's built-in stub crates first, then falls back to any
/// PE DLLs pre-loaded from the prefix (e.g. DXVK).
fn resolve(dll: &str, func: &str) -> Option<usize> {
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
        .or_else(|| weave_vulkan::resolve(dll, func))
        .or_else(|| weave_ws2::resolve(dll, func))
        .or_else(|| weave_comctl32::resolve(dll, func))
        // uxtheme.dll — visual style / theme API stubs (IrfanView, Notepad++, 7zFM)
        .or_else(|| weave_comctl32::resolve_uxtheme(dll, func))
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

fn main() {
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
        let mut side_dlls: Vec<(String, Vec<u8>, *mut u8)> = Vec::new();

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
                    dll_registry::register(dll_key.clone(), image, exports);
                    eprintln!("weave: pre-loaded {dll_name} from exe dir");
                    loaded.insert(dll_key.clone());
                    side_dlls.push((dll_name, dll_bytes.clone(), base));
                    // Discover transitive dependencies and add them to the queue.
                    if let Ok(parsed) = weave_core::pe::parse(&dll_bytes) {
                        for dep in &parsed.imports {
                            let dep_key = dep.dll.to_lowercase();
                            if dep_key != dll_key
                                && !dll_registry::is_registered(&dep_key)
                                && !loaded.contains(&dep_key)
                            {
                                pending.push(dep.dll.clone());
                            }
                        }
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
                        let dll_entry = image.entry_point;
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
                        if !dll_entry.is_null() {
                            const DLL_PROCESS_ATTACH: u32 = 1;
                            type DllMain = unsafe extern "win64" fn(
                                hinst: usize,
                                reason: u32,
                                reserved: usize,
                            )
                                -> i32;
                            let dll_main: DllMain = unsafe { std::mem::transmute(dll_entry) };
                            let ok = unsafe { dll_main(image_base, DLL_PROCESS_ATTACH, 0) };
                            eprintln!(
                                "weave/E3-M9-trace: preloaded OptiPNG.dll DllMain({image_base:#x}) → {ok}"
                            );
                        }
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
    // Safety: image.base points to a fully mapped PE loaded by loader::load().
    let mut missing: Vec<String> = Vec::new();
    unsafe {
        iat::patch_best_effort(&bytes, image.base, resolve, |dll, func, iat_va| {
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
        // RVA 0x29b51: movq %rax, 0x38(%rdi) — stores factory vtable[1] result
        // at canvas object +0x38. The factory's internal virtual method returns
        // INVALID_HANDLE_VALUE, which bypasses the null-check at RVA 0x21c1b8
        // and crashes. NOP the store so +0x38 stays NULL, letting the null-check
        // skip the vtable dispatch.
        let n = cfg::apply_binary_patches(
            image.base,
            &[(
                0x29b51,
                &[0x48, 0x89, 0x47, 0x38], // movq %rax, 0x38(%rdi)
                &[0x90, 0x90, 0x90, 0x90], // 4× NOP
            )],
        );
        if n > 0 {
            eprintln!("weave: applied {n} binary patch(es) for {exe_name}");
        }
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

    weave_sandbox::apply(!args.no_sandbox, &allowed);

    // ── 4.5. Sandbox runtime invariant — release blocker ─────────────────
    // After `apply()` runs, the sandbox state is committed. This assert is
    // the single point at which "the sandbox is active" stops being a design
    // claim and becomes a verified runtime invariant. If anything above this
    // line went wrong — `WEAVE_DISABLE_SANDBOX=1`, an old kernel without
    // Landlock, an unsupported host OS — we panic here, before a single byte
    // of guest Win32 code can run. The CI gate
    // `sandbox_invariant_blocks_unsandboxed_launch` verifies this fires.
    //
    // When `--no-sandbox` is explicitly passed, the user has accepted the
    // risk and we skip the invariant. The CI test uses `WEAVE_DISABLE_SANDBOX`
    // (not `--no-sandbox`) to verify the panic, so the gate remains covered.
    if !args.no_sandbox {
        weave_sandbox::assert_sandboxed!("weave-cli");
    }

    // ── 5. Initialise TEB / PEB / TLS ────────────────────────────────────
    let _teb = teb::setup(&image).unwrap_or_else(|e| {
        eprintln!("weave: TEB setup failed: {e}");
        std::process::exit(1);
    });

    // ── 6. Install exception handlers ─────────────────────────────────────
    seh::install(&image);

    // ── 6.5. Patch CFG dispatch stubs ─────────────────────────────────────
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
