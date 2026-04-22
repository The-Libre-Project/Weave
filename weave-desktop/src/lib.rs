//! Desktop integration for Weave — `.desktop` file generation, xdg-mime handler
//! registration, and application menu management.

mod icon;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Errors returned by weave-desktop operations.
#[derive(Debug)]
pub enum DesktopError {
    Io(io::Error),
    /// The XDG tool (`xdg-mime`, `update-desktop-database`) was not found or
    /// returned a non-zero exit code.
    XdgTool(String),
    /// Could not determine the user's home directory or `XDG_DATA_HOME`.
    HomeNotFound,
}

impl From<io::Error> for DesktopError {
    fn from(e: io::Error) -> Self {
        DesktopError::Io(e)
    }
}

impl std::fmt::Display for DesktopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DesktopError::Io(e) => write!(f, "I/O error: {e}"),
            DesktopError::XdgTool(s) => write!(f, "XDG tool error: {s}"),
            DesktopError::HomeNotFound => write!(f, "could not determine home directory"),
        }
    }
}

/// Returns the directory where per-user icons are stored.
///
/// Uses `$XDG_DATA_HOME/icons` if set, otherwise `~/.local/share/icons`.
pub fn icons_dir() -> Result<PathBuf, DesktopError> {
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .map_err(|_| DesktopError::HomeNotFound)?;
    Ok(base.join("icons"))
}

/// Extract the icon from a Windows `.exe` file and install it as
/// `weave-{app_id}.ico` in the user's icons directory.
///
/// Returns `Ok(Some(path))` if an icon was extracted and written.
/// Returns `Ok(None)` if the file has no icon resources (not an error —
/// the caller should fall back to the default Weave icon).
/// Returns `Err` only on I/O failure after extraction succeeded.
pub fn extract_and_install_icon(
    app_id: &str,
    exe_path: &Path,
) -> Result<Option<PathBuf>, DesktopError> {
    let exe_bytes = fs::read(exe_path)?;
    let Some(ico_bytes) = icon::extract_icon(&exe_bytes) else {
        return Ok(None);
    };
    let dir = icons_dir()?;
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("weave-{app_id}.ico"));
    fs::write(&path, &ico_bytes)?;
    Ok(Some(path))
}

/// Returns the directory where `.desktop` files are installed for this user.
///
/// Uses `$XDG_DATA_HOME/applications` if set, otherwise `~/.local/share/applications`.
pub fn applications_dir() -> Result<PathBuf, DesktopError> {
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .map_err(|_| DesktopError::HomeNotFound)?;
    Ok(base.join("applications"))
}

/// Generates the textual content of a `.desktop` file for a Windows application.
///
/// # Parameters
/// - `app_name`: Display name shown in the application menu
/// - `exec_cmd`: Full launch command (e.g. `"weave run /path/to/app.exe"`)
/// - `icon_path`: Optional path to a PNG/SVG icon; `None` uses the `weave` icon
/// - `categories`: XDG category string (e.g. `"Game;"` or `"Utility;"`)
pub fn generate_desktop_file(
    app_name: &str,
    exec_cmd: &str,
    icon_path: Option<&Path>,
    categories: &str,
) -> String {
    let icon_line = match icon_path {
        Some(p) => format!("Icon={}", p.display()),
        None => "Icon=weave".to_string(),
    };
    format!(
        "[Desktop Entry]\n\
         Version=1.0\n\
         Type=Application\n\
         Name={app_name}\n\
         Exec={exec_cmd}\n\
         {icon_line}\n\
         Categories={categories}\n\
         StartupNotify=true\n\
         Comment=Windows application running via Weave\n"
    )
}

/// Installs a `.desktop` file into the user's applications directory.
///
/// Writes to `~/.local/share/applications/weave-{app_id}.desktop`.
/// `app_id` must be an ASCII identifier with no spaces (e.g. `"notepad"`).
/// Creates the directory if it does not exist.
pub fn install_desktop_file(app_id: &str, content: &str) -> Result<PathBuf, DesktopError> {
    let dir = applications_dir()?;
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("weave-{app_id}.desktop"));
    fs::write(&path, content)?;
    Ok(path)
}

/// Write a `.desktop` file into an arbitrary destination directory.
///
/// Unlike `install_desktop_file`, this function writes directly to `dest_dir`
/// rather than the user's `~/.local/share/applications`. Used by the
/// `IPersistFile::Save` callback to place shortcuts relative to a prefix.
///
/// The filename is derived from `name` by replacing characters that are illegal
/// in filenames (anything other than alphanumerics, `-`, `_`, `.`) with `-`.
pub fn write_shortcut(
    name: &str,
    exec_cmd: &str,
    icon_path: Option<&str>,
    dest_dir: &std::path::Path,
) -> Result<std::path::PathBuf, DesktopError> {
    let slug: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let filename = format!("{slug}.desktop");
    let dest = dest_dir.join(&filename);
    let icon_line = icon_path.map(|p| format!("Icon={p}\n")).unwrap_or_default();
    let content = format!(
        "[Desktop Entry]\nVersion=1.0\nType=Application\nName={name}\nExec={exec_cmd}\n{icon_line}Terminal=false\n"
    );
    fs::write(&dest, content)?;
    Ok(dest)
}

/// Removes a previously installed `.desktop` file.
///
/// Returns `Ok(())` even if the file did not exist.
pub fn uninstall_desktop_file(app_id: &str) -> Result<(), DesktopError> {
    let dir = applications_dir()?;
    let path = dir.join(format!("weave-{app_id}.desktop"));
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(DesktopError::Io(e)),
    }
}

/// Registers Weave as the default handler for `.exe` files via `xdg-mime`.
///
/// Requires `weave.desktop` to exist in the applications directory (the Weave
/// launcher itself). That file must declare
/// `MimeType=application/x-ms-dos-executable;`.
///
/// Returns `Ok(())` silently if `xdg-mime` is not installed — best-effort only.
pub fn register_exe_handler() -> Result<(), DesktopError> {
    let output = Command::new("xdg-mime")
        .args([
            "default",
            "weave.desktop",
            "application/x-ms-dos-executable",
        ])
        .output();
    match output {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => Err(DesktopError::XdgTool(
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(DesktopError::Io(e)),
    }
}

/// Notifies the desktop environment that new `.desktop` files have been installed.
///
/// Calls `update-desktop-database ~/.local/share/applications`.
/// Returns `Ok(())` silently if the tool is not installed.
pub fn update_desktop_database() -> Result<(), DesktopError> {
    let dir = applications_dir()?;
    let output = Command::new("update-desktop-database").arg(&dir).output();
    match output {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => Err(DesktopError::XdgTool(
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(DesktopError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_contains_name_and_exec() {
        let content =
            generate_desktop_file("Notepad", "weave run /apps/notepad.exe", None, "Utility;");
        assert!(content.contains("Name=Notepad"));
        assert!(content.contains("Exec=weave run /apps/notepad.exe"));
        assert!(content.contains("Categories=Utility;"));
        assert!(content.contains("Icon=weave"));
    }

    #[test]
    fn test_generate_with_custom_icon() {
        let icon = Path::new("/usr/share/icons/notepad.png");
        let content = generate_desktop_file(
            "Notepad",
            "weave run /apps/notepad.exe",
            Some(icon),
            "Utility;",
        );
        assert!(content.contains("Icon=/usr/share/icons/notepad.png"));
    }

    #[test]
    fn test_generate_desktop_entry_header() {
        let content = generate_desktop_file("App", "weave run /app.exe", None, "Game;");
        assert!(content.starts_with("[Desktop Entry]\n"));
        assert!(content.contains("Type=Application\n"));
        assert!(content.contains("Version=1.0\n"));
    }

    #[test]
    fn test_uninstall_nonexistent_is_ok() {
        let result = uninstall_desktop_file("weave-test-nonexistent-xyzzy-99999");
        assert!(result.is_ok());
    }
}
