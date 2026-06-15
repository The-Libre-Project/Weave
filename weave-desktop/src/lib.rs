//! Desktop integration for Weave — `.desktop` file generation, xdg-mime handler
//! registration, and application menu management.

mod icon;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use image::ImageEncoder;

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

/// Extract the icon from a Windows `.exe` file and install it as a PNG
/// in the user's icons directory at `~/.local/share/icons/weave-{app_id}.png`.
///
/// Uses the `image` crate to convert the first 32bpp (or best-available)
/// icon entry from BGRA pixel data to a PNG file.
pub fn extract_and_install_png_icon(
    app_id: &str,
    exe_path: &Path,
) -> Result<Option<PathBuf>, DesktopError> {
    let exe_bytes = fs::read(exe_path)?;
    let Some(ico_bytes) = icon::extract_icon(&exe_bytes) else {
        return Ok(None);
    };
    let Some(png_bytes) = ico_to_png_bytes(&ico_bytes) else {
        return Ok(None);
    };
    let dir = icons_dir()?;
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("weave-{app_id}.png"));
    fs::write(&path, &png_bytes)?;
    Ok(Some(path))
}

/// Parse a self-contained `.ico` byte buffer and convert the best entry
/// (highest bit-depth, largest dimensions) to a standalone PNG.
///
/// Returns `None` if the buffer is not a valid `.ico` or if none of the
/// entries can be decoded.  Handles 32bpp (BGRA → RGBA) and 24bpp
/// (BGR → RGB) DIB data as well as embedded PNG entries.
fn ico_to_png_bytes(ico_data: &[u8]) -> Option<Vec<u8>> {
    if ico_data.len() < 6 {
        return None;
    }
    let count = u16::from_le_bytes([ico_data[4], ico_data[5]]) as usize;
    if count == 0 || ico_data.len() < 6 + count * 16 {
        return None;
    }

    // Gather ICONDIRENTRY records.
    let mut entries: Vec<(u8, u8, u16, u32, u32)> = Vec::with_capacity(count);
    for i in 0..count {
        let base = 6 + i * 16;
        let w = ico_data[base]; // 0 means 256
        let h = ico_data[base + 1];
        let bit_count = u16::from_le_bytes([ico_data[base + 6], ico_data[base + 7]]);
        let data_size = u32::from_le_bytes([
            ico_data[base + 8],
            ico_data[base + 9],
            ico_data[base + 10],
            ico_data[base + 11],
        ]);
        let offset = u32::from_le_bytes([
            ico_data[base + 12],
            ico_data[base + 13],
            ico_data[base + 14],
            ico_data[base + 15],
        ]);
        entries.push((w, h, bit_count, data_size, offset));
    }

    // Prefer highest bit_count, then largest area.
    entries.sort_by(|a, b| {
        b.2.cmp(&a.2).then_with(|| {
            let area_a = (if a.0 == 0 { 256u32 } else { a.0 as u32 })
                * (if a.1 == 0 { 256u32 } else { a.1 as u32 });
            let area_b = (if b.0 == 0 { 256u32 } else { b.0 as u32 })
                * (if b.1 == 0 { 256u32 } else { b.1 as u32 });
            area_b.cmp(&area_a)
        })
    });

    let best = &entries[0];
    let data_start = best.3 as usize;
    let data_end = data_start + best.4 as usize;
    let raw = ico_data.get(data_start..data_end)?;

    // Embedded PNG — write directly.
    if raw.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some(raw.to_vec());
    }

    // DIB / BMP pixel data — must parse BITMAPINFOHEADER.
    if raw.len() < 40 {
        return None;
    }
    let dib_size = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    if dib_size < 40 {
        return None;
    }
    let width = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let full_height = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
    let bpp = u16::from_le_bytes([raw[14], raw[15]]);

    // In ICO files, full_height = XOR height + AND mask height.
    let actual_height = full_height / 2;

    match bpp {
        32 => {
            let row_size = width as usize * 4;
            let pixel_off = dib_size as usize;
            let mut rgba = Vec::with_capacity((width * actual_height * 4) as usize);
            for y in 0..actual_height {
                let row_start = pixel_off + y as usize * row_size;
                for x in 0..width as usize {
                    let pos = row_start + x * 4;
                    let b = raw.get(pos).copied().unwrap_or(0);
                    let g = raw.get(pos + 1).copied().unwrap_or(0);
                    let r = raw.get(pos + 2).copied().unwrap_or(0);
                    let a = raw.get(pos + 3).copied().unwrap_or(0);
                    rgba.extend_from_slice(&[r, g, b, a]);
                }
            }
            encode_rgba_to_png(&rgba, width, actual_height)
        }
        24 => {
            let stride = ((width as usize * 3) + 3) & !3;
            let pixel_off = dib_size as usize;
            let mut rgb = Vec::with_capacity((width * actual_height * 3) as usize);
            for y in 0..actual_height {
                let row_start = pixel_off + y as usize * stride;
                for x in 0..width as usize {
                    let pos = row_start + x * 3;
                    let b = raw.get(pos).copied().unwrap_or(0);
                    let g = raw.get(pos + 1).copied().unwrap_or(0);
                    let r = raw.get(pos + 2).copied().unwrap_or(0);
                    rgb.extend_from_slice(&[r, g, b]);
                }
            }
            encode_rgb_to_png(&rgb, width, actual_height)
        }
        _ => None,
    }
}

/// Encode 8-bit RGBA pixel data as a PNG in memory.
fn encode_rgba_to_png(data: &[u8], width: u32, height: u32) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    {
        use image::codecs::png::PngEncoder;
        use image::ExtendedColorType;
        let encoder = PngEncoder::new(&mut buf);
        encoder
            .write_image(data, width, height, ExtendedColorType::Rgba8)
            .ok()?;
    }
    Some(buf)
}

/// Encode 8-bit RGB pixel data as a PNG in memory.
fn encode_rgb_to_png(data: &[u8], width: u32, height: u32) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    {
        use image::codecs::png::PngEncoder;
        use image::ExtendedColorType;
        let encoder = PngEncoder::new(&mut buf);
        encoder
            .write_image(data, width, height, ExtendedColorType::Rgb8)
            .ok()?;
    }
    Some(buf)
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
         Terminal=false\n\
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
