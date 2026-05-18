// Win32 INI file read/write — GetPrivateProfileString*, WritePrivateProfileString*, etc.
//
// Wine ref: dlls/kernel32/profile.c — PROFILE_Load/Save/Open/FlushFile, PROFILE_GetString,
// PROFILE_SetString. This is an independent Rust implementation of the same behavioral
// contract; no Wine source is copied.
//
// Design:
//   • Process-global cache: Mutex<HashMap<canonical-linux-path, IniFile>>
//   • On first access per path: parse the file from disk (if it exists)
//   • On write: update the in-memory tree and flush to disk immediately
//   • Section/key lookup is case-insensitive (ASCII fold only — matches Windows behavior)
//   • Encoding detection: UTF-16LE BOM → decode; UTF-8 BOM → strip; else ANSI/UTF-8 lossy

use std::collections::HashMap;
use std::io::Write as _;
use std::sync::{Mutex, OnceLock};

static CACHE: OnceLock<Mutex<HashMap<String, IniFile>>> = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<String, IniFile>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

struct IniFile {
    sections: Vec<IniSection>,
}

struct IniSection {
    name: String,
    entries: Vec<(String, String)>,
}

// ── Parsing ───────────────────────────────────────────────────────────────────

fn decode_bytes(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&u16s).to_owned();
    }
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&u16s).to_owned();
    }
    let data = if bytes.len() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
        &bytes[3..]
    } else {
        bytes
    };
    String::from_utf8_lossy(data).into_owned()
}

fn parse(text: &str) -> IniFile {
    let mut sections: Vec<IniSection> = Vec::new();
    let mut cur = IniSection {
        name: String::new(),
        entries: Vec::new(),
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            if let Some(end) = line.rfind(']') {
                let prev = std::mem::replace(
                    &mut cur,
                    IniSection {
                        name: line[1..end].trim().to_owned(),
                        entries: Vec::new(),
                    },
                );
                sections.push(prev);
            }
        } else if let Some(eq) = line.find('=') {
            let key = line[..eq].trim_end().to_owned();
            let val = line[eq + 1..].to_owned();
            cur.entries.push((key, val));
        }
    }
    sections.push(cur);
    IniFile { sections }
}

fn load(path: &str) -> IniFile {
    match std::fs::read(path) {
        Ok(bytes) => parse(&decode_bytes(&bytes)),
        Err(_) => IniFile {
            sections: Vec::new(),
        },
    }
}

// ── Serialization ─────────────────────────────────────────────────────────────

fn save(path: &str, ini: &IniFile) {
    let mut buf = Vec::<u8>::new();
    let mut first = true;
    for section in &ini.sections {
        if !section.name.is_empty() {
            if !first {
                let _ = buf.write_all(b"\r\n");
            }
            let _ = write!(buf, "[{}]\r\n", section.name);
            first = false;
        } else {
            first = false;
        }
        for (k, v) in &section.entries {
            let _ = write!(buf, "{}={}\r\n", k, v);
        }
    }
    let _ = std::fs::write(path, &buf);
}

// ── Case-insensitive helpers ──────────────────────────────────────────────────

fn eq_ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn find_section<'a>(ini: &'a IniFile, section: &str) -> Option<&'a IniSection> {
    ini.sections.iter().find(|s| eq_ci(&s.name, section))
}

fn find_section_mut<'a>(ini: &'a mut IniFile, section: &str) -> Option<&'a mut IniSection> {
    ini.sections.iter_mut().find(|s| eq_ci(&s.name, section))
}

fn find_entry<'a>(sec: &'a IniSection, key: &str) -> Option<&'a str> {
    sec.entries
        .iter()
        .find(|(k, _)| eq_ci(k, key))
        .map(|(_, v)| v.as_str())
}

// ── Public API ────────────────────────────────────────────────────────────────

/// GetPrivateProfileStringW core — returns the value for section/key, or default.
///
/// `linux_path` — canonical Linux path to the .ini file; None means use defaults.
pub fn get_string(linux_path: Option<&str>, section: &str, key: &str, default: &str) -> String {
    let Some(path) = linux_path else {
        return default.to_owned();
    };
    let mut guard = cache().lock().unwrap_or_else(|e| e.into_inner());
    if !guard.contains_key(path) {
        let ini = load(path);
        guard.insert(path.to_owned(), ini);
    }
    let ini = guard.get(path).unwrap();
    find_section(ini, section)
        .and_then(|s| find_entry(s, key))
        .unwrap_or(default)
        .to_owned()
}

/// Return all key names in a section, NUL-separated (for lp_key_name == NULL path).
pub fn get_section_keys(linux_path: Option<&str>, section: &str) -> Vec<String> {
    let Some(path) = linux_path else {
        return Vec::new();
    };
    let mut guard = cache().lock().unwrap_or_else(|e| e.into_inner());
    if !guard.contains_key(path) {
        guard.insert(path.to_owned(), load(path));
    }
    let ini = guard.get(path).unwrap();
    match find_section(ini, section) {
        Some(s) => s.entries.iter().map(|(k, _)| k.clone()).collect(),
        None => Vec::new(),
    }
}

/// Return all section names (for lp_app_name == NULL path).
pub fn get_section_names(linux_path: Option<&str>) -> Vec<String> {
    let Some(path) = linux_path else {
        return Vec::new();
    };
    let mut guard = cache().lock().unwrap_or_else(|e| e.into_inner());
    if !guard.contains_key(path) {
        guard.insert(path.to_owned(), load(path));
    }
    let ini = guard.get(path).unwrap();
    ini.sections
        .iter()
        .filter(|s| !s.name.is_empty())
        .map(|s| s.name.clone())
        .collect()
}

/// GetPrivateProfileIntW core — parses the stored string as an integer.
pub fn get_int(linux_path: Option<&str>, section: &str, key: &str, default: i32) -> i32 {
    let val = get_string(linux_path, section, key, "");
    if val.is_empty() {
        return default;
    }
    let s = val.trim();
    // Wine: supports decimal and 0x/0X hex prefix
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i32::from_str_radix(hex, 16).unwrap_or(default)
    } else {
        s.parse::<i32>().unwrap_or(default)
    }
}

/// WritePrivateProfileStringW core.
///
/// `value == None` → delete the key. Returns TRUE on success.
pub fn set_string(linux_path: Option<&str>, section: &str, key: &str, value: Option<&str>) -> bool {
    let Some(path) = linux_path else { return false };
    let mut guard = cache().lock().unwrap_or_else(|e| e.into_inner());
    if !guard.contains_key(path) {
        guard.insert(path.to_owned(), load(path));
    }
    let ini = guard.get_mut(path).unwrap();

    if let Some(val) = value {
        // Set or create the key
        if let Some(sec) = find_section_mut(ini, section) {
            if let Some(entry) = sec.entries.iter_mut().find(|(k, _)| eq_ci(k, key)) {
                entry.1 = val.to_owned();
            } else {
                sec.entries.push((key.to_owned(), val.to_owned()));
            }
        } else {
            ini.sections.push(IniSection {
                name: section.to_owned(),
                entries: vec![(key.to_owned(), val.to_owned())],
            });
        }
    } else {
        // Delete the key (or section if key is empty)
        if key.is_empty() {
            ini.sections.retain(|s| !eq_ci(&s.name, section));
        } else if let Some(sec) = find_section_mut(ini, section) {
            sec.entries.retain(|(k, _)| !eq_ci(k, key));
        }
    }
    save(path, ini);
    true
}

/// WritePrivateProfileSectionW core — replace the entire section with new key=value lines.
pub fn set_section(
    linux_path: Option<&str>,
    section: &str,
    entries: Vec<(String, String)>,
) -> bool {
    let Some(path) = linux_path else { return false };
    let mut guard = cache().lock().unwrap_or_else(|e| e.into_inner());
    if !guard.contains_key(path) {
        guard.insert(path.to_owned(), load(path));
    }
    let ini = guard.get_mut(path).unwrap();
    if let Some(sec) = find_section_mut(ini, section) {
        sec.entries = entries;
    } else {
        ini.sections.push(IniSection {
            name: section.to_owned(),
            entries,
        });
    }
    save(path, ini);
    true
}
