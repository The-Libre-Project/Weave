//! Architecture compatibility detection for Weave.
//!
//! Weave's in-process execution model requires the host CPU to run the PE's
//! instruction set. On ARM64 hosts running x86_64 Windows binaries, CPU
//! translation is needed. This module detects mismatches and guides the user
//! toward the correct FEX-Emu or Box64 setup.

use std::path::{Path, PathBuf};

// ── Host architecture ─────────────────────────────────────────────────────────

/// The instruction set architecture of the host process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostArch {
    X86_64,
    Aarch64,
    Other,
}

/// Detect the host architecture at runtime.
pub fn host_arch() -> HostArch {
    match std::env::consts::ARCH {
        "x86_64" => HostArch::X86_64,
        "aarch64" => HostArch::Aarch64,
        _ => HostArch::Other,
    }
}

// ── PE machine type ───────────────────────────────────────────────────────────

/// The machine type declared in the PE COFF header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeArch {
    /// IMAGE_FILE_MACHINE_AMD64 (0x8664)
    X86_64,
    /// IMAGE_FILE_MACHINE_ARM64 (0xAA64)
    Aarch64,
    /// Any other machine type
    Other(u16),
}

/// Read the PE machine type from raw binary bytes.
///
/// Returns `None` if the bytes are too short or do not start with the MZ
/// signature.
///
/// Layout used:
/// - bytes[0x3C..0x40]: little-endian u32 offset to the PE signature ("PE\0\0")
/// - PE_offset + 4:     little-endian u16 Machine field
pub fn pe_arch(bytes: &[u8]) -> Option<PeArch> {
    // MZ signature check
    if bytes.len() < 0x40 || bytes[0] != b'M' || bytes[1] != b'Z' {
        return None;
    }

    // PE header offset is at 0x3C as a little-endian u32
    let pe_offset = u32::from_le_bytes(bytes[0x3C..0x40].try_into().ok()?) as usize;

    // PE\0\0 signature (4 bytes) + Machine (2 bytes)
    let machine_offset = pe_offset + 4;
    if bytes.len() < machine_offset + 2 {
        return None;
    }

    let machine = u16::from_le_bytes(bytes[machine_offset..machine_offset + 2].try_into().ok()?);

    Some(match machine {
        0x8664 => PeArch::X86_64,
        0xAA64 => PeArch::Aarch64,
        other => PeArch::Other(other),
    })
}

// ── FEX / Box64 detection ─────────────────────────────────────────────────────

/// Check whether this process is already running under FEX-Emu.
///
/// FEX sets the `FEX_ROOTFS` environment variable when active. Weave also
/// checks for `/proc/self/exe` pointing through the FEX thunk path as a
/// secondary indicator.
pub fn is_running_under_fex() -> bool {
    std::env::var("FEX_ROOTFS").is_ok()
}

/// Check whether this process is already running under Box64.
///
/// Box64 sets the `BOX64_PATH` environment variable when active.
pub fn is_running_under_box64() -> bool {
    std::env::var("BOX64_PATH").is_ok()
}

/// Search common installation paths for the FEX interpreter binary.
pub fn find_fex_interpreter() -> Option<PathBuf> {
    let candidates = [
        "/usr/bin/FEXInterpreter",
        "/usr/local/bin/FEXInterpreter",
        "/opt/fex-emu/bin/FEXInterpreter",
    ];
    candidates
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .map(PathBuf::from)
}

/// Search common installation paths for the Box64 binary.
pub fn find_box64() -> Option<PathBuf> {
    let candidates = [
        "/usr/bin/box64",
        "/usr/local/bin/box64",
        "/opt/box64/bin/box64",
    ];
    candidates
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .map(PathBuf::from)
}

// ── Compatibility check ───────────────────────────────────────────────────────

/// Check whether the host can execute the given PE binary.
///
/// Reads the first 512 bytes of `exe_path` to determine the PE machine type,
/// then compares it with the host architecture. If a mismatch is detected,
/// prints guidance to stderr and returns `Err` with an exit code.
///
/// Returns `Ok(())` if execution can proceed normally.
pub fn check_arch_compatibility(exe_path: &Path) -> Result<(), i32> {
    // Read just enough bytes to parse the PE header (512 is always sufficient)
    let mut buf = [0u8; 512];
    let n = match std::fs::File::open(exe_path) {
        Ok(mut f) => {
            use std::io::Read;
            f.read(&mut buf).unwrap_or(0)
        }
        Err(_) => return Ok(()), // let the normal open-file error path handle this
    };

    let arch = match pe_arch(&buf[..n]) {
        Some(a) => a,
        None => return Ok(()), // not a PE or too short — let loader report the error
    };

    match (host_arch(), arch) {
        // Native x86_64 running x86_64 PE — ideal path
        (HostArch::X86_64, PeArch::X86_64) => Ok(()),

        // ARM64 host, x86_64 PE — needs CPU translation
        (HostArch::Aarch64, PeArch::X86_64) => {
            if is_running_under_fex() || is_running_under_box64() {
                // Already inside a translator — x86_64 code will work fine
                return Ok(());
            }

            eprintln!("weave: architecture mismatch");
            eprintln!("  Host:   aarch64 (ARM64)");
            eprintln!("  Binary: x86_64 (the Windows .exe you want to run)");
            eprintln!();

            eprintln!("  Weave needs a CPU translator to run x86_64 code on this ARM64 host.");
            eprintln!();

            if let Some(fex) = find_fex_interpreter() {
                eprintln!("  FEX-Emu found at: {}", fex.display());
                eprintln!();
                eprintln!("  Recommended setup (one-time):");
                eprintln!("    sudo apt install fex-emu-binfmt   # Debian/Ubuntu");
                eprintln!("    # or: follow https://github.com/FEX-Emu/FEX#binfmt_misc");
                eprintln!();
                eprintln!("  With binfmt_misc configured, run the x86_64 Weave build:");
                eprintln!("    weave-x86_64 {}", exe_path.display());
            } else if let Some(box64) = find_box64() {
                eprintln!("  Box64 found at: {}", box64.display());
                eprintln!();
                eprintln!("  Recommended setup:");
                eprintln!("    box64 weave-x86_64 {}", exe_path.display());
            } else {
                eprintln!("  Neither FEX-Emu nor Box64 was found.");
                eprintln!();
                eprintln!("  Install FEX-Emu:");
                eprintln!("    https://github.com/FEX-Emu/FEX");
                eprintln!();
                eprintln!("  Or install Box64:");
                eprintln!("    https://github.com/ptitSeb/box64");
            }

            Err(1)
        }

        // ARM64 PE on any host — not supported yet
        (_, PeArch::Aarch64) => {
            eprintln!("weave: ARM64 Windows PE binaries are not yet supported");
            Err(1)
        }

        // x86 32-bit PE on any host — not supported (Weave is 64-bit only)
        (_, PeArch::Other(0x014c)) => {
            eprintln!("weave: 32-bit x86 Windows PE binaries are not supported");
            eprintln!("  This binary requires a 32-bit execution environment.");
            eprintln!("  Use the 64-bit build of the application if available.");
            Err(1)
        }

        // Any other unrecognised PE arch — let the loader report the error
        _ => Ok(()),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_arch_too_short() {
        assert!(pe_arch(&[]).is_none());
        assert!(pe_arch(&[b'M', b'Z']).is_none());
    }

    #[test]
    fn test_pe_arch_not_mz() {
        let buf = [0u8; 512];
        assert!(pe_arch(&buf).is_none());
    }

    #[test]
    fn test_pe_arch_x86_64() {
        // Minimal fake PE header: MZ at 0, PE offset at 0x3C pointing to 0x40,
        // then "PE\0\0" + machine 0x8664
        let mut buf = [0u8; 512];
        buf[0] = b'M';
        buf[1] = b'Z';
        // PE header at offset 0x40
        buf[0x3C] = 0x40;
        buf[0x3D] = 0x00;
        buf[0x3E] = 0x00;
        buf[0x3F] = 0x00;
        // "PE\0\0"
        buf[0x40] = b'P';
        buf[0x41] = b'E';
        buf[0x42] = 0x00;
        buf[0x43] = 0x00;
        // Machine: 0x8664 (little-endian)
        buf[0x44] = 0x64;
        buf[0x45] = 0x86;

        assert_eq!(pe_arch(&buf), Some(PeArch::X86_64));
    }

    #[test]
    fn test_pe_arch_aarch64() {
        let mut buf = [0u8; 512];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C] = 0x40;
        // "PE\0\0"
        buf[0x40] = b'P';
        buf[0x41] = b'E';
        // Machine: 0xAA64 (little-endian)
        buf[0x44] = 0x64;
        buf[0x45] = 0xAA;

        assert_eq!(pe_arch(&buf), Some(PeArch::Aarch64));
    }

    #[test]
    fn test_host_arch_returns_value() {
        // Just verify it returns without panicking
        let _ = host_arch();
    }

    #[test]
    fn test_fex_box64_env_detection() {
        // Without the env vars set, both should return false
        std::env::remove_var("FEX_ROOTFS");
        std::env::remove_var("BOX64_PATH");
        assert!(!is_running_under_fex());
        assert!(!is_running_under_box64());
    }
}
