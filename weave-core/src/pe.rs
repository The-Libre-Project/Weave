use goblin::pe::PE;

/// A section of the PE binary — a named chunk of memory with specific permissions.
#[derive(Debug)]
pub struct Section {
    pub name: String,
    /// Address where this section will live once loaded (relative to image base).
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub can_execute: bool,
    pub can_write: bool,
}

/// A single function imported from an external DLL.
#[derive(Debug)]
pub struct Import {
    pub dll: String,
    pub function: String,
}

/// Everything Weave needs to know about a PE binary before loading it.
#[derive(Debug)]
pub struct PeInfo {
    /// Preferred load address. ASLR means this may not be honoured.
    pub image_base: u64,
    /// Entry point, relative to image base.
    pub entry_point_rva: u64,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
}

/// Parse a PE binary from raw bytes.
///
/// Returns a `PeInfo` on success, or an error string describing what went wrong.
pub fn parse(bytes: &[u8]) -> Result<PeInfo, String> {
    let pe = PE::parse(bytes).map_err(|e| format!("goblin parse error: {e}"))?;

    let header = pe.header;

    let optional = header
        .optional_header
        .ok_or("missing optional header — not a valid executable")?;

    let image_base = optional.windows_fields.image_base;
    let entry_point_rva = optional.standard_fields.address_of_entry_point;

    let sections = pe
        .sections
        .iter()
        .map(|s| {
            let name = String::from_utf8_lossy(&s.name)
                .trim_end_matches('\0')
                .to_string();
            let chars = s.characteristics;
            Section {
                name,
                virtual_address: s.virtual_address,
                virtual_size: s.virtual_size,
                can_execute: chars & 0x2000_0000 != 0,
                can_write: chars & 0x8000_0000 != 0,
            }
        })
        .collect();

    let imports = pe
        .imports
        .iter()
        .map(|i| Import {
            dll: i.dll.to_string(),
            function: i.name.to_string(),
        })
        .collect();

    Ok(PeInfo {
        image_base,
        entry_point_rva,
        sections,
        imports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse the Phase 0 test binary and assert it looks right.
    ///
    /// This test is the ground truth check that goblin handles our target binary.
    /// If it fails, the PE loader cannot proceed.
    #[test]
    fn parse_hello_minimal() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/fixtures/bin/hello_minimal.exe"
        );
        let bytes = std::fs::read(path).expect("hello_minimal.exe not found — run Step 0 first");

        let info = parse(&bytes).expect("parse failed");

        // Image base for a standard MinGW 64-bit build
        assert_eq!(info.image_base, 0x0000_0001_4000_0000);

        // Must have a .text section (executable code)
        let text = info
            .sections
            .iter()
            .find(|s| s.name == ".text")
            .expect("no .text section");
        assert!(text.can_execute);
        assert!(!text.can_write);

        // Must have exactly 3 imports, all from ntdll.dll
        assert_eq!(info.imports.len(), 3, "expected 3 imports, got: {:#?}", info.imports);
        for imp in &info.imports {
            assert_eq!(
                imp.dll.to_ascii_lowercase(),
                "ntdll.dll",
                "unexpected import from {}: {}",
                imp.dll,
                imp.function
            );
        }

        let names: Vec<&str> = info.imports.iter().map(|i| i.function.as_str()).collect();
        assert!(names.contains(&"NtWriteFile"), "missing NtWriteFile");
        assert!(names.contains(&"NtTerminateProcess"), "missing NtTerminateProcess");
        assert!(names.contains(&"RtlInitUnicodeString"), "missing RtlInitUnicodeString");
    }

    #[test]
    fn reject_garbage_bytes() {
        let result = parse(b"this is not a PE binary");
        assert!(result.is_err());
    }
}
