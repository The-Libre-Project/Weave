use clap::Parser;
use std::path::PathBuf;
use weave_core::pe;

/// Weave — run Windows executables on Linux.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the Windows .exe file to run
    exe: PathBuf,
}

fn main() {
    let args = Args::parse();

    let bytes = std::fs::read(&args.exe).unwrap_or_else(|e| {
        eprintln!("error: could not read {}: {e}", args.exe.display());
        std::process::exit(1);
    });

    let info = pe::parse(&bytes).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    println!("binary:      {}", args.exe.display());
    println!("image base:  {:#018x}", info.image_base);
    println!("entry point: {:#010x} (rva)", info.entry_point_rva);
    println!();

    println!("sections ({}):", info.sections.len());
    for s in &info.sections {
        let perms = format!(
            "{}{}",
            if s.can_execute { "x" } else { "-" },
            if s.can_write { "w" } else { "-" },
        );
        println!("  {:12}  rva={:#010x}  size={:#08x}  [{}]", s.name, s.virtual_address, s.virtual_size, perms);
    }
    println!();

    // Group imports by DLL for readability
    let mut dlls: Vec<&str> = info.imports.iter().map(|i| i.dll.as_str()).collect();
    dlls.dedup();
    let dll_count = {
        let mut seen = std::collections::HashSet::new();
        info.imports.iter().filter(|i| seen.insert(&i.dll)).count()
    };

    println!("imports ({} functions from {} DLL{}):", info.imports.len(), dll_count, if dll_count == 1 { "" } else { "s" });
    let mut current_dll = "";
    for imp in &info.imports {
        if imp.dll != current_dll {
            println!("  {}:", imp.dll);
            current_dll = &imp.dll;
        }
        println!("    {}", imp.function);
    }

    // TODO: load and execute (Step 3+)
    println!();
    println!("(execution not yet implemented)");
}
