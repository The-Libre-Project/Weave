use clap::Parser;
use std::path::PathBuf;

/// Weave — run Windows executables on Linux.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the Windows .exe file to run
    exe: PathBuf,
}

fn main() {
    let args = Args::parse();
    println!("weave: loading {}", args.exe.display());
    // TODO: pass to weave-core PE loader (Step 2+)
}
