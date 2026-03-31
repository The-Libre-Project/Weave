/// Jump to a PE entry point and run.
///
/// The entry point is called with the Windows x86-64 calling convention
/// (`extern "win64"`). For a console EXE, the CRT startup function (or our
/// custom `entry` for nostdlib builds) takes no arguments and terminates the
/// process by calling NtTerminateProcess — it never returns.
///
/// If the entry point does return (it shouldn't), we exit with code 0.

/// Transfer control to the loaded PE's entry point.
///
/// This function does not return under normal circumstances: the entry point
/// calls `NtTerminateProcess` (our stub), which calls `libc::exit()`.
pub fn run(entry_point: *const u8) -> ! {
    // Safety: entry_point is a valid executable address set up by the loader.
    // The Windows x86-64 ABI is declared here so the compiler generates the
    // correct prologue/epilogue (shadow space allocation, callee-saved regs).
    let f: extern "win64" fn() = unsafe { std::mem::transmute(entry_point) };
    f();

    // Reached only if the entry point returned without calling ExitProcess /
    // NtTerminateProcess. Treat it as a clean exit.
    std::process::exit(0)
}
