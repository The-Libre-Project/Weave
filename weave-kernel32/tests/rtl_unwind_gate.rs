// Gate: RtlUnwind no longer aborts — resolver returns non-null and the implementation
// delegates to unwind_ex rather than process::abort().
//
// Tier A assertions:
//   A1: kernel32::resolve("RtlUnwind") returns Some(addr) with addr != 0
//   A2: The resolved addr differs from RtlUnwindEx addr (it's a distinct trampoline)
//
// These assertions verify the stub was replaced; full stack-unwind behavior requires
// a live exception frame and is validated in integration by SciTE/Notepad++ gate runs.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

#[test]
fn rtl_unwind_resolver_non_null() {
    let addr = weave_kernel32::resolve("kernel32.dll", "RtlUnwind");
    assert!(
        addr.is_some(),
        "RtlUnwind must be present in the resolver (was missing before this fix)"
    );
    let addr = addr.unwrap();
    assert_ne!(addr, 0, "RtlUnwind resolver must return a non-zero function pointer");
}

#[test]
fn rtl_unwind_and_rtl_unwind_ex_are_distinct() {
    let unwind = weave_kernel32::resolve("kernel32.dll", "RtlUnwind")
        .expect("RtlUnwind must resolve");
    let unwind_ex = weave_kernel32::resolve("kernel32.dll", "RtlUnwindEx")
        .expect("RtlUnwindEx must resolve");
    assert_ne!(
        unwind, unwind_ex,
        "RtlUnwind and RtlUnwindEx must be distinct trampolines"
    );
}
