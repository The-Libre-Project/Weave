//! MFC140U.dll stubs for Weave.
//!
//! All 227 ordinals imported by stats.exe from mfc140u.dll are
//! resolved here. Function stubs are Phase-A sentinels returning 0.
//! No MFC functionality is implemented; the stubs satisfy IAT resolution
//! so stats.exe can reach its own code paths.
//!
//! Wine ref: dlls/mfc140u/mfc140u.c — ordinals are entry-point wrappers;
//!   the real implementation would delegate to MFC90/100/120 patterns.
#![allow(clippy::missing_safety_doc)]

/// No-op stub for most MFC140U ordinals.
/// Win64 ABI places return value in RAX; returning 0 covers void and int return types.
pub unsafe extern "win64" fn mfc140u_noop(_a: usize, _b: usize, _c: usize, _d: usize) -> usize {
    0
}

/// Stub that returns a pointer to a static buffer (128 bytes, zeroed).
/// Used for MFC functions that return a non-optional pointer that the caller immediately dereferences
/// (e.g. AFX_MODULE_STATE accessors, object factory helpers).
///
/// Wine ref: dlls/mfc140u/mfc140u.c — ordinal wrappers delegate to MFC90/100/120; the real
///   implementations return a pointer to a per-module AFX_MODULE_STATE or AFX_THREAD_STATE.
pub unsafe extern "win64" fn mfc140u_buffer_stub(
    _a: usize,
    _b: usize,
    _c: usize,
    _d: usize,
) -> usize {
    #[allow(static_mut_refs)]
    static mut BUF: [u8; 128] = [0; 128];
    std::ptr::addr_of_mut!(BUF) as usize
}

/// Resolve an MFC140U.dll import to a stub address.
///
/// Returns `None` if the DLL is not mfc140u.dll.
/// Returns `Some(addr)` for every ordinal that stats.exe imports.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("mfc140u.dll") {
        return None;
    }

    // All imports are ordinals (#N). Match and return the appropriate stub.
    let addr = match func {
        // Pointer-returning functions: return a stable non-null buffer.
        // Ordinal #2212: called during MFC/CWinApp init — returns a pointer that the caller
        // immediately writes to at offset 0x28. Returning 0 (null) crashes at RVA 0x128f7 in
        // stats.exe. IAT thunk at RVA 0x12096 → slot 0x16d10 → mfc140u!#2212 (ordinal 0x8a4).
        // Wine ref: dlls/mfc140u/mfc140u.c — ordinal wrappers; #2212 is likely AFX_MODULE_STATE
        //   or AFX_THREAD_STATE accessor that must return a valid pointer.
        "#2212" => mfc140u_buffer_stub as *const () as usize,
        // Void / int / bool returning functions: return 0.
        "#2287" | "#8167" | "#4656" | "#6320" | "#3756" | "#6247" | "#8468" | "#4726"
        | "#11850" | "#3172" | "#3279" | "#3278" | "#3812" | "#2629" | "#13761" | "#11406"
        | "#6631" | "#14217" | "#7651" | "#14211" | "#2967" | "#4352" | "#9384" | "#5582"
        | "#4360" | "#4828" | "#4767" | "#4752" | "#4814" | "#4859" | "#4782" | "#4837"
        | "#4853" | "#4794" | "#4800" | "#4806" | "#4788" | "#4843" | "#4776" | "#1755"
        | "#1734" | "#1748" | "#1722" | "#1700" | "#11940" | "#11944" | "#13513" | "#3173"
        | "#10691" | "#6729" | "#8656" | "#14209" | "#11625" | "#3718" | "#8830" | "#11415"
        | "#11414" | "#7393" | "#9979" | "#9975" | "#9977" | "#9978" | "#9976" | "#14360"
        | "#2698" | "#9946" | "#3209" | "#3212" | "#13401" | "#6002" | "#6879" | "#502"
        | "#3081" | "#8095" | "#4872" | "#4873" | "#5917" | "#12142" | "#1766" | "#5722"
        | "#13351" | "#13360" | "#5727" | "#13358" | "#5726" | "#2510" | "#4353" | "#11119"
        | "#5743" | "#8521" | "#9043" | "#1129" | "#7912" | "#8904" | "#11489" | "#11484"
        | "#5189" | "#11859" | "#3723" | "#4443" | "#8928" | "#11763" | "#11184" | "#10093"
        | "#8993" | "#7245" | "#2270" | "#14220" | "#1503" | "#6619" | "#8471" | "#990"
        | "#11806" | "#5723" | "#13354" | "#8947" | "#9159" | "#11902" | "#11771" | "#1454"
        | "#7913" | "#7394" | "#2316" | "#2370" | "#1450" | "#8084" | "#11929" | "#10124"
        | "#12544" | "#4445" | "#8023" | "#5183" | "#9842" | "#9838" | "#9835" | "#2439"
        | "#12223" | "#12222" | "#14210" | "#7650" | "#14216" | "#4011" | "#3949" | "#12625"
        | "#7668" | "#11928" | "#11709" | "#2011" | "#11665" | "#14088" | "#12212" | "#7719"
        | "#14288" | "#6121" | "#14290" | "#6123" | "#14289" | "#6122" | "#4307" | "#983"
        | "#6614" | "#1059" | "#365" | "#2187" | "#2149" | "#3731" | "#5706" | "#11921"
        | "#7920" | "#11933" | "#11901" | "#12607" | "#2311" | "#12610" | "#13864" | "#5080"
        | "#5363" | "#5552" | "#9041" | "#5339" | "#5555" | "#5083" | "#5229" | "#5062"
        | "#7460" | "#7461" | "#7450" | "#5227" | "#7922" | "#9941" | "#8900" | "#14027"
        | "#2903" | "#3484" | "#8161" | "#4655" | "#13619" | "#7893" | "#2414" | "#8058"
        | "#12600" | "#8452" | "#8451" | "#14032" | "#14026" | "#14033" | "#14039" | "#4510"
        | "#13986" | "#1501" | "#1033" | "#286" | "#280" | "#296" | "#13618" | "#12240"
        | "#6717" | "#5674" | "#4946" | "#4181" | "#2415" | "#1641" | "#2350" | "#2346"
        | "#5451" | "#2272" => mfc140u_noop as *const () as usize,
        _ => return None,
    };

    Some(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_function_stub_is_some() {
        assert!(resolve("mfc140u.dll", "#2287").is_some());
    }

    #[test]
    fn resolve_function_stub_nonzero() {
        let addr = resolve("mfc140u.dll", "#2287").unwrap();
        assert_ne!(addr, 0, "stub address must be non-zero");
    }

    #[test]
    fn resolve_unknown_dll_returns_none() {
        assert!(resolve("kernel32.dll", "#2287").is_none());
    }

    #[test]
    fn resolve_unknown_ordinal_returns_none() {
        assert!(resolve("mfc140u.dll", "#99999").is_none());
    }
}
