//! Guest-pointer validators for Weave Win32 shims.
//!
//! Each function validates a guest-supplied pointer against the constraints
//! declared in `docs/POINTERS.tsv` for its shape. Returns `Some(typed pointer)`
//! if valid, `None` if the pointer is null, misaligned, or fails a size check.
//!
//! # Safety
//! These functions validate *pointer shape* only — they do not check whether
//! the pointed-to memory is readable, writable, or mapped. The caller is
//! responsible for bounds-checking the pointed-to region via the paired size
//! parameter (cch, cb, nSize) before dereference.

// ── Sized output pointers (paired with cch/cb) ──────────────────────────────

/// Validate a guest-supplied LPWSTR output buffer paired with a DWORD cch.
/// Returns the pointer if non-null and cch > 0.
pub fn validate_lpwstr(p: usize, cch: u32) -> Option<*mut u16> {
    if p == 0 {
        return None;
    }
    if cch == 0 {
        return None;
    }
    Some(p as *mut u16)
}

/// Validate a guest-supplied LPWSTR_INOUT interior pointer.
/// Returns the pointer if non-null.
pub fn validate_lpwstr_inout(p: usize) -> Option<*mut u16> {
    if p == 0 {
        return None;
    }
    Some(p as *mut u16)
}

/// Validate a guest-supplied LPCSTR input pointer.
/// Returns the pointer if non-null (null-terminated, iterate up to cap).
pub fn validate_lpcstr(p: usize) -> Option<*const u8> {
    if p == 0 {
        return None;
    }
    Some(p as *const u8)
}

/// Validate a guest-supplied LPSTR output buffer paired with a DWORD nSize.
/// Returns the pointer if non-null and nSize > 0.
pub fn validate_lpstr(p: usize, nsize: u32) -> Option<*mut u8> {
    if p == 0 {
        return None;
    }
    if nsize == 0 {
        return None;
    }
    Some(p as *mut u8)
}

/// Validate a guest-supplied LPBOOL (pointer to BOOL/i32).
/// Returns the pointer if non-null and 4-byte aligned.
pub fn validate_lpbool(p: usize) -> Option<*mut i32> {
    if p == 0 {
        return None;
    }
    if !p.is_multiple_of(4) {
        return None;
    }
    Some(p as *mut i32)
}

/// Validate a guest-supplied LPDWORD (pointer to 4-byte DWORD).
/// Returns the pointer if non-null and 4-byte aligned.
pub fn validate_lpdword(p: usize) -> Option<*mut u32> {
    if p == 0 {
        return None;
    }
    if !p.is_multiple_of(4) {
        return None;
    }
    Some(p as *mut u32)
}

/// Validate a guest-supplied LPULONG (pointer to 4-byte ULONG).
/// Returns the pointer if non-null and 4-byte aligned.
pub fn validate_lpulong(p: usize) -> Option<*mut u32> {
    if p == 0 {
        return None;
    }
    if !p.is_multiple_of(4) {
        return None;
    }
    Some(p as *mut u32)
}

/// Validate a guest-supplied LPHANDLE (pointer to 8-byte HANDLE).
/// Returns the pointer if non-null and 8-byte aligned.
pub fn validate_lphandle(p: usize) -> Option<*mut *mut u8> {
    if p == 0 {
        return None;
    }
    if !p.is_multiple_of(8) {
        return None;
    }
    Some(p as *mut *mut u8)
}

// ── Raw buffer pointers (null check only) ──────────────────────────────────

/// Validate a guest-supplied LPVOID (raw mutable buffer).
/// Returns the pointer if non-null.
pub fn validate_lpvoid(p: usize) -> Option<*mut u8> {
    if p == 0 {
        return None;
    }
    Some(p as *mut u8)
}

/// Validate a guest-supplied LPVOID_IN (raw const buffer).
/// Returns the pointer if non-null.
pub fn validate_lpvoid_in(p: usize) -> Option<*const u8> {
    if p == 0 {
        return None;
    }
    Some(p as *const u8)
}

/// Validate a guest-supplied LPCVOID (raw const buffer).
/// Returns the pointer if non-null.
pub fn validate_lpcvoid(p: usize) -> Option<*const u8> {
    if p == 0 {
        return None;
    }
    Some(p as *const u8)
}

/// Validate a guest-supplied LPBYTE (raw byte buffer with paired cb).
/// Returns the pointer if non-null and cb > 0.
pub fn validate_lpbyte(p: usize, cb: u32) -> Option<*mut u8> {
    if p == 0 {
        return None;
    }
    if cb == 0 {
        return None;
    }
    Some(p as *mut u8)
}

/// Validate a guest-supplied PULONG (pointer to 4-byte ULONG).
/// Returns the pointer if non-null and 4-byte aligned.
pub fn validate_pulong(p: usize) -> Option<*mut u32> {
    if p == 0 {
        return None;
    }
    if !p.is_multiple_of(4) {
        return None;
    }
    Some(p as *mut u32)
}

/// Validate a guest-supplied LPOVERLAPPED structure pointer.
/// Returns the pointer if non-null, 8-byte aligned, and cb >= 32.
pub fn validate_lpoverlapped(p: usize, cb: u32) -> Option<*mut u8> {
    if p == 0 {
        return None;
    }
    if cb < 32 {
        return None;
    }
    if !p.is_multiple_of(8) {
        return None;
    }
    Some(p as *mut u8)
}

/// Validate a guest-supplied LPOVERLAPPED_COMPLETION_ROUTINE (fn ptr).
/// Returns the pointer if non-null.
pub fn validate_lpoverlapped_completion_routine(p: usize) -> Option<usize> {
    if p == 0 || !p.is_multiple_of(2) {
        return None;
    }
    Some(p)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_lpwstr ─────────────────────────────────────────────────────

    #[test]
    fn lpwstr_null() {
        assert!(validate_lpwstr(0, 100).is_none());
    }

    #[test]
    fn lpwstr_zero_cch() {
        assert!(validate_lpwstr(0x1000, 0).is_none());
    }

    #[test]
    fn lpwstr_ok() {
        let v = validate_lpwstr(0x1000, 100);
        assert!(v.is_some());
        assert_eq!(v.unwrap() as usize, 0x1000);
    }

    // ── validate_lpwstr_inout ──────────────────────────────────────────────

    #[test]
    fn lpwstr_inout_null() {
        assert!(validate_lpwstr_inout(0).is_none());
    }

    #[test]
    fn lpwstr_inout_ok() {
        let v = validate_lpwstr_inout(0x2000);
        assert!(v.is_some());
        assert_eq!(v.unwrap() as usize, 0x2000);
    }

    // ── validate_lpcstr ─────────────────────────────────────────────────────

    #[test]
    fn lpcstr_null() {
        assert!(validate_lpcstr(0).is_none());
    }

    #[test]
    fn lpcstr_ok() {
        let v = validate_lpcstr(0x3000);
        assert!(v.is_some());
        assert_eq!(v.unwrap() as usize, 0x3000);
    }

    // ── validate_lpstr ──────────────────────────────────────────────────────

    #[test]
    fn lpstr_null() {
        assert!(validate_lpstr(0, 100).is_none());
    }

    #[test]
    fn lpstr_zero_nsize() {
        assert!(validate_lpstr(0x1000, 0).is_none());
    }

    #[test]
    fn lpstr_ok() {
        let v = validate_lpstr(0x1000, 100);
        assert!(v.is_some());
        assert_eq!(v.unwrap() as usize, 0x1000);
    }

    // ── validate_lpbool ─────────────────────────────────────────────────────

    #[test]
    fn lpbool_null() {
        assert!(validate_lpbool(0).is_none());
    }

    #[test]
    fn lpbool_misaligned() {
        assert!(validate_lpbool(0x1001).is_none());
    }

    #[test]
    fn lpbool_ok() {
        let v = validate_lpbool(0x1000);
        assert!(v.is_some());
        assert_eq!(v.unwrap() as usize, 0x1000);
    }

    // ── validate_lpdword ────────────────────────────────────────────────────

    #[test]
    fn lpdword_null() {
        assert!(validate_lpdword(0).is_none());
    }

    #[test]
    fn lpdword_misaligned() {
        assert!(validate_lpdword(0x1001).is_none());
    }

    #[test]
    fn lpdword_ok() {
        let v = validate_lpdword(0x1000);
        assert!(v.is_some());
        assert_eq!(v.unwrap() as usize, 0x1000);
    }

    // ── validate_lpulong ────────────────────────────────────────────────────

    #[test]
    fn lpulong_null() {
        assert!(validate_lpulong(0).is_none());
    }

    #[test]
    fn lpulong_misaligned() {
        assert!(validate_lpulong(0x1001).is_none());
    }

    #[test]
    fn lpulong_ok() {
        let v = validate_lpulong(0x1000);
        assert!(v.is_some());
        assert_eq!(v.unwrap() as usize, 0x1000);
    }

    // ── validate_lphandle ────────────────────────────────────────────────────

    #[test]
    fn lphandle_null() {
        assert!(validate_lphandle(0).is_none());
    }

    #[test]
    fn lphandle_misaligned() {
        assert!(validate_lphandle(0x1001).is_none());
    }

    #[test]
    fn lphandle_misaligned_4() {
        // 4-byte aligned but not 8-byte aligned
        assert!(validate_lphandle(0x1004).is_none());
    }

    #[test]
    fn lphandle_ok() {
        let v = validate_lphandle(0x1000);
        assert!(v.is_some());
        assert_eq!(v.unwrap() as usize, 0x1000);
    }

    // ── validate_lpvoid ─────────────────────────────────────────────────────

    #[test]
    fn lpvoid_null() {
        assert!(validate_lpvoid(0).is_none());
    }

    #[test]
    fn lpvoid_ok() {
        let v = validate_lpvoid(0x5000);
        assert!(v.is_some());
        assert_eq!(v.unwrap() as usize, 0x5000);
    }

    // ── validate_lpvoid_in ──────────────────────────────────────────────────

    #[test]
    fn lpvoid_in_null() {
        assert!(validate_lpvoid_in(0).is_none());
    }

    #[test]
    fn lpvoid_in_ok() {
        let v = validate_lpvoid_in(0x6000);
        assert!(v.is_some());
        assert_eq!(v.unwrap() as usize, 0x6000);
    }

    // ── validate_lpcvoid ────────────────────────────────────────────────────

    #[test]
    fn lpcvoid_null() {
        assert!(validate_lpcvoid(0).is_none());
    }

    #[test]
    fn lpcvoid_ok() {
        let v = validate_lpcvoid(0x7000);
        assert!(v.is_some());
        assert_eq!(v.unwrap() as usize, 0x7000);
    }

    // ── validate_lpbyte ─────────────────────────────────────────────────────

    #[test]
    fn lpbyte_null() {
        assert!(validate_lpbyte(0, 100).is_none());
    }

    #[test]
    fn lpbyte_zero_cb() {
        assert!(validate_lpbyte(0x1000, 0).is_none());
    }

    #[test]
    fn lpbyte_ok() {
        let v = validate_lpbyte(0x1000, 100);
        assert!(v.is_some());
        assert_eq!(v.unwrap() as usize, 0x1000);
    }

    // ── validate_pulong ─────────────────────────────────────────────────────

    #[test]
    fn pulong_null() {
        assert!(validate_pulong(0).is_none());
    }

    #[test]
    fn pulong_misaligned() {
        assert!(validate_pulong(0x1001).is_none());
    }

    #[test]
    fn pulong_ok() {
        let v = validate_pulong(0x1000);
        assert!(v.is_some());
        assert_eq!(v.unwrap() as usize, 0x1000);
    }

    // ── validate_lpoverlapped ───────────────────────────────────────────────

    #[test]
    fn lpoverlapped_null() {
        assert!(validate_lpoverlapped(0, 32).is_none());
    }

    #[test]
    fn lpoverlapped_too_small() {
        assert!(validate_lpoverlapped(0x1000, 16).is_none());
    }

    #[test]
    fn lpoverlapped_misaligned() {
        assert!(validate_lpoverlapped(0x1004, 32).is_none());
    }

    #[test]
    fn lpoverlapped_ok() {
        let v = validate_lpoverlapped(0x1000, 32);
        assert!(v.is_some());
        assert_eq!(v.unwrap() as usize, 0x1000);
    }

    // ── validate_lpoverlapped_completion_routine ────────────────────────────

    #[test]
    fn lpoverlapped_completion_routine_null() {
        assert!(validate_lpoverlapped_completion_routine(0).is_none());
    }

    #[test]
    fn lpoverlapped_completion_routine_ok() {
        let v = validate_lpoverlapped_completion_routine(0x8000);
        assert!(v.is_some());
        assert_eq!(v.unwrap(), 0x8000);
    }

    #[test]
    fn lpoverlapped_completion_routine_misaligned() {
        assert!(validate_lpoverlapped_completion_routine(0x8001).is_none());
    }
}
