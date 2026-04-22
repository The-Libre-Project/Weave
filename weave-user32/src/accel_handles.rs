//! Handle table for HACCEL values produced by `LoadAcceleratorsW` /
//! `LoadAcceleratorsA`.
//!
//! Slab-backed with dedup keyed on `(hinst, name_key)`. Unlike
//! `image_handles`, there is no per-kind discriminator — HACCEL is a single
//! resource type (RT_ACCELERATOR ordinal 9) and there is no cross-kind
//! collision to avoid.
//!
//! Wine ref: `dlls/user32/resource.c::LoadAcceleratorsW` —
//!   `if (!(rsrc = FindResourceW( instance, name, (LPWSTR)RT_ACCELERATOR ))) return 0;`
//!   `pe_table = LoadResource( instance, rsrc );`
//!   `count = SizeofResource( instance, rsrc ) / sizeof(*pe_table);`
//!   `...`
//!   `handle = NtUserCreateAcceleratorTable( table, count );`
//! Wine copies each `PE_ACCEL` (8-byte) entry into an `ACCEL` and hands the
//! array to `NtUserCreateAcceleratorTable`, which creates a kernel object
//! keyed on the copied bytes. Weave stops at the resource lookup and stores
//! the raw resource blob pointer+size — enough for guests that only need
//! the presence-of-an-accelerator-table signal before attaching it via
//! `TranslateAcceleratorW` (still a stub in Weave).
//!
//! Handle space: values start at `ACCEL_HANDLE_BASE` (0x4FFF_0001) and
//! monotonically increment. This range is deliberately distinct from:
//!   * `weave-user32::menu_handles`  (0x5FFF_0001),
//!   * `weave-user32::image_handles` (0x6FFF_0001),
//!   * `weave-core::module_handles`  (0x7FFF_0001),
//!
//! so a stray HMENU / HICON / HMODULE never masquerades as an HACCEL in
//! crash traces.

use std::collections::HashMap;
use std::sync::Mutex;

pub const ACCEL_HANDLE_BASE: usize = 0x4FFF_0001;

/// Dedup key for accelerator handles.
///
/// * `hinst` — HMODULE the caller passed; we do not synthesize a module for
///   `hInst == NULL` (system-accelerator resolution is out of scope).
/// * `name_key` — for integer-resource names (`IS_INTRESOURCE`) the ordinal
///   itself; for string names, a 64-bit FNV-1a hash of the UTF-16 code units
///   with the high bit set to disambiguate from ordinals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ShareKey {
    hinst: usize,
    name_key: u64,
}

/// Raw accelerator resource blob descriptor. Not decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccelBlob {
    pub ptr: usize,
    pub size: u32,
}

struct Table {
    shared: HashMap<ShareKey, usize>,
    alive: HashMap<usize, (ShareKey, AccelBlob)>,
    next: usize,
}

static TABLE: Mutex<Option<Table>> = Mutex::new(None);

fn with_table<F, R>(fallback: R, f: F) -> R
where
    F: FnOnce(&mut Table) -> R,
{
    let mut guard = match TABLE.lock() {
        Ok(g) => g,
        Err(e) => {
            eprintln!("weave/user32: accel handle table mutex poisoned: {e}");
            return fallback;
        }
    };
    let table = guard.get_or_insert_with(|| Table {
        shared: HashMap::new(),
        alive: HashMap::new(),
        next: ACCEL_HANDLE_BASE,
    });
    f(table)
}

/// FNV-1a 64 over a UTF-16 name. Never exposed to callers.
fn hash_name_w(name: &[u16]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for w in name {
        for b in w.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
    }
    h
}

/// Normalise a caller-supplied resource identifier (either an ordinal via
/// `IS_INTRESOURCE` or a UTF-16 string pointer) into a stable `u64` key.
///
/// # Safety
/// If `(name_ptr as usize) >> 16 != 0`, the caller guarantees `name_ptr` is
/// a valid null-terminated UTF-16 string.
// Wine ref: dlls/user32/resource.c::LoadAcceleratorsW — forwards `name`
// straight to FindResourceW, which applies IS_INTRESOURCE internally;
// integer names are matched by ordinal, string names are matched
// case-insensitively by UTF-16 codepoints. We mirror the same dichotomy
// into a single u64 key.
pub unsafe fn name_key_from_wide_ptr(name_ptr: usize) -> u64 {
    if name_ptr >> 16 == 0 {
        return name_ptr as u64;
    }
    let mut wchars: Vec<u16> = Vec::new();
    // SAFETY: caller contract above.
    unsafe {
        let mut p = name_ptr as *const u16;
        for _ in 0..32_768 {
            let ch = *p;
            if ch == 0 {
                break;
            }
            wchars.push(ch);
            p = p.add(1);
        }
    }
    hash_name_w(&wchars) | 0x8000_0000_0000_0000
}

/// Register or retrieve the canonical HACCEL for `(hinst, name_key)`.
/// Duplicate calls with the same key return the same handle; the stored
/// `AccelBlob` from the first registration is preserved.
pub fn register(hinst: usize, name_key: u64, blob: AccelBlob) -> usize {
    with_table(0, |t| {
        let key = ShareKey { hinst, name_key };
        if let Some(&existing) = t.shared.get(&key) {
            return existing;
        }
        let handle = t.next;
        t.next += 1;
        t.shared.insert(key, handle);
        t.alive.insert(handle, (key, blob));
        handle
    })
}

/// Look up whether `handle` was produced by `register` and is still alive.
/// Returns the `(hinst, name_key, blob)` it was registered under.
pub fn lookup(handle: usize) -> Option<(usize, u64, AccelBlob)> {
    if handle == 0 {
        return None;
    }
    with_table(None, |t| {
        t.alive
            .get(&handle)
            .map(|(k, b)| (k.hinst, k.name_key, *b))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mkblob(ptr: usize, size: u32) -> AccelBlob {
        AccelBlob { ptr, size }
    }

    #[test]
    fn register_returns_nonzero_handle_and_round_trips() {
        let blob = mkblob(0x1000_2000, 24);
        let h = register(0xAA_BB_CC_DD, 42, blob);
        assert!(h >= ACCEL_HANDLE_BASE);
        let (hinst, key, got) = lookup(h).expect("handle should be alive");
        assert_eq!(hinst, 0xAA_BB_CC_DD);
        assert_eq!(key, 42);
        assert_eq!(got, blob);
    }

    #[test]
    fn distinct_keys_get_distinct_handles() {
        let hinst = 0x1111_2222;
        let h1 = register(hinst, 1, mkblob(0x10, 8));
        let h2 = register(hinst, 2, mkblob(0x20, 16));
        assert_ne!(h1, h2);
        // Different hinst with same name_key also distinct.
        let h3 = register(0x3333_4444, 1, mkblob(0x30, 8));
        assert_ne!(h1, h3);
    }

    #[test]
    fn duplicate_key_returns_same_handle() {
        let hinst = 0xDEAD_BEEF;
        let first = mkblob(0xAAA, 8);
        let h1 = register(hinst, 7, first);
        // A second call with a different blob must not overwrite — same key
        // dedups to the same handle and the first blob survives.
        let h2 = register(hinst, 7, mkblob(0xBBB, 16));
        assert_eq!(h1, h2);
        let (_, _, got) = lookup(h1).expect("handle alive");
        assert_eq!(got, first);
    }
}
