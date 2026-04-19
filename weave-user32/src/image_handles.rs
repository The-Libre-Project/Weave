//! Handle table for HICON / HCURSOR / HBITMAP produced by `LoadImageW` and
//! friends. Slab-backed, with `LR_SHARED` dedup keyed on
//! `(hinst, name_key, type)`.
//!
//! Wine ref: `dlls/user32/cursoricon.c::CURSORICON_Load` — on `LR_SHARED`,
//! Wine computes a `(module_name, res_name, hRsrc)` identity and calls
//! `NtUserFindExistingCursorIcon` before allocating a fresh handle. Weave
//! encodes the same identity more cheaply because the HRSRC (address of
//! `IMAGE_RESOURCE_DATA_ENTRY`) is already a stable `(hinst, resource)`
//! fingerprint inside a single loaded image.
//!
//! Handle space: values start at `HANDLE_BASE` (0x6FFF_0001) and monotonically
//! increment. This range is deliberately distinct from `weave-core`'s
//! module-handle table (0x7FFF_0001) so a stray HMODULE never masquerades as
//! an HICON in crash traces.

use std::collections::HashMap;
use std::sync::Mutex;

const HANDLE_BASE: usize = 0x6FFF_0001;

/// Type tag recorded on every allocated handle so later APIs
/// (e.g. `DrawIcon`, `DestroyIcon`, `GetIconInfo`) can validate the kind of
/// resource they were handed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImageKind {
    Icon,
    Cursor,
    Bitmap,
}

/// Metadata recorded alongside each handle. The raw resource bytes pointer
/// stays live for the lifetime of the mapped module (Win32 invariant: HRSRC
/// is a direct pointer into `.rsrc`), so we keep it as a plain `usize` rather
/// than borrowing the image with a lifetime.
#[derive(Debug, Clone)]
pub struct ImageEntry {
    pub kind: ImageKind,
    /// Pointer to the first byte of the actual resource payload
    /// (RT_ICON / RT_CURSOR / RT_BITMAP bytes, not the group directory).
    pub data_ptr: usize,
    /// Size of that payload in bytes.
    pub data_size: u32,
    pub width: i32,
    pub height: i32,
    /// `bit_count` from the group-directory entry (0 for bitmaps that were
    /// never routed through a group).
    pub bpp: u16,
    /// Whether this handle was allocated under `LR_SHARED` — shared handles
    /// are dedup'd and `DestroyIcon` on them is a no-op per Win32 contract.
    pub shared: bool,
}

/// Dedup key for `LR_SHARED` lookups.
///
/// * `hinst` — HMODULE the caller passed; 0 for OEM (`hInst == NULL`).
/// * `name_key` — for integer-resource names (`IS_INTRESOURCE`) the ordinal
///   itself; for string names, a 64-bit FNV-1a hash of the UTF-16 code units
///   (collisions would only cause a spurious cache hit on *same hinst +
///   same kind*, which is already a programmer error on the guest side).
/// * `kind` — icon/cursor/bitmap cannot share a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ShareKey {
    hinst: usize,
    name_key: u64,
    kind: ImageKind,
}

struct Table {
    by_handle: HashMap<usize, ImageEntry>,
    shared: HashMap<ShareKey, usize>,
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
            eprintln!("weave/user32: image handle table mutex poisoned: {e}");
            return fallback;
        }
    };
    let table = guard.get_or_insert_with(|| Table {
        by_handle: HashMap::new(),
        shared: HashMap::new(),
        next: HANDLE_BASE,
    });
    f(table)
}

/// FNV-1a 64 over a UTF-16 name (or any byte sequence representing the
/// resource identifier). Used only to collapse string names to a `u64` dedup
/// key; never exposed to callers.
pub fn hash_name_w(name: &[u16]) -> u64 {
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
// Wine ref: dlls/user32/cursoricon.c — IS_INTRESOURCE gate: any value with
// zero high bits is an ordinal, else it's an LPCWSTR. Wrong test would
// dereference a small integer.
pub unsafe fn name_key_from_ptr(name_ptr: usize) -> u64 {
    if name_ptr >> 16 == 0 {
        // Ordinal path — pack the u16 directly.
        return name_ptr as u64;
    }
    // UTF-16 string path: walk until terminator.
    let mut wchars: Vec<u16> = Vec::new();
    // SAFETY: caller contract above.
    unsafe {
        let mut p = name_ptr as *const u16;
        // Cap at 32k chars as a guardrail; resource names never approach this.
        for _ in 0..32_768 {
            let ch = *p;
            if ch == 0 {
                break;
            }
            wchars.push(ch);
            p = p.add(1);
        }
    }
    // Mix a salt bit so string names can never collide with ordinal packing.
    hash_name_w(&wchars) | 0x8000_0000_0000_0000
}

/// Look up an existing shared handle for `(hinst, name_key, kind)`.
pub fn get_shared(hinst: usize, name_key: u64, kind: ImageKind) -> Option<usize> {
    with_table(None, |t| {
        t.shared
            .get(&ShareKey {
                hinst,
                name_key,
                kind,
            })
            .copied()
    })
}

/// Allocate a new handle for `entry`. If `share_key` is `Some` and the entry
/// is marked `shared`, the handle is also registered in the shared map so
/// future calls with the same key return it.
pub fn insert(entry: ImageEntry, share_key: Option<(usize, u64)>) -> usize {
    with_table(0, |t| {
        if entry.shared {
            if let Some((hinst, name_key)) = share_key {
                let key = ShareKey {
                    hinst,
                    name_key,
                    kind: entry.kind,
                };
                if let Some(&existing) = t.shared.get(&key) {
                    return existing;
                }
                let handle = t.next;
                t.next += 1;
                t.by_handle.insert(handle, entry);
                t.shared.insert(key, handle);
                return handle;
            }
        }
        let handle = t.next;
        t.next += 1;
        t.by_handle.insert(handle, entry);
        handle
    })
}

/// Retrieve an entry by handle.
pub fn get(handle: usize) -> Option<ImageEntry> {
    if handle == 0 {
        return None;
    }
    with_table(None, |t| t.by_handle.get(&handle).cloned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_returns_nonzero_handle() {
        let h = insert(
            ImageEntry {
                kind: ImageKind::Icon,
                data_ptr: 0x1000,
                data_size: 64,
                width: 32,
                height: 32,
                bpp: 32,
                shared: false,
            },
            None,
        );
        assert!(h >= HANDLE_BASE);
        let e = get(h).unwrap();
        assert_eq!(e.kind, ImageKind::Icon);
        assert_eq!(e.width, 32);
    }

    #[test]
    fn shared_dedup_returns_same_handle() {
        let hinst = 0xAA_BB_CC_DD;
        let name_key = 42;
        let make = || ImageEntry {
            kind: ImageKind::Icon,
            data_ptr: 0x2000,
            data_size: 96,
            width: 16,
            height: 16,
            bpp: 8,
            shared: true,
        };
        let h1 = insert(make(), Some((hinst, name_key)));
        let h2 = insert(make(), Some((hinst, name_key)));
        assert_eq!(h1, h2);
        // And lookup works:
        assert_eq!(get_shared(hinst, name_key, ImageKind::Icon), Some(h1));
        // Different kind under the same key must NOT collide.
        let h3 = insert(
            ImageEntry {
                kind: ImageKind::Cursor,
                ..make()
            },
            Some((hinst, name_key)),
        );
        assert_ne!(h1, h3);
    }

    #[test]
    fn name_key_from_ordinal_is_small() {
        // SAFETY: ordinal path — no deref.
        let k = unsafe { name_key_from_ptr(7) };
        assert_eq!(k, 7);
    }

    #[test]
    fn name_key_from_string_is_salted() {
        let s: Vec<u16> = "HELLO\0".encode_utf16().collect();
        // SAFETY: s lives for the call; pointer is valid UTF-16 + NUL.
        let k = unsafe { name_key_from_ptr(s.as_ptr() as usize) };
        // High bit set to disambiguate from ordinals.
        assert!(k & 0x8000_0000_0000_0000 != 0);
    }
}
