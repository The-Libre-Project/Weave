//! GDI object table — brushes, pens, fonts, bitmaps.
//!
//! Handles are allocated starting at `GDI_HANDLE_OFFSET`. Stock objects are
//! encoded as `STOCK_HANDLE_BASE + index` and never stored in the table.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::defs::*;

// ── GDI object kinds ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub enum GdiKind {
    Brush {
        color: u32,
    },
    Pen {
        color: u32,
        style: i32,
        width: i32,
    },
    Font {
        height: i32,
        weight: i32,
        italic: bool,
        face: [u16; 32],
    },
    Bitmap,
}

// ── Global object table ───────────────────────────────────────────────────────

struct ObjTable {
    entries: HashMap<usize, GdiKind>,
    next_id: usize,
}

fn table() -> &'static Mutex<ObjTable> {
    static T: OnceLock<Mutex<ObjTable>> = OnceLock::new();
    T.get_or_init(|| {
        Mutex::new(ObjTable {
            entries: HashMap::new(),
            next_id: GDI_HANDLE_OFFSET,
        })
    })
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Allocate a new GDI object and return its handle.
pub fn alloc(kind: GdiKind) -> usize {
    let mut t = table().lock().unwrap();
    let id = t.next_id;
    t.next_id += 1;
    t.entries.insert(id, kind);
    id
}

/// Read a GDI object.
pub fn get<F, R>(handle: usize, f: F) -> Option<R>
where
    F: FnOnce(&GdiKind) -> R,
{
    let t = table().lock().unwrap();
    t.entries.get(&handle).map(f)
}

/// Free an allocated object. Stock objects cannot be freed (returns false).
pub fn free(handle: usize) -> bool {
    if is_stock(handle) {
        return false;
    }
    table().lock().unwrap().entries.remove(&handle).is_some()
}

/// True for stock object handles.
pub fn is_stock(handle: usize) -> bool {
    (STOCK_HANDLE_BASE..STOCK_HANDLE_BASE + 32).contains(&handle)
}

/// Return the "stock" handle for a GetStockObject index.
pub fn stock_handle(index: i32) -> usize {
    STOCK_HANDLE_BASE + index as usize
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_returns_handle_in_gdi_range() {
        let h = alloc(GdiKind::Brush { color: 0xFF0000 });
        assert!(
            h >= GDI_HANDLE_OFFSET,
            "handle {h:#x} below GDI_HANDLE_OFFSET"
        );
        assert!(
            h < STOCK_HANDLE_BASE,
            "handle {h:#x} collides with stock range"
        );
        free(h);
    }

    #[test]
    fn alloc_returns_distinct_handles() {
        let h1 = alloc(GdiKind::Brush { color: 0 });
        let h2 = alloc(GdiKind::Pen {
            color: 0,
            style: 0,
            width: 1,
        });
        assert_ne!(h1, h2);
        free(h1);
        free(h2);
    }

    #[test]
    fn get_returns_correct_kind() {
        let h = alloc(GdiKind::Brush { color: 0xAABBCC });
        let color = get(h, |k| match k {
            GdiKind::Brush { color } => *color,
            _ => 0,
        });
        assert_eq!(color, Some(0xAABBCC));
        free(h);
    }

    #[test]
    fn get_on_missing_handle_returns_none() {
        // Use a handle that should never be allocated (0 is below GDI_HANDLE_OFFSET)
        let result = get(0, |_| ());
        assert!(result.is_none());
    }

    #[test]
    fn free_allocated_object_returns_true() {
        let h = alloc(GdiKind::Brush { color: 0 });
        assert!(free(h));
    }

    #[test]
    fn free_same_handle_twice_returns_false() {
        let h = alloc(GdiKind::Brush { color: 0 });
        assert!(free(h));
        assert!(!free(h)); // already gone
    }

    #[test]
    fn free_stock_handle_returns_false() {
        // Stock objects can never be freed
        assert!(!free(STOCK_HANDLE_BASE)); // WHITE_BRUSH stock handle
        assert!(!free(STOCK_HANDLE_BASE + 7)); // BLACK_PEN stock handle
    }

    #[test]
    fn is_stock_detects_stock_range() {
        assert!(is_stock(STOCK_HANDLE_BASE));
        assert!(is_stock(STOCK_HANDLE_BASE + 19)); // DC_PEN is index 19
        assert!(!is_stock(STOCK_HANDLE_BASE + 32)); // one past the end
        assert!(!is_stock(GDI_HANDLE_OFFSET));
        assert!(!is_stock(0));
    }

    #[test]
    fn stock_handle_adds_base_offset() {
        assert_eq!(stock_handle(0), STOCK_HANDLE_BASE);
        assert_eq!(stock_handle(7), STOCK_HANDLE_BASE + 7);
        assert_eq!(stock_handle(19), STOCK_HANDLE_BASE + 19);
    }

    #[test]
    fn brush_color_stock_white_brush() {
        let h = stock_handle(WHITE_BRUSH);
        assert_eq!(brush_color(h), 0x00FF_FFFF);
    }

    #[test]
    fn brush_color_stock_black_brush() {
        let h = stock_handle(BLACK_BRUSH);
        assert_eq!(brush_color(h), 0x0000_0000);
    }

    #[test]
    fn brush_color_allocated_brush() {
        let h = alloc(GdiKind::Brush { color: 0x0000_FF00 });
        assert_eq!(brush_color(h), 0x0000_FF00);
        free(h);
    }
}

/// Extract the brush fill color from any brush handle (allocated or stock).
/// Returns 0x00FFFFFF (white) for null/hollow/unknown brushes.
pub fn brush_color(handle: usize) -> u32 {
    if is_stock(handle) {
        let idx = handle - STOCK_HANDLE_BASE;
        return match idx as i32 {
            WHITE_BRUSH => 0x00FF_FFFF,
            LTGRAY_BRUSH => 0x00C0_C0C0,
            GRAY_BRUSH => 0x0080_8080,
            DKGRAY_BRUSH => 0x0040_4040,
            BLACK_BRUSH => 0x0000_0000,
            NULL_BRUSH => 0x00FF_FFFF, // HOLLOW_BRUSH == NULL_BRUSH
            _ => 0x00FF_FFFF,
        };
    }
    get(handle, |k| match k {
        GdiKind::Brush { color } => *color,
        _ => 0x00FF_FFFF,
    })
    .unwrap_or(0x00FF_FFFF)
}

/// Extract the pen color from any pen handle (allocated or stock).
pub fn pen_color(handle: usize) -> u32 {
    if is_stock(handle) {
        let idx = handle - STOCK_HANDLE_BASE;
        return match idx as i32 {
            WHITE_PEN => 0x00FF_FFFF,
            BLACK_PEN => 0x0000_0000,
            NULL_PEN => 0x00FF_FFFF,
            _ => 0x0000_0000,
        };
    }
    get(handle, |k| match k {
        GdiKind::Pen { color, .. } => *color,
        _ => 0x0000_0000,
    })
    .unwrap_or(0x0000_0000)
}
