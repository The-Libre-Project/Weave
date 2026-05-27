use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

static START: OnceLock<Instant> = OnceLock::new();

#[inline]
pub fn mark_phase(name: &str) {
    let start = START.get_or_init(Instant::now);
    let ms = start.elapsed().as_millis();
    eprintln!("PHASE: {} t={}", name, ms);
}

static PHASE_SHELL_ENUM: AtomicBool = AtomicBool::new(false);
static PHASE_LISTVIEW_INSERT: AtomicBool = AtomicBool::new(false);

/// E3-M5b: first `IShellFolder::EnumObjects` / `IEnumIDList::Next` delivered an item.
#[inline]
pub fn mark_shell_enum_first() {
    if !PHASE_SHELL_ENUM.swap(true, Ordering::Relaxed) {
        mark_phase("shell_enum_first");
    }
}

/// E3-M5b: first successful `LVM_INSERTITEM` on a ListView control.
#[inline]
pub fn mark_listview_insert_first() {
    if !PHASE_LISTVIEW_INSERT.swap(true, Ordering::Relaxed) {
        mark_phase("listview_insert_first");
    }
}
