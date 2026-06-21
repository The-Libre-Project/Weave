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
static PHASE_SHELL_FOLDER_ENUM_OBJECTS: AtomicBool = AtomicBool::new(false);
static PHASE_SHELL_FOLDER_PARSE_DISPLAY_NAME: AtomicBool = AtomicBool::new(false);
static PHASE_LISTVIEW_INSERT: AtomicBool = AtomicBool::new(false);
static PHASE_FIND_FIRST_FILE: AtomicBool = AtomicBool::new(false);
static PHASE_FIND_NEXT_FILE: AtomicBool = AtomicBool::new(false);

/// E3-M5b: first `IShellFolder::EnumObjects` / `IEnumIDList::Next` delivered an item.
#[inline]
pub fn mark_shell_enum_first() {
    if !PHASE_SHELL_ENUM.swap(true, Ordering::Relaxed) {
        mark_phase("shell_enum_first");
    }
}

/// M18: first `IShellFolder::EnumObjects` dispatch — proves Q-Dir is navigating
/// the shell namespace for file-pane population.
#[inline]
pub fn mark_shell_folder_enum_objects_first() {
    if !PHASE_SHELL_FOLDER_ENUM_OBJECTS.swap(true, Ordering::Relaxed) {
        mark_phase("shell_folder_enum_objects_first");
    }
}

/// M18c: first `IShellFolder::ParseDisplayName` dispatch — proves Q-Dir resolves
/// paths via the shell namespace before enumerating.
#[inline]
pub fn mark_shell_folder_parse_display_name_first() {
    if !PHASE_SHELL_FOLDER_PARSE_DISPLAY_NAME.swap(true, Ordering::Relaxed) {
        mark_phase("shell_folder_parse_display_name_first");
    }
}

/// E3-M5b: first successful `LVM_INSERTITEM` on a ListView control.
#[inline]
pub fn mark_listview_insert_first() {
    if !PHASE_LISTVIEW_INSERT.swap(true, Ordering::Relaxed) {
        mark_phase("listview_insert_first");
    }
}

/// E3-M5b: first `FindFirstFileW` returned a valid enumeration handle (CI probe path).
#[inline]
pub fn mark_find_first_file_first() {
    if !PHASE_FIND_FIRST_FILE.swap(true, Ordering::Relaxed) {
        mark_phase("find_first_file_first");
    }
}

/// E3-M5b: first `FindNextFileW` returned TRUE with a real directory entry.
#[inline]
pub fn mark_find_next_file_first() {
    if !PHASE_FIND_NEXT_FILE.swap(true, Ordering::Relaxed) {
        mark_phase("find_next_file_first");
    }
}
