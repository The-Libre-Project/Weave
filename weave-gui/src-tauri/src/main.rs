// Prevents an extra console window from opening on Windows in release builds.
// Required by Tauri — do not remove.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    weave_gui_lib::run();
}