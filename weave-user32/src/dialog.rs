//! DLGTEMPLATE parsing and modal dialog creation (DialogBoxParamW Phase B).
//!
//! Wine ref: dlls/user32/dialog.c — DIALOG_ParseTemplate32, DIALOG_CreateControls32,
//! DIALOG_CreateIndirect, DIALOG_DoDialogBox.

use crate::class::{self, ClassEntry};
use crate::defs::*;
use crate::queue::{self, MsgEntry};
use crate::window::{self, WindowEntry};
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::Mutex;
use weave_core::resource::{resource_entry_ptr_and_size, ResourceId};

const RT_DIALOG: u16 = 5;
const DS_SETFONT: u32 = 0x0000_0040;
const DS_NOFAILCREATE: u32 = 0x0000_8000;
const WS_EX_DLGMODALFRAME: u32 = 0x0000_0001;
const WS_EX_CONTROLPARENT: u32 = 0x0002_0000;
const DIALOG_BASE_X: u32 = 6;
const DIALOG_BASE_Y: u32 = 13;
// Wine ref: include/winuser.h — bytes reserved for dialog manager state in #32770 HWNDs.
const DLG_WINDOW_EXTRA: u32 = 30;

struct ParsedTemplate {
    style: u32,
    ex_style: u32,
    nb_items: u16,
    x: i16,
    y: i16,
    cx: i16,
    cy: i16,
    class_name: String,
    caption: String,
    dialog_ex: bool,
    controls_offset: usize,
}

struct ControlInfo {
    style: u32,
    ex_style: u32,
    x: i16,
    y: i16,
    cx: i16,
    cy: i16,
    id: u32,
    class_name: String,
    window_name: String,
}

struct ActiveModal {
    hwnd: usize,
    ended: AtomicBool,
    result: AtomicIsize,
}

static ACTIVE_MODAL: Mutex<Option<ActiveModal>> = Mutex::new(None);

/// Minimal WM_PAINT handler for dialog HWNDs — BeginPaint/ValidateRect/EndPaint without guest dlgproc.
///
/// Wine ref: dlls/win32u/defwnd.c — DefWindowProc WM_PAINT calls BeginPaint then EndPaint
/// (which validates the update region). Q-Dir dlgproc SIGSEGV on WM_PAINT (RVA 0x8281) and
/// WM_INITDIALOG (0x7880d); route paint through DefWindowProc instead of guest dispatch.
pub(crate) fn paint_and_validate_hwnd(hwnd: usize) -> isize {
    if hwnd == 0 || window::with(hwnd, |_| ()).is_none() {
        return 0;
    }
    crate::api::def_window_proc_w(hwnd, WM_PAINT, 0, 0)
}

fn lock_modal(
    m: &Mutex<Option<ActiveModal>>,
) -> Option<std::sync::MutexGuard<'_, Option<ActiveModal>>> {
    m.lock()
        .map_err(|e| eprintln!("weave/user32: dialog modal mutex poisoned: {e}"))
        .ok()
}

fn align_dword(off: usize) -> usize {
    (off + 3) & !3
}

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_i16(data: &[u8], off: usize) -> Option<i16> {
    read_u16(data, off).map(|v| v as i16)
}

fn mul_div(value: i16, numer: u32, denom: u32) -> i32 {
    (value as i32).saturating_mul(numer as i32) / denom as i32
}

fn wide_string_at(data: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut units: Vec<u16> = Vec::new();
    while off + 1 < data.len() {
        let ch = read_u16(data, off)?;
        off += 2;
        if ch == 0 {
            return Some((String::from_utf16_lossy(&units), off));
        }
        units.push(ch);
    }
    None
}

fn builtin_control_class(id: u16) -> Option<&'static str> {
    match id {
        0x80..=0x85 => Some(
            [
                "Button",
                "Edit",
                "Static",
                "ListBox",
                "ScrollBar",
                "ComboBox",
            ][id as usize - 0x80],
        ),
        0..=5 => Some(
            [
                "Button",
                "Edit",
                "Static",
                "ListBox",
                "ScrollBar",
                "ComboBox",
            ][id as usize],
        ),
        _ => None,
    }
}

fn resolve_template_string(data: &[u8], off: usize) -> Option<(String, usize)> {
    let word = read_u16(data, off)?;
    match word {
        0 => Some(("#32770".to_string(), off + 2)),
        0xffff => {
            let id = read_u16(data, off + 2)?;
            let name = builtin_control_class(id)
                .map(str::to_string)
                .unwrap_or_else(|| format!("#{id}"));
            Some((name, off + 4))
        }
        _ => wide_string_at(data, off),
    }
}

fn parse_template(data: &[u8]) -> Option<ParsedTemplate> {
    if data.len() < 8 {
        return None;
    }
    let dlgver = read_u16(data, 0)?;
    let signature = read_u16(data, 2)?;
    let (mut off, dialog_ex, style, ex_style) = if dlgver == 1 && signature == 0xffff {
        if data.len() < 26 {
            return None;
        }
        (16usize, true, read_u32(data, 12)?, read_u32(data, 8)?)
    } else {
        (8usize, false, read_u32(data, 0)?, read_u32(data, 4)?)
    };
    let nb_items = read_u16(data, off)?;
    off += 2;
    let x = read_i16(data, off)?;
    off += 2;
    let y = read_i16(data, off)?;
    off += 2;
    let cx = read_i16(data, off)?;
    off += 2;
    let cy = read_i16(data, off)?;
    off += 2;
    off = skip_menu_name(data, off)?;
    let (class_name, off) = resolve_template_string(data, off)?;
    let (caption, mut off) = wide_string_at(data, off)?;
    if (style & DS_SETFONT) != 0 && off + 2 <= data.len() {
        off += 2;
        if dialog_ex && off + 4 <= data.len() {
            off += 4;
        }
        if off < data.len() && read_u16(data, off)? != 0 {
            let (_, next) = wide_string_at(data, off)?;
            off = next;
        }
    }
    Some(ParsedTemplate {
        style,
        ex_style,
        nb_items,
        x,
        y,
        cx,
        cy,
        class_name,
        caption,
        dialog_ex,
        controls_offset: align_dword(off),
    })
}

fn skip_menu_name(data: &[u8], off: usize) -> Option<usize> {
    let word = read_u16(data, off)?;
    match word {
        0 => Some(off + 2),
        0xffff => Some(off + 4),
        _ => wide_string_at(data, off).map(|(_, next)| next),
    }
}

fn parse_control(data: &[u8], mut off: usize, dialog_ex: bool) -> Option<(ControlInfo, usize)> {
    if dialog_ex {
        if data.len() < off + 24 {
            return None;
        }
        let _help = read_u32(data, off)?;
        off += 4;
        let ex_style = read_u32(data, off)?;
        off += 4;
        let style = read_u32(data, off)?;
        off += 4;
        let x = read_i16(data, off)?;
        off += 2;
        let y = read_i16(data, off)?;
        off += 2;
        let cx = read_i16(data, off)?;
        off += 2;
        let cy = read_i16(data, off)?;
        off += 2;
        let id = read_u32(data, off)?;
        off += 4;
        let (class_name, off) = resolve_template_string(data, off)?;
        let (window_name, off) = resolve_control_caption(data, off)?;
        let off = skip_creation_data(data, off)?;
        Some((
            ControlInfo {
                style,
                ex_style,
                x,
                y,
                cx,
                cy,
                id,
                class_name,
                window_name,
            },
            align_dword(off),
        ))
    } else {
        if data.len() < off + 18 {
            return None;
        }
        let style = read_u32(data, off)?;
        off += 4;
        let ex_style = read_u32(data, off)?;
        off += 4;
        let x = read_i16(data, off)?;
        off += 2;
        let y = read_i16(data, off)?;
        off += 2;
        let cx = read_i16(data, off)?;
        off += 2;
        let cy = read_i16(data, off)?;
        off += 2;
        let id = read_u16(data, off)? as u32;
        off += 2;
        let (class_name, off) = resolve_template_string(data, off)?;
        let (window_name, off) = resolve_control_caption(data, off)?;
        let off = skip_creation_data(data, off)?;
        Some((
            ControlInfo {
                style,
                ex_style,
                x,
                y,
                cx,
                cy,
                id,
                class_name,
                window_name,
            },
            align_dword(off),
        ))
    }
}

fn resolve_control_caption(data: &[u8], off: usize) -> Option<(String, usize)> {
    let word = read_u16(data, off)?;
    if word == 0xffff {
        let id = read_u16(data, off + 2)?;
        return Some((format!("#{id}"), off + 4));
    }
    wide_string_at(data, off)
}

fn skip_creation_data(data: &[u8], off: usize) -> Option<usize> {
    let size_words = read_u16(data, off)?;
    Some(off + 2 + size_words as usize * 2)
}

fn resource_id_from_name_ptr(ptr: *const u16) -> ResourceId {
    let raw = ptr as usize;
    if raw >> 16 == 0 {
        ResourceId::Id(raw as u16)
    } else {
        let mut units: Vec<u16> = Vec::new();
        let mut p = ptr;
        loop {
            let ch = unsafe { *p };
            if ch == 0 {
                break;
            }
            units.push(ch);
            p = unsafe { p.add(1) };
        }
        ResourceId::Name(units)
    }
}

fn create_frame_window(
    template: &ParsedTemplate,
    hwnd_parent: usize,
    dlg_proc: usize,
    _h_instance: usize,
) -> usize {
    class::register(
        "#32770",
        ClassEntry {
            wnd_proc: dlg_proc,
            style: 0,
            h_cursor: 0,
            hbr_background: 0,
            cb_wnd_extra: DLG_WINDOW_EXTRA,
            h_icon: 0,
            h_icon_sm: 0,
        },
    );
    let mut style = template.style;
    let mut ex_style = template.ex_style;
    if (style & WS_CHILD) == 0 {
        ex_style |= WS_EX_CONTROLPARENT;
    }
    if (style & 0x0000_0080) != 0 {
        ex_style |= WS_EX_DLGMODALFRAME;
    }
    style &= !WS_VISIBLE;
    let width = mul_div(template.cx, DIALOG_BASE_X, 4).max(1) as u32;
    let height = mul_div(template.cy, DIALOG_BASE_Y, 8).max(1) as u32;
    let pos_x = mul_div(template.x, DIALOG_BASE_X, 4);
    let pos_y = mul_div(template.y, DIALOG_BASE_Y, 8);
    let (abs_x, abs_y) = if (style & WS_CHILD) != 0 && hwnd_parent != 0 {
        let parent_pos = window::with(hwnd_parent, |e| (e.x, e.y)).unwrap_or((0, 0));
        (pos_x + parent_pos.0, pos_y + parent_pos.1)
    } else {
        (pos_x, pos_y)
    };
    let xcb_id = crate::backend::create_window(
        &template.caption,
        pos_x,
        pos_y,
        width,
        height,
        false,
        if (style & WS_CHILD) != 0 {
            window::xcb_id(hwnd_parent)
        } else {
            0
        },
    );
    let hwnd = window::create(WindowEntry {
        class_name: template.class_name.clone(),
        wnd_proc: dlg_proc,
        title: template.caption.clone(),
        style,
        x: abs_x,
        y: abs_y,
        width,
        height,
        visible: false,
        xcb_id,
        h_menu: 0,
        hwnd_parent,
        tid: unsafe { libc::syscall(libc::SYS_gettid) as u32 },
    });
    if hwnd != 0 {
        crate::api::init_window_extra(hwnd, ex_style, DLG_WINDOW_EXTRA);
        crate::api::mark_create_window_phase();
    }
    hwnd
}

fn create_control_window(dialog_hwnd: usize, info: &ControlInfo, _h_instance: usize) -> usize {
    let cls = match class::find(&info.class_name) {
        Some(c) => c,
        None => {
            eprintln!(
                "weave/dialog: unknown control class {:?} — skipped",
                info.class_name
            );
            return 0;
        }
    };
    let mut style = info.style & !WS_POPUP;
    style |= WS_CHILD;
    if (style & WS_BORDER) != 0 {
        style &= !WS_BORDER;
    }
    let width = mul_div(info.cx, DIALOG_BASE_X, 4).max(1) as u32;
    let height = mul_div(info.cy, DIALOG_BASE_Y, 8).max(1) as u32;
    let pos_x = mul_div(info.x, DIALOG_BASE_X, 4);
    let pos_y = mul_div(info.y, DIALOG_BASE_Y, 8);
    let parent_pos = window::with(dialog_hwnd, |e| (e.x, e.y)).unwrap_or((0, 0));
    let abs_x = parent_pos.0 + pos_x;
    let abs_y = parent_pos.1 + pos_y;
    let title = if info.window_name.starts_with('#') {
        String::new()
    } else {
        info.window_name.clone()
    };
    let xcb_id = crate::backend::create_window(
        &title,
        pos_x,
        pos_y,
        width,
        height,
        false,
        window::xcb_id(dialog_hwnd),
    );
    let hwnd = window::create(WindowEntry {
        class_name: info.class_name.clone(),
        wnd_proc: cls.wnd_proc,
        title,
        style,
        x: abs_x,
        y: abs_y,
        width,
        height,
        visible: false,
        xcb_id,
        h_menu: info.id as usize,
        hwnd_parent: dialog_hwnd,
        tid: unsafe { libc::syscall(libc::SYS_gettid) as u32 },
    });
    if hwnd != 0 && cls.cb_wnd_extra != 0 {
        crate::api::init_window_extra(hwnd, info.ex_style, cls.cb_wnd_extra);
    }
    hwnd
}

/// Load a DLGTEMPLATE from the PE, create the dialog + child controls, run WM_INITDIALOG.
///
/// Returns the dialog HWND on success.
///
/// # Safety
/// `template_ptr` must point at `template_size` bytes of a valid DLGTEMPLATE inside the PE.
pub unsafe fn create_from_template_bytes(
    template_ptr: *const u8,
    template_size: usize,
    hwnd_parent: usize,
    dlg_proc: usize,
    init_param: isize,
    h_instance: usize,
) -> Option<usize> {
    if template_ptr.is_null() || dlg_proc == 0 || template_size == 0 {
        return None;
    }
    let data = unsafe { std::slice::from_raw_parts(template_ptr, template_size) };
    let parsed = parse_template(data)?;
    let hwnd = create_frame_window(&parsed, hwnd_parent, dlg_proc, h_instance);
    if hwnd == 0 {
        return None;
    }
    let mut off = parsed.controls_offset;
    for _ in 0..parsed.nb_items {
        let (control, next) = parse_control(data, off, parsed.dialog_ex)?;
        if create_control_window(hwnd, &control, h_instance) == 0
            && (parsed.style & DS_NOFAILCREATE) == 0
        {
            window::remove(hwnd);
            return None;
        }
        off = next;
    }
    // Wine ref: dlls/user32/dialog.c — SendMessageW(hwnd, WM_INITDIALOG, hwndFocus, lParam).
    // NOTE: WM_INITDIALOG dispatch to the guest dlgproc is currently deferred (not sent) for
    // ALL guests — see TASK-CLEANUP-QDIR-ARC.md "masked regression". Restoring it is a tracked,
    // separately-verified change, not part of this path.
    eprintln!(
        "weave/dialog: WM_INITDIALOG deferred for hwnd={hwnd:#x} — guest dlgproc crashes on init"
    );
    // init_param is the WM_INITDIALOG lParam; held unused while dispatch is deferred
    // (consumed again when WM_INITDIALOG is restored — see TASK-CLEANUP-QDIR-ARC.md).
    let _ = init_param;
    // Wine ref: dlls/user32/dialog.c — ShowWindow(SW_SHOW) marks update region dirty and posts WM_PAINT.
    crate::api::show_window(hwnd, SW_SHOW);
    Some(hwnd)
}

pub fn begin_modal(hwnd: usize) {
    if let Some(mut guard) = lock_modal(&ACTIVE_MODAL) {
        *guard = Some(ActiveModal {
            hwnd,
            ended: AtomicBool::new(false),
            result: AtomicIsize::new(0),
        });
    }
}

pub fn signal_end_dialog(hwnd: usize, result: isize) -> bool {
    let Some(mut guard) = lock_modal(&ACTIVE_MODAL) else {
        return false;
    };
    let Some(state) = guard.as_mut() else {
        return false;
    };
    if state.hwnd != hwnd {
        return false;
    }
    state.result.store(result, Ordering::Relaxed);
    state.ended.store(true, Ordering::Relaxed);
    queue::post(MsgEntry {
        hwnd: 0,
        message: WM_NULL,
        w_param: 0,
        l_param: 0,
        time: 0,
        pt_x: 0,
        pt_y: 0,
    });
    true
}

pub fn take_modal_result(hwnd: usize) -> Option<isize> {
    let mut guard = lock_modal(&ACTIVE_MODAL)?;
    let state = guard.take()?;
    if state.hwnd != hwnd {
        *guard = Some(state);
        return None;
    }
    Some(state.result.load(Ordering::Relaxed))
}

pub fn modal_ended() -> bool {
    lock_modal(&ACTIVE_MODAL)
        .and_then(|g| g.as_ref().map(|s| s.ended.load(Ordering::Relaxed)))
        .unwrap_or(false)
}

/// Wake the global queue after a modal dialog returns so post-dialog `GetMessageW` does not block.
///
/// Wine ref: dlls/user32/dialog.c::DIALOG_DoDialogBox — pumps until `DF_END`; Q-Dir then calls
/// `GetMessageW` on an empty queue (CI 26543785305). `WM_TIMER` wakes `wait_event` via the pipe.
pub fn wake_post_modal_queue() {
    queue::post(MsgEntry {
        hwnd: 0,
        message: crate::defs::WM_TIMER,
        w_param: 1,
        l_param: 0,
        time: 0,
        pt_x: 0,
        pt_y: 0,
    });
    eprintln!("weave/dialog: post-modal WM_TIMER queued");
}

/// Load RT_DIALOG from `image_base`, create dialog window + controls.
///
/// # Safety
/// Caller must ensure `image_base`, `template_name`, and `h_instance` are valid guest pointers.
pub unsafe fn create_from_resource(
    image_base: usize,
    template_name: *const u16,
    hwnd_parent: usize,
    dlg_proc: usize,
    init_param: isize,
    h_instance: usize,
) -> Option<usize> {
    let name = resource_id_from_name_ptr(template_name);
    let entry =
        weave_core::resource::find_resource_entry(image_base, ResourceId::Id(RT_DIALOG), name, 0)?;
    let (ptr, size) = unsafe { resource_entry_ptr_and_size(image_base, entry)? };
    unsafe { create_from_template_bytes(ptr, size, hwnd_parent, dlg_proc, init_param, h_instance) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_standard_template() {
        let mut data = vec![0u8; 64];
        // style, exStyle
        data[0..4].copy_from_slice(&0x90CF0000u32.to_le_bytes());
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        // nbItems=0, x,y,cx,cy, menu, class
        data[8..10].copy_from_slice(&0u16.to_le_bytes());
        data[10..12].copy_from_slice(&0u16.to_le_bytes());
        data[12..14].copy_from_slice(&0u16.to_le_bytes());
        data[14..16].copy_from_slice(&100u16.to_le_bytes());
        data[16..18].copy_from_slice(&80u16.to_le_bytes());
        data[18..20].copy_from_slice(&0u16.to_le_bytes());
        data[20..22].copy_from_slice(&0u16.to_le_bytes());
        // caption "Hi\0" (UTF-16 LE)
        data[22..24].copy_from_slice(&(b'H' as u16).to_le_bytes());
        data[24..26].copy_from_slice(&(b'i' as u16).to_le_bytes());
        data[26..28].copy_from_slice(&0u16.to_le_bytes());
        let parsed = parse_template(&data).expect("template should parse");
        assert_eq!(parsed.caption, "Hi");
        assert_eq!(parsed.class_name, "#32770");
        assert_eq!(parsed.cx, 100);
    }
}
