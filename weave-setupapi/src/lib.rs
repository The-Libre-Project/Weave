//! setupapi.dll stubs for Weave.
//!
//! Covers the Windows Setup API device enumeration functions imported by SDL2
//! for HID joystick discovery. All functions return an empty/invalid device
//! set so SDL2 reports "0 HID joysticks" and continues normally — the correct
//! behaviour for a headless environment with no attached controllers.
//!
//! Wine ref: dlls/setupapi/devinst.c

#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]

/// SetupDiGetClassDevsA — return a handle to a device info set.
///
/// Returns INVALID_HANDLE_VALUE (all-bits-set) so SDL2 detects no devices.
/// Wine ref: dlls/setupapi/devinst.c — SetupDiGetClassDevsA
pub unsafe extern "win64" fn SetupDiGetClassDevsA(
    _class_guid: *const u8,
    _enumerator: *const u8,
    _hwnd_parent: usize,
    _flags: u32,
) -> usize {
    usize::MAX // INVALID_HANDLE_VALUE
}

/// SetupDiEnumDeviceInterfaces — iterate interface entries in a device set.
///
/// Returns FALSE (0) immediately so SDL2 stops enumeration.
/// Wine ref: dlls/setupapi/devinst.c — SetupDiEnumDeviceInterfaces
pub unsafe extern "win64" fn SetupDiEnumDeviceInterfaces(
    _devinfo: usize,
    _devinfo_data: *const u8,
    _interface_class_guid: *const u8,
    _member_index: u32,
    _device_interface_data: *mut u8,
) -> i32 {
    0 // FALSE
}

/// SetupDiGetDeviceInterfaceDetailA — get detail for one interface entry.
///
/// Returns FALSE (0); SDL2 checks the return and skips this entry.
/// Wine ref: dlls/setupapi/devinst.c — SetupDiGetDeviceInterfaceDetailA
pub unsafe extern "win64" fn SetupDiGetDeviceInterfaceDetailA(
    _devinfo: usize,
    _iface_data: *const u8,
    _detail: *mut u8,
    _size: u32,
    _req_size: *mut u32,
    _info_data: *mut u8,
) -> i32 {
    0 // FALSE
}

/// SetupDiEnumDeviceInfo — iterate device info elements in a device set.
///
/// Returns FALSE (0) immediately so SDL2 stops enumeration.
/// Wine ref: dlls/setupapi/devinst.c — SetupDiEnumDeviceInfo
pub unsafe extern "win64" fn SetupDiEnumDeviceInfo(
    _devinfo: usize,
    _member_index: u32,
    _devinfo_data: *mut u8,
) -> i32 {
    0 // FALSE
}

/// SetupDiGetDeviceRegistryPropertyA — read a device registry property.
///
/// Returns FALSE (0); there are no devices, so there is no property to read.
/// Wine ref: dlls/setupapi/devinst.c — SetupDiGetDeviceRegistryPropertyA
pub unsafe extern "win64" fn SetupDiGetDeviceRegistryPropertyA(
    _devinfo: usize,
    _devinfo_data: *const u8,
    _prop: u32,
    _reg_type: *mut u32,
    _buf: *mut u8,
    _size: u32,
    _req: *mut u32,
) -> i32 {
    0 // FALSE
}

/// SetupDiDestroyDeviceInfoList — free a device info set handle.
///
/// Returns TRUE (1). The handle we returned (INVALID_HANDLE_VALUE) is a
/// sentinel, so there is nothing to free.
/// Wine ref: dlls/setupapi/devinst.c — SetupDiDestroyDeviceInfoList
pub unsafe extern "win64" fn SetupDiDestroyDeviceInfoList(_devinfo: usize) -> i32 {
    1 // TRUE
}

// ── Phase A stubs ─────────────────────────────────────────────────

#[allow(unused_variables)]
pub unsafe extern "win64" fn cm_get_device_id_a(
    psz_device_id: *mut u8,
    buffer_len: u32,
    ul_flags: u32,
    p_veto: *mut u8,
) -> i32 {
    0
}

#[allow(unused_variables)]
pub unsafe extern "win64" fn cm_get_parent(
    p_parent: *mut u32,
    dev_inst: u32,
    ul_flags: u32,
) -> i32 {
    0
}

#[allow(unused_variables)]
pub unsafe extern "win64" fn cm_locate_dev_node_a(
    p_dev_node: *mut u32,
    p_device_id: *const u8,
    ul_flags: u32,
) -> i32 {
    0
}

// ── OpenMPT Phase A stubs ────────────────────────────────────────────────

#[allow(unused_variables)]
pub unsafe extern "win64" fn setup_di_open_device_interface_reg_key(
    _devinfo: usize,
    _iface_data: *const u8,
    _reserved: u32,
    _sam_desired: u32,
) -> usize {
    usize::MAX // INVALID_HANDLE_VALUE
}

#[allow(unused_variables)]
pub unsafe extern "win64" fn setup_di_get_device_interface_alias(
    _devinfo: usize,
    _iface_data: *const u8,
    _alias_guid: *const u8,
    _alias_data: *mut u8,
) -> i32 {
    0 // FALSE
}

#[allow(unused_variables)]
pub unsafe extern "win64" fn setup_di_get_device_registry_property_w(
    _devinfo: usize,
    _devinfo_data: *const u8,
    _property: u32,
    _property_reg_data_type: *mut u32,
    _property_buffer: *mut u8,
    _property_buffer_size: u32,
    _required_size: *mut u32,
) -> i32 {
    0 // FALSE
}

#[allow(unused_variables)]
pub unsafe extern "win64" fn setup_di_get_class_devs_w(
    _class_guid: *const u8,
    _enumerator: *const u16,
    _hwnd_parent: usize,
    _flags: u32,
) -> usize {
    usize::MAX // INVALID_HANDLE_VALUE
}

#[allow(unused_variables)]
pub unsafe extern "win64" fn setup_di_get_device_interface_detail_w(
    _devinfo: usize,
    _iface_data: *const u8,
    _detail_data: *mut u8,
    _detail_size: u32,
    _required_size: *mut u32,
    _devinfo_data: *mut u8,
) -> i32 {
    0 // FALSE
}

// ── DLL Resolver ─────────────────────────────────────────────────────────────

/// Resolve a setupapi.dll import to a function pointer.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("setupapi.dll") {
        return None;
    }

    match func {
        "SetupDiGetClassDevsA" => Some(SetupDiGetClassDevsA as *const () as usize),
        "SetupDiEnumDeviceInterfaces" => Some(SetupDiEnumDeviceInterfaces as *const () as usize),
        "SetupDiGetDeviceInterfaceDetailA" => {
            Some(SetupDiGetDeviceInterfaceDetailA as *const () as usize)
        }
        "SetupDiEnumDeviceInfo" => Some(SetupDiEnumDeviceInfo as *const () as usize),
        "SetupDiGetDeviceRegistryPropertyA" => {
            Some(SetupDiGetDeviceRegistryPropertyA as *const () as usize)
        }
        "SetupDiDestroyDeviceInfoList" => Some(SetupDiDestroyDeviceInfoList as *const () as usize),
        // ── Phase A stubs ─────────────────────────────────────────────────
        "CM_Get_Device_IDA" => Some(
            cm_get_device_id_a as unsafe extern "win64" fn(_, _, _, _) -> _ as *const () as usize,
        ),
        "CM_Get_Parent" => {
            Some(cm_get_parent as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize)
        }
        "CM_Locate_DevNodeA" => Some(
            cm_locate_dev_node_a as unsafe extern "win64" fn(_, _, _) -> _ as *const () as usize,
        ),
        // ── OpenMPT Phase A stubs ──────────────────────────────────────────
        "SetupDiOpenDeviceInterfaceRegKey" => Some(
            setup_di_open_device_interface_reg_key as unsafe extern "win64" fn(_, _, _, _) -> _
                as *const () as usize,
        ),
        "SetupDiGetDeviceInterfaceAlias" => Some(
            setup_di_get_device_interface_alias as unsafe extern "win64" fn(_, _, _, _) -> _
                as *const () as usize,
        ),
        "SetupDiGetDeviceRegistryPropertyW" => Some(
            setup_di_get_device_registry_property_w
                as unsafe extern "win64" fn(_, _, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SetupDiGetClassDevsW" => Some(
            setup_di_get_class_devs_w as unsafe extern "win64" fn(_, _, _, _) -> _ as *const ()
                as usize,
        ),
        "SetupDiGetDeviceInterfaceDetailW" => Some(
            setup_di_get_device_interface_detail_w
                as unsafe extern "win64" fn(_, _, _, _, _, _) -> _ as *const ()
                as usize,
        ),
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_all_exports() {
        let syms = [
            "SetupDiGetClassDevsA",
            "SetupDiEnumDeviceInterfaces",
            "SetupDiGetDeviceInterfaceDetailA",
            "SetupDiEnumDeviceInfo",
            "SetupDiGetDeviceRegistryPropertyA",
            "SetupDiDestroyDeviceInfoList",
        ];
        for sym in &syms {
            assert!(
                resolve("setupapi.dll", sym).is_some(),
                "missing export: {sym}"
            );
            // Case-insensitive DLL name must also work.
            assert!(
                resolve("SETUPAPI.DLL", sym).is_some(),
                "case-insensitive miss for: {sym}"
            );
        }
    }

    #[test]
    fn resolve_wrong_dll() {
        assert!(resolve("kernel32.dll", "SetupDiGetClassDevsA").is_none());
        assert!(resolve("user32.dll", "SetupDiDestroyDeviceInfoList").is_none());
    }
}
