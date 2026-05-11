//! wldap32.dll stubs for Weave — LDAP client.
//!
//! curl.exe imports 17 LDAP symbols for optional LDAP URL support.
//! These are all no-op stubs returning 0/null. LDAP functionality
//! is not supported; stubs exist solely to satisfy IAT resolution.

#![allow(unused_variables, non_snake_case, clippy::missing_safety_doc)]

/// ber_free — free a BER element.
pub unsafe extern "win64" fn ber_free(_pBerElement: usize, _fbuf: i32) {}

/// ldap_bind_s — synchronous bind to an LDAP directory.
pub unsafe extern "win64" fn ldap_bind_s(
    _ld: usize,
    _dn: usize,
    _cred: usize,
    _method: u32,
) -> u32 {
    0x51 // LDAP_NOT_SUPPORTED
}

/// ldap_err2string — convert LDAP error code to string.
pub unsafe extern "win64" fn ldap_err2string(_err: u32) -> usize {
    0
}

/// ldap_first_attribute — get first attribute of an LDAP entry.
pub unsafe extern "win64" fn ldap_first_attribute(
    _ld: usize,
    _entry: usize,
    _ppBer: usize,
) -> usize {
    0
}

/// ldap_first_entry — get first entry in an LDAP message.
pub unsafe extern "win64" fn ldap_first_entry(_ld: usize, _res: usize) -> usize {
    0
}

/// ldap_get_dn — get the DN of an LDAP entry.
pub unsafe extern "win64" fn ldap_get_dn(_ld: usize, _entry: usize) -> usize {
    0
}

/// ldap_get_values_len — get attribute values with lengths.
pub unsafe extern "win64" fn ldap_get_values_len(_ld: usize, _entry: usize, _attr: usize) -> usize {
    0
}

/// ldap_init — initialize an LDAP handle.
pub unsafe extern "win64" fn ldap_init(_HostName: usize, _PortNumber: u32) -> usize {
    0
}

/// ldap_memfree — free memory allocated by LDAP.
pub unsafe extern "win64" fn ldap_memfree(_block: usize) {}

/// ldap_msgfree — free LDAP message result.
pub unsafe extern "win64" fn ldap_msgfree(_res: usize) -> i32 {
    0
}

/// ldap_next_attribute — get next attribute of an LDAP entry.
pub unsafe extern "win64" fn ldap_next_attribute(
    _ld: usize,
    _entry: usize,
    _BerElement: usize,
) -> usize {
    0
}

/// ldap_next_entry — get next entry in an LDAP message.
pub unsafe extern "win64" fn ldap_next_entry(_ld: usize, _entry: usize) -> usize {
    0
}

/// ldap_search_s — synchronous LDAP search.
pub unsafe extern "win64" fn ldap_search_s(
    _ld: usize,
    _base: usize,
    _scope: i32,
    _filter: usize,
    _attrs: usize,
    _attrsonly: i32,
    _res: usize,
) -> u32 {
    0x51 // LDAP_NOT_SUPPORTED
}

/// ldap_set_option — set LDAP session option.
pub unsafe extern "win64" fn ldap_set_option(_ld: usize, _option: i32, _invalue: usize) -> u32 {
    0
}

/// ldap_simple_bind_s — synchronous simple bind.
pub unsafe extern "win64" fn ldap_simple_bind_s(_ld: usize, _dn: usize, _passwd: usize) -> u32 {
    0x51 // LDAP_NOT_SUPPORTED
}

/// ldap_sslinit — initialize SSL-enabled LDAP handle.
pub unsafe extern "win64" fn ldap_sslinit(
    _HostName: usize,
    _PortNumber: u32,
    _secure: i32,
) -> usize {
    0
}

/// ldap_unbind_s — unbind from LDAP directory.
pub unsafe extern "win64" fn ldap_unbind_s(_ld: usize) -> u32 {
    0
}

/// ldap_value_free_len — free array of berval values.
pub unsafe extern "win64" fn ldap_value_free_len(_vals: usize) {}

/// Resolve a wldap32.dll import to a function pointer.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("wldap32.dll") {
        return None;
    }
    match func {
        "ber_free" => Some(ber_free as *const () as usize),
        "ldap_bind_s" => Some(ldap_bind_s as *const () as usize),
        "ldap_err2string" => Some(ldap_err2string as *const () as usize),
        "ldap_first_attribute" => Some(ldap_first_attribute as *const () as usize),
        "ldap_first_entry" => Some(ldap_first_entry as *const () as usize),
        "ldap_get_dn" => Some(ldap_get_dn as *const () as usize),
        "ldap_get_values_len" => Some(ldap_get_values_len as *const () as usize),
        "ldap_init" => Some(ldap_init as *const () as usize),
        "ldap_memfree" => Some(ldap_memfree as *const () as usize),
        "ldap_msgfree" => Some(ldap_msgfree as *const () as usize),
        "ldap_next_attribute" => Some(ldap_next_attribute as *const () as usize),
        "ldap_next_entry" => Some(ldap_next_entry as *const () as usize),
        "ldap_search_s" => Some(ldap_search_s as *const () as usize),
        "ldap_set_option" => Some(ldap_set_option as *const () as usize),
        "ldap_simple_bind_s" => Some(ldap_simple_bind_s as *const () as usize),
        "ldap_sslinit" => Some(ldap_sslinit as *const () as usize),
        "ldap_unbind_s" => Some(ldap_unbind_s as *const () as usize),
        "ldap_value_free_len" => Some(ldap_value_free_len as *const () as usize),
        _ => None,
    }
}
