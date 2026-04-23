//! Probe gate for _Mtx_* and _Cnd_* real pthread backing.
//!
//! A2: _Mtx_init_in_situ on a zeroed 64-byte buffer returns 0
//! A3: _Mtx_lock on that buffer returns 0
//! A4: _Mtx_unlock on that buffer returns 0
//! A5: _Mtx_destroy_in_situ on that buffer completes without crashing

use std::ffi::c_void;
use weave_msvcp140::{mtx_destroy_in_situ, mtx_init_in_situ, mtx_lock, mtx_unlock};

/// 64-byte zeroed buffer — larger than pthread_mutex_t on Linux x86_64 (40 bytes).
fn zeroed_buf() -> [u8; 64] {
    [0u8; 64]
}

#[test]
fn a2_mtx_init_in_situ_returns_zero() {
    let mut buf = zeroed_buf();
    let ret = unsafe { mtx_init_in_situ(buf.as_mut_ptr() as *mut c_void, 0) };
    assert_eq!(ret, 0, "A2: _Mtx_init_in_situ must return 0 (_Thrd_success)");
    // cleanup
    unsafe {
        mtx_destroy_in_situ(buf.as_mut_ptr() as *mut c_void, 0, 0, 0);
    }
}

#[test]
fn a3_mtx_lock_returns_zero() {
    let mut buf = zeroed_buf();
    unsafe {
        mtx_init_in_situ(buf.as_mut_ptr() as *mut c_void, 0);
        let ret = mtx_lock(buf.as_mut_ptr() as *mut c_void, 0, 0, 0);
        assert_eq!(ret, 0, "A3: _Mtx_lock must return 0 (_Thrd_success)");
        // unlock before destroy to avoid EBUSY on non-recursive mutex
        mtx_unlock(buf.as_mut_ptr() as *mut c_void, 0, 0, 0);
        mtx_destroy_in_situ(buf.as_mut_ptr() as *mut c_void, 0, 0, 0);
    }
}

#[test]
fn a4_mtx_unlock_returns_zero() {
    let mut buf = zeroed_buf();
    unsafe {
        mtx_init_in_situ(buf.as_mut_ptr() as *mut c_void, 0);
        mtx_lock(buf.as_mut_ptr() as *mut c_void, 0, 0, 0);
        let ret = mtx_unlock(buf.as_mut_ptr() as *mut c_void, 0, 0, 0);
        assert_eq!(ret, 0, "A4: _Mtx_unlock must return 0 (_Thrd_success)");
        mtx_destroy_in_situ(buf.as_mut_ptr() as *mut c_void, 0, 0, 0);
    }
}

#[test]
fn a5_mtx_destroy_in_situ_does_not_crash() {
    let mut buf = zeroed_buf();
    unsafe {
        mtx_init_in_situ(buf.as_mut_ptr() as *mut c_void, 0);
        // A5: must not crash
        mtx_destroy_in_situ(buf.as_mut_ptr() as *mut c_void, 0, 0, 0);
    }
}

#[test]
fn recursive_mutex_init_returns_zero() {
    let mut buf = zeroed_buf();
    // flags bit 0x100 = recursive
    let ret = unsafe { mtx_init_in_situ(buf.as_mut_ptr() as *mut c_void, 0x100) };
    assert_eq!(ret, 0, "recursive _Mtx_init_in_situ must return 0");
    unsafe {
        mtx_destroy_in_situ(buf.as_mut_ptr() as *mut c_void, 0, 0, 0);
    }
}
