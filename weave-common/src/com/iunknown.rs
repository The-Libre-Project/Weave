use super::guid::IID_IUNKNOWN;

#[cfg(test)]
use super::guid::GUID;

const S_OK: u32 = 0;
const E_NOINTERFACE: u32 = 0x8000_4002;

#[repr(C)]
pub struct IUnknownVtbl {
    pub query_interface:
        unsafe extern "win64" fn(*mut IUnknownImpl, *const u8, *mut *mut ()) -> u32,
    pub add_ref: unsafe extern "win64" fn(*mut IUnknownImpl) -> u32,
    pub release: unsafe extern "win64" fn(*mut IUnknownImpl) -> u32,
}

#[repr(C)]
pub struct IUnknownImpl {
    pub vtable: *const IUnknownVtbl,
    pub ref_count: u32,
}

impl IUnknownImpl {
    pub fn new() -> Box<Self> {
        Box::new(IUnknownImpl {
            vtable: &IUNKNOWN_VTBL,
            ref_count: 1,
        })
    }
}

unsafe impl Send for IUnknownImpl {}
unsafe impl Sync for IUnknownImpl {}

static IUNKNOWN_VTBL: IUnknownVtbl = IUnknownVtbl {
    query_interface: iunknown_query_interface,
    add_ref: iunknown_add_ref,
    release: iunknown_release,
};

unsafe extern "win64" fn iunknown_query_interface(
    this: *mut IUnknownImpl,
    riid: *const u8,
    ppv: *mut *mut (),
) -> u32 {
    if ppv.is_null() {
        return 0x8007_0057;
    }
    unsafe { *ppv = std::ptr::null_mut() };

    if riid.is_null() {
        return 0x8007_0057;
    }

    let iid_bytes = unsafe { std::ptr::read_unaligned(riid as *const [u8; 16]) };
    if iid_bytes == IID_IUNKNOWN.to_bytes() {
        unsafe {
            (*this).ref_count += 1;
            *ppv = this as *mut ();
        }
        S_OK
    } else {
        E_NOINTERFACE
    }
}

unsafe extern "win64" fn iunknown_add_ref(this: *mut IUnknownImpl) -> u32 {
    let count = unsafe { (*this).ref_count + 1 };
    unsafe { (*this).ref_count = count };
    count
}

unsafe extern "win64" fn iunknown_release(this: *mut IUnknownImpl) -> u32 {
    let prev = unsafe { (*this).ref_count };
    let new = prev - 1;
    if new == 0 {
        unsafe { drop(Box::from_raw(this)) };
    } else {
        unsafe { (*this).ref_count = new };
    }
    new
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call_qi(obj: *mut IUnknownImpl, riid: *const u8, ppv: *mut *mut ()) -> u32 {
        let vtbl = unsafe { &*(*obj).vtable };
        unsafe { (vtbl.query_interface)(obj, riid, ppv) }
    }

    fn call_add_ref(obj: *mut IUnknownImpl) -> u32 {
        let vtbl = unsafe { &*(*obj).vtable };
        unsafe { (vtbl.add_ref)(obj) }
    }

    fn call_release(obj: *mut IUnknownImpl) -> u32 {
        let vtbl = unsafe { &*(*obj).vtable };
        unsafe { (vtbl.release)(obj) }
    }

    fn make_iunknown() -> *mut IUnknownImpl {
        let obj = IUnknownImpl::new();
        Box::into_raw(obj)
    }

    #[test]
    fn iunknown_initial_refcount() {
        let ptr = make_iunknown();
        unsafe {
            assert_eq!((*ptr).ref_count, 1);
            call_release(ptr);
        }
    }

    #[test]
    fn iunknown_add_ref_increments() {
        let ptr = make_iunknown();
        unsafe {
            let count = call_add_ref(ptr);
            assert_eq!(count, 2);
            assert_eq!((*ptr).ref_count, 2);
            call_release(ptr);
            call_release(ptr);
        }
    }

    #[test]
    fn iunknown_release_decrements_and_frees() {
        let ptr = make_iunknown();
        unsafe {
            call_add_ref(ptr);
            let c1 = call_release(ptr);
            assert_eq!(c1, 1);
            let c2 = call_release(ptr);
            assert_eq!(c2, 0);
        }
    }

    #[test]
    fn iunknown_query_interface_self_succeeds() {
        let ptr = make_iunknown();
        unsafe {
            let iid = IID_IUNKNOWN.to_bytes();
            let mut ppv: *mut () = std::ptr::null_mut();
            let hr = call_qi(ptr, iid.as_ptr(), &mut ppv);
            assert_eq!(hr, S_OK);
            assert_eq!(ppv, ptr as *mut ());
            assert_eq!((*ptr).ref_count, 2);
            call_release(ptr);
            call_release(ptr);
        }
    }

    #[test]
    fn iunknown_query_interface_unknown_fails() {
        let ptr = make_iunknown();
        unsafe {
            let unknown_iid = GUID::from_bytes(&[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            ]);
            let mut ppv: *mut () = std::ptr::null_mut();
            let hr = call_qi(ptr, unknown_iid.to_bytes().as_ptr(), &mut ppv);
            assert_eq!(hr, E_NOINTERFACE);
            assert!(ppv.is_null());
            assert_eq!((*ptr).ref_count, 1);
            call_release(ptr);
        }
    }

    #[test]
    fn iunknown_query_interface_null_ppv_returns_error() {
        let ptr = make_iunknown();
        unsafe {
            let iid = IID_IUNKNOWN.to_bytes();
            let hr = call_qi(ptr, iid.as_ptr(), std::ptr::null_mut());
            assert_ne!(hr, S_OK);
            call_release(ptr);
        }
    }
}
