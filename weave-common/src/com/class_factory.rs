use super::guid::{IID_ICLASSFACTORY, IID_IUNKNOWN};

#[cfg(test)]
use super::guid::GUID;

const S_OK: u32 = 0;
const E_NOINTERFACE: u32 = 0x8000_4002;
const E_NOTIMPL: u32 = 0x8000_4001;

#[repr(C)]
pub struct IClassFactoryVtbl {
    pub query_interface:
        unsafe extern "win64" fn(*mut IClassFactoryImpl, *const u8, *mut *mut ()) -> u32,
    pub add_ref: unsafe extern "win64" fn(*mut IClassFactoryImpl) -> u32,
    pub release: unsafe extern "win64" fn(*mut IClassFactoryImpl) -> u32,
    pub create_instance:
        unsafe extern "win64" fn(*mut IClassFactoryImpl, *mut (), *const u8, *mut *mut ()) -> u32,
    pub lock_server: unsafe extern "win64" fn(*mut IClassFactoryImpl, i32) -> u32,
}

#[repr(C)]
pub struct IClassFactoryImpl {
    pub vtable: *const IClassFactoryVtbl,
    pub ref_count: u32,
}

impl IClassFactoryImpl {
    pub fn new() -> Box<Self> {
        Box::new(IClassFactoryImpl {
            vtable: &ICLASSFACTORY_VTBL,
            ref_count: 1,
        })
    }
}

unsafe impl Send for IClassFactoryImpl {}
unsafe impl Sync for IClassFactoryImpl {}

static ICLASSFACTORY_VTBL: IClassFactoryVtbl = IClassFactoryVtbl {
    query_interface: classfactory_query_interface,
    add_ref: classfactory_add_ref,
    release: classfactory_release,
    create_instance: classfactory_create_instance,
    lock_server: classfactory_lock_server,
};

unsafe extern "win64" fn classfactory_query_interface(
    this: *mut IClassFactoryImpl,
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
    if iid_bytes == IID_IUNKNOWN.to_bytes() || iid_bytes == IID_ICLASSFACTORY.to_bytes() {
        unsafe {
            (*this).ref_count += 1;
            *ppv = this as *mut ();
        }
        S_OK
    } else {
        E_NOINTERFACE
    }
}

unsafe extern "win64" fn classfactory_add_ref(this: *mut IClassFactoryImpl) -> u32 {
    let count = unsafe { (*this).ref_count + 1 };
    unsafe { (*this).ref_count = count };
    count
}

unsafe extern "win64" fn classfactory_release(this: *mut IClassFactoryImpl) -> u32 {
    let prev = unsafe { (*this).ref_count };
    let new = prev - 1;
    if new == 0 {
        unsafe { drop(Box::from_raw(this)) };
    } else {
        unsafe { (*this).ref_count = new };
    }
    new
}

unsafe extern "win64" fn classfactory_create_instance(
    _this: *mut IClassFactoryImpl,
    _p_unk_outer: *mut (),
    _riid: *const u8,
    _ppv: *mut *mut (),
) -> u32 {
    E_NOTIMPL
}

unsafe extern "win64" fn classfactory_lock_server(
    _this: *mut IClassFactoryImpl,
    _f_lock: i32,
) -> u32 {
    S_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::com::iunknown::IUnknownImpl;

    fn call_qi(obj: *mut IClassFactoryImpl, riid: *const u8, ppv: *mut *mut ()) -> u32 {
        let vtbl = unsafe { &*(*obj).vtable };
        unsafe { (vtbl.query_interface)(obj, riid, ppv) }
    }

    fn call_add_ref(obj: *mut IClassFactoryImpl) -> u32 {
        let vtbl = unsafe { &*(*obj).vtable };
        unsafe { (vtbl.add_ref)(obj) }
    }

    fn call_release(obj: *mut IClassFactoryImpl) -> u32 {
        let vtbl = unsafe { &*(*obj).vtable };
        unsafe { (vtbl.release)(obj) }
    }

    fn call_create_instance(
        obj: *mut IClassFactoryImpl,
        outer: *mut (),
        riid: *const u8,
        ppv: *mut *mut (),
    ) -> u32 {
        let vtbl = unsafe { &*(*obj).vtable };
        unsafe { (vtbl.create_instance)(obj, outer, riid, ppv) }
    }

    fn call_lock_server(obj: *mut IClassFactoryImpl, fl: i32) -> u32 {
        let vtbl = unsafe { &*(*obj).vtable };
        unsafe { (vtbl.lock_server)(obj, fl) }
    }

    fn make_classfactory() -> *mut IClassFactoryImpl {
        let obj = IClassFactoryImpl::new();
        Box::into_raw(obj)
    }

    #[test]
    fn classfactory_initial_refcount() {
        let ptr = make_classfactory();
        unsafe {
            assert_eq!((*ptr).ref_count, 1);
            call_release(ptr);
        }
    }

    #[test]
    fn classfactory_qi_for_iunknown_succeeds() {
        let ptr = make_classfactory();
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
    fn classfactory_qi_for_iclassfactory_succeeds() {
        let ptr = make_classfactory();
        unsafe {
            let iid = IID_ICLASSFACTORY.to_bytes();
            let mut ppv: *mut () = std::ptr::null_mut();
            let hr = call_qi(ptr, iid.as_ptr(), &mut ppv);
            assert_eq!(hr, S_OK);
            assert_eq!(ppv, ptr as *mut ());
            call_release(ptr);
            call_release(ptr);
        }
    }

    #[test]
    fn classfactory_qi_for_unknown_fails() {
        let ptr = make_classfactory();
        unsafe {
            let unknown_iid =
                GUID::from_bytes(&[0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            let mut ppv: *mut () = std::ptr::null_mut();
            let hr = call_qi(ptr, unknown_iid.to_bytes().as_ptr(), &mut ppv);
            assert_eq!(hr, E_NOINTERFACE);
            assert!(ppv.is_null());
            call_release(ptr);
        }
    }

    #[test]
    fn classfactory_create_instance_returns_e_notimpl() {
        let ptr = make_classfactory();
        unsafe {
            let iid = IID_IUNKNOWN.to_bytes();
            let mut ppv: *mut () = std::ptr::null_mut();
            let hr = call_create_instance(ptr, std::ptr::null_mut(), iid.as_ptr(), &mut ppv);
            assert_eq!(hr, E_NOTIMPL);
            assert!(ppv.is_null());
            call_release(ptr);
        }
    }

    #[test]
    fn classfactory_lock_server_returns_s_ok() {
        let ptr = make_classfactory();
        unsafe {
            let hr = call_lock_server(ptr, 1);
            assert_eq!(hr, S_OK);
            let hr = call_lock_server(ptr, 0);
            assert_eq!(hr, S_OK);
            call_release(ptr);
        }
    }

    #[test]
    fn classfactory_add_ref_release_roundtrip() {
        let ptr = make_classfactory();
        unsafe {
            call_add_ref(ptr);
            let c = call_release(ptr);
            assert_eq!(c, 1);
            let c = call_release(ptr);
            assert_eq!(c, 0);
        }
    }
}
