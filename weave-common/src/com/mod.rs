/// COM vtable dereference pattern for `repr(C)` objects in probe gates
/// =====================================================================
///
/// A COM object pointer (`obj: *const *const VtableType`) is a pointer to a struct
/// whose **first field** is the vtable pointer. Getting the vtable pointer from a
/// probe gate requires two steps:
///
/// ```text
/// // CORRECT — dereference the object pointer first, then access the vtable field:
/// let vtable = (*obj).vtable as *const usize;
/// let slot_fn: SlotFnType = transmute(*vtable.add(N));
///
/// // WRONG — this treats the vtable-pointer value as if it were a usize directly.
/// //         The cast succeeds but produces the wrong address (the vtable pointer's
/// //         bit pattern, not the function pointer stored at slot N):
/// let vtable = *obj as *const usize;  // BUG: fixed in commit ea52048
/// ```
///
/// Why it is wrong: `obj` is `*const *const VtableType`.  `*obj` dereferences to
/// `*const VtableType` — a raw pointer whose numeric value is the vtable's address.
/// Casting that directly to `*const usize` makes `vtable` hold the vtable address as
/// a number, then `.add(N)` walks from that address — correct.  But if the struct has
/// a named field (`pub vtable: *const [usize; N]`) you must access it by name:
/// `(*obj).vtable`, not `*obj`.  `*obj` on a `*const ShellLinkObject` would give the
/// whole `ShellLinkObject` value, not just the first field.
///
/// Rule of thumb: always write `(*obj).vtable` and let the compiler enforce the type.
/// If `(*obj)` is the struct, `.vtable` is the vtable pointer.  Then `as *const usize`
/// is safe and correct.
#[cfg(target_arch = "x86_64")]
pub mod shell_link;

pub mod guid;

#[cfg(target_arch = "x86_64")]
pub mod iunknown;
#[cfg(target_arch = "x86_64")]
pub mod class_factory;
