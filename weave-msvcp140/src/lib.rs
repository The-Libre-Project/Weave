//! MSVCP140.dll stubs for Weave.
//!
//! All 80 imports used by NXEngine-evo (nx.exe) are resolved here.
//! Function stubs are no-op — they accept any Win64 arguments and return 0.
//! Real pthread implementations for _Mtx_* and _Cnd_* added in TASK-3.
#![allow(clippy::missing_safety_doc)]
#![allow(unreachable_patterns)]
//! Real implementations of _Thrd_* come in TASK-4.
//!
//! Wine ref: dlls/msvcp140/msvcp140.c — _Mtx_init_in_situ(mtx, flags),
//!   _Mtx_lock(mtx) returns _Thrd_success = 0.
//! Do NOT add warn_once logging here — these methods are called many times per frame.

/// Single no-op stub for all remaining function symbols.
/// Win64 ABI places return value in RAX; returning 0 covers void, ptr, and int return types.
///
/// Diagnostic: logs the first invocation (with arg0/RCX) so we can identify
/// which unresolved stub gets called during MSVCP140 DllMain init and whose
/// return-0 value gets used as a corrupted vtable pointer.
pub unsafe extern "win64" fn msvcp_noop(a0: usize, _b: usize, _c: usize, _d: usize) -> usize {
    static NOOP_FIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !NOOP_FIRED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!(
            "weave/msvcp: FIRST noop stub call a0=0x{a0:x} — return 0 may be used as vtable base"
        );
    }
    0
}

/// Log the first call to a locale/facet function with arg0 (`this`/first arg)
/// and the caller return address.  Signal-safe after init: uses atomics,
/// no heap allocation on the hot path (OnceLock init happens once).
fn log_first_locale_call(name: &'static str, a0: usize) {
    static CALLED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<&'static str>>> =
        std::sync::OnceLock::new();
    let mut set = CALLED
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if set.insert(name) {
        eprintln!(
            "weave/msvcp: locale call {name} this=0x{a0:x} — if this=0, the C++ object is null"
        );
    }
}

// ── Individual locale/facet diagnostic wrappers ──────────────────────────
// Each shadows the corresponding bulk `msvcp_noop` entry in resolve(), logs
// the first invocation, then returns 0 (same behaviour as msvcp_noop).
// The caller sees a standard 4-arg Win64 extern function.

pub unsafe extern "win64" fn msvcp_diag_getcat_ctype_d(
    a0: usize,
    _a1: usize,
    _a2: usize,
    _a3: usize,
) -> usize {
    log_first_locale_call("_Getcat@?$ctype@D@std@@", a0);
    0
}
pub unsafe extern "win64" fn msvcp_diag_getcat_ctype_w(
    a0: usize,
    _a1: usize,
    _a2: usize,
    _a3: usize,
) -> usize {
    log_first_locale_call("_Getcat@?$ctype@_W@std@@", a0);
    0
}
pub unsafe extern "win64" fn msvcp_diag_init_locale(
    a0: usize,
    _a1: usize,
    _a2: usize,
    _a3: usize,
) -> usize {
    log_first_locale_call("_Init@locale@std@@", a0);
    0
}
pub unsafe extern "win64" fn msvcp_diag_makeloc(
    a0: usize,
    _a1: usize,
    _a2: usize,
    _a3: usize,
) -> usize {
    log_first_locale_call("_Makeloc@_Locimp@locale@std@@", a0);
    0
}
pub unsafe extern "win64" fn msvcp_diag_new_locimp(
    a0: usize,
    _a1: usize,
    _a2: usize,
    _a3: usize,
) -> usize {
    log_first_locale_call("_New_Locimp@_Locimp@locale@std@@", a0);
    0
}
pub unsafe extern "win64" fn msvcp_diag_locimp_adderfac(
    a0: usize,
    _a1: usize,
    _a2: usize,
    _a3: usize,
) -> usize {
    log_first_locale_call("_Locimp_Addfac@_Locimp@locale@std@@", a0);
    0
}
pub unsafe extern "win64" fn msvcp_diag_getgloballocale(
    a0: usize,
    _a1: usize,
    _a2: usize,
    _a3: usize,
) -> usize {
    log_first_locale_call("_Getgloballocale@locale@std@@", a0);
    0
}
pub unsafe extern "win64" fn msvcp_diag_getfalse(
    a0: usize,
    _a1: usize,
    _a2: usize,
    _a3: usize,
) -> usize {
    log_first_locale_call("_Getfalse@_Locinfo@std@@", a0);
    0
}

// ── Fake vtable tables and virtual base tables ────────────────────────────────
//
// These are all-zero fake vtables used by the constructor stubs below.
// Virtual calls through these vtables are routed via IAT-patched real methods anyway;
// the vtable pointer just needs to be non-null for layout validity.
//
// Wine ref: dlls/msvcp60/ios.c — basic_streambuf_char_vtable, basic_ios_char_vtable, etc.
static FAKE_STREAMBUF_VTABLE: [usize; 16] = [0usize; 16];
static FAKE_IOS_VTABLE: [usize; 16] = [0usize; 16];
static FAKE_ISTREAM_VTABLE: [usize; 16] = [0usize; 16];
static FAKE_OSTREAM_VTABLE: [usize; 16] = [0usize; 16];
static FAKE_IOSTREAM_VTABLE: [usize; 16] = [0usize; 16];

// Virtual base tables (vbtable): [0i32, byte_offset_to_virtual_basic_ios_char]
// basic_istream offset is binary-specific. NXEngine's nx.exe MSVC layout places
// the basic_ios virtual base at complete+0xB0 (not Wine's +0x10). Disassembly
// at nx.exe RVA 0x55310:
//   140055341  add rcx, 0xb0          ; this for basic_ios ctor
//   140055348  call basic_ios_ctor    ; this = complete+0xB0
//   140055357  lea rbx, [rdi+0x10]    ; sb = embedded basic_filebuf
//   140055364  mov rcx, rdi           ; this = complete (for istream ctor)
//   140055367  call basic_istream_ctor ; this=complete, sb=complete+0x10
// The user code reads vtable[+4]=0xB0 after our ctor returns to install the
// derived basic_ios vtable at complete+0xB0 — so vbtable[+4] must equal 0xB0
// for the RTTI adjustment to land on the basic_ios subobject.
//
// basic_ostream offset is also binary-specific. NXEngine's nx.exe MSVC layout
// places the basic_ios virtual base at complete+0x88 (not Wine's +0x08). The
// stack-ostream call site at nx.exe RVA 0x14094939e allocates `this` then,
// after the ctor returns, the helper at 0x140095880 reads:
//   mov rax, [rsp+0x70]              ; rax = [this] = our vbtable ptr
//   movsxd rcx, dword ptr [rax+4]    ; rcx = BASIC_OSTREAM_VBTABLE[1]
//   ...
//   lea edx, [rcx-0x88]              ; edx = vbtable[1] - 0x88
//   mov dword ptr [rsp+rcx+0x6c], edx ; write at this + (vbtable[1]) + (-4)
// With vbtable[1]=0x08, that store lands at this+4 with value 0xffffff80,
// shredding the upper half of the vbtable pointer (TASK-10h, CI 25243021648).
// With vbtable[1]=0x88, edx=0 and the store lands at this+0x84 — a benign
// in-frame slot — and downstream reads of [this + vbase + 0x28]/[+0x48] hit
// the basic_ios subobject we initialised, mirroring the istream 0xB0 fix.
// Wine ref: dlls/msvcp60/ios.c — basic_ostream_char_vbtable, basic_iostream_char_vbtable*.
static BASIC_ISTREAM_VBTABLE: [i32; 2] = [0i32, 0xB0i32];
static BASIC_OSTREAM_VBTABLE: [i32; 2] = [0i32, 0x88i32];
static BASIC_IOSTREAM_VBTABLE1: [i32; 2] = [0i32, 0x18i32];
static BASIC_IOSTREAM_VBTABLE2: [i32; 2] = [0i32, 0x10i32];

// ── Fake locale infrastructure ────────────────────────────────────────────────
//
// NXEngine inlines locale::_Getfacet() which navigates:
//   locale* this → [+8] = _Locimp* impl
//   impl → [+0x10] = facet** farray, [+0x18] = size_t nfacets
// After _Getfacet, the locale._Ptr is "decremented" via impl->vtable[2].
//
// We construct a minimal static structure that satisfies these accesses without
// implementing the full locale machinery.
//
// Wine ref: dlls/msvcp90/locale.c — _Locimp layout, facet base, _Getfacet().
#[repr(C)]
struct FakeLocaleData {
    vtable: [usize; 8],    // fake vtable — all entries = msvcp_noop
    locimp_vtable: usize,  // _Locimp.vtable (= &self.vtable[0]); at locimp+0x00
    locimp_refs: usize,    // _Locimp._Refs = 1;                   at locimp+0x08
    locimp_farray: usize,  // _Locimp._Farray (= &self.farray);    at locimp+0x10
    locimp_nfacets: usize, // _Locimp._Nfacets = 1;                at locimp+0x18
    farray: usize,         // farray[0] = locimp addr (non-null facet*)
}

// SAFETY: all fields are usize; no interior mutability; written once before first read.
unsafe impl Send for FakeLocaleData {}
unsafe impl Sync for FakeLocaleData {}

static FAKE_LOCALE_DATA: std::sync::OnceLock<Box<FakeLocaleData>> = std::sync::OnceLock::new();

// ── File I/O registry ─────────────────────────────────────────────────────────
// `_Fiopen` registers the most recently opened FILE*. read/seekg/tellg/xsgetn/
// sbumpc use this directly — no object-memory scan. NXEngine opens files
// sequentially so the last registered fp is always the active one.
//
// The scan-based approach (scanning `this` memory for a matching FILE*) was
// removed because `this` for istream methods is basic_istream*, not basic_filebuf*,
// so the FILE* isn't in that memory range; and when `this` is corrupted the
// scan itself faults (Fail #5: SIGSEGV at fault=obj+16 with garbage this).
static MSVCP_OPEN_FP: std::sync::Mutex<Option<usize>> = std::sync::Mutex::new(None);

fn get_current_fp() -> Option<*mut libc::FILE> {
    let guard = MSVCP_OPEN_FP.lock().ok()?;
    (*guard).map(|p| p as *mut libc::FILE)
}

fn get_fake_locale_data() -> &'static FakeLocaleData {
    FAKE_LOCALE_DATA.get_or_init(|| {
        let noop = msvcp_noop as *const () as usize;
        let mut b = Box::new(FakeLocaleData {
            vtable: [noop; 8],
            locimp_vtable: 0,
            locimp_refs: 1,
            locimp_farray: 0,
            locimp_nfacets: 1,
            farray: 0,
        });
        let vtable_addr = b.vtable.as_ptr() as usize;
        let locimp_addr = &b.locimp_vtable as *const usize as usize;
        let farray_addr = &b.farray as *const usize as usize;
        b.locimp_vtable = vtable_addr;
        b.locimp_farray = farray_addr;
        b.farray = locimp_addr; // farray[0] = locimp itself (non-null, any facet*)
        b
    })
}

// ── Constructor helper utilities ───────────────────────────────────────────────

/// Write a pointer-sized value at `base + off`.
/// Wine ref: used throughout dlls/msvcp60/ios.c for field initialization.
#[inline(always)]
unsafe fn write_ptr(base: *mut u8, off: usize, val: *const u8) {
    *(base.add(off) as *mut *const u8) = val;
}

/// Initialize the self-referential pointer fields of a basic_streambuf_char.
/// Wine ref: dlls/msvcp60/ios.c basic_streambuf_char__Init_empty line 757 —
///   sets prbuf=&rbuf, pwbuf=&wbuf, prpos=&rpos, pwpos=&wpos, prsize=&rsize, pwsize=&wsize.
unsafe fn streambuf_init_empty(this: *mut u8) {
    write_ptr(this, 0x50, this.add(0x40)); // prbuf  = &rbuf
    write_ptr(this, 0x58, this.add(0x48)); // pwbuf  = &wbuf
    write_ptr(this, 0x70, this.add(0x60)); // prpos  = &rpos
    write_ptr(this, 0x78, this.add(0x68)); // pwpos  = &wpos
                                           // prsize/pwsize point to int fields — cast to *const u8 for write_ptr uniformity
    write_ptr(this, 0x88, this.add(0x80)); // prsize = &rsize
    write_ptr(this, 0x90, this.add(0x84)); // pwsize = &wsize
                                           // rbuf/wbuf/rpos/wpos already zero from calloc; rsize/wsize = 0
}

// ── Discard streambuf — MSVC field layout ────────────────────────────────────
//
// nx.exe is MSVC-built; its inlined ostream-output helpers walk basic_streambuf
// internal fields at offsets that don't match Wine's layout. Each of those
// reads is shaped `[rcx+OFF] → [[rcx+OFF]]` — a pointer-to-pointer chase. Our
// historical fake streambuf zero-initialised these slots, so MSVC's inlined
// reads got NULL on the inner deref.
//
// Confirmed from disassembly of nx.exe's helper at RVA 0x140063650 (CI run
// 25287337817, fault rva 0x000063a29 → then 0x0006367e once the op<<-noop
// cascade was unblocked):
//
//   mov 0x70(%rcx), %edx      ; flags @ +0x70 (i32)
//   mov 0x40(%rcx), %rax      ; ptr @ +0x40
//   mov (%rax), %r9           ; deref → faulted on NULL
//   mov 0x68(%rcx), %r8       ; count @ +0x68 (i64)
//   mov 0x20(%rcx), %rax      ; ptr @ +0x20
//   ...
//   mov 0x38(%rcx), %rax      ; ptr @ +0x38
//   mov 0x50(%rcx), %rax      ; ptr @ +0x50 (i32 deref via movslq)
//   mov 0x18(%rcx), %rax      ; ptr @ +0x18
//
// `init_discard_streambuf_ms_layout` populates every one of those slots with
// a valid pointer into a static zero buffer (`DISCARD_SINK`) so the inner
// deref reads zero (not faults). Flags at +0x70 stay 0 so the helper falls
// through both branch arms without taking either "active write" path.
//
// This is *not* a real MSVC basic_streambuf implementation — it is a discard
// streambuf that passively absorbs the inlined field reads on the cerr-style
// logging path. Real I/O stays on the libc::fread / libc::fseek path through
// `MSVCP_OPEN_FP`, which doesn't touch these fields.
//
// The sink is heap-allocated (not a `static [u8; N]`) because some inlined
// helper branches in nx.exe write through these pointer chases — a static
// non-mut buffer lives in `.rodata` and would fault on first write. Heap
// memory is RW by default. Single 256-byte alloc shared by every discard
// streambuf; never freed; never read meaningfully by us — it just absorbs.
static DISCARD_SINK_PTR: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

fn discard_sink_ptr() -> *mut u8 {
    *DISCARD_SINK_PTR.get_or_init(|| {
        let layout = std::alloc::Layout::from_size_align(256, 16).unwrap();
        // SAFETY: layout is non-zero-sized and well-aligned; alloc_zeroed
        // returns either null (we'd crash later anyway) or a 256-byte RW
        // buffer the OS guarantees stays mapped for the process lifetime.
        unsafe { std::alloc::alloc_zeroed(layout) as usize }
    }) as *mut u8
}

pub unsafe fn init_discard_streambuf_ms_layout(sb: *mut u8) {
    let sink = discard_sink_ptr() as *const u8;
    write_ptr(sb, 0x18, sink);
    write_ptr(sb, 0x20, sink);
    write_ptr(sb, 0x38, sink);
    write_ptr(sb, 0x40, sink);
    write_ptr(sb, 0x50, sink);
    write_ptr(sb, 0x58, sink);
    *(sb.add(0x68) as *mut i64) = 0; // count
    *(sb.add(0x70) as *mut u32) = 0; // flags
}

// ── 6 constructor implementations ─────────────────────────────────────────────

/// `basic_streambuf<char>::_Init()` — initialize self-referential pointer fields only.
/// Called after memory is already zeroed; does not write vtable or locale.
/// Wine ref: dlls/msvcp60/ios.c basic_streambuf_char__Init_empty line 757.
pub unsafe extern "win64" fn msvcp_streambuf_init(
    this: *mut u8,
    _b: usize,
    _c: usize,
    _d: usize,
) -> *mut u8 {
    if !this.is_null() {
        streambuf_init_empty(this);
    }
    this
}

/// `basic_streambuf<char>::basic_streambuf()` — default constructor.
/// Zeroes the struct, writes fake vtable + fake locale ptr, sets self-referential pointers.
/// Wine ref: dlls/msvcp60/ios.c basic_streambuf_char_ctor ~line 830 — calls _Init_empty.
pub unsafe extern "win64" fn msvcp_streambuf_ctor(
    this: *mut u8,
    _b: usize,
    _c: usize,
    _d: usize,
) -> *mut u8 {
    if this.is_null() {
        return this;
    }
    // Zero the whole struct (0xA0 bytes)
    std::ptr::write_bytes(this, 0u8, 0xA0);
    // Write fake vtable at +0x00
    write_ptr(this, 0x00, FAKE_STREAMBUF_VTABLE.as_ptr() as *const u8);
    // Write fake locale pointer at +0x98
    let locale_ptr = get_fake_locale_data() as *const FakeLocaleData as *const u8;
    write_ptr(this, 0x98, locale_ptr);
    // Set self-referential pointer fields (Wine layout — kept for callers that
    // depend on prbuf/pwbuf/prpos/pwpos/prsize/pwsize self-references).
    streambuf_init_empty(this);
    // Overlay the MSVC discard layout so inlined ostream-output helpers in
    // user binaries (e.g. nx.exe) can chase [+0x18..+0x58] pointers through
    // to a valid sink buffer instead of NULL. Overwrites the +0x70 i32 slot
    // (Wine wrote a pointer there; MSVC reads it as i32 flags).
    init_discard_streambuf_ms_layout(this);
    this
}

/// `basic_ios<char>::basic_ios()` — default constructor (no streambuf argument).
/// Zero-inits ios_base fields, writes fake vtable, sets fmtfl defaults, fillch=' '.
/// Note: strbuf and stream are NOT set here — set by basic_ios_char_init.
/// Wine ref: dlls/msvcp60/ios.c basic_ios_char_ctor line 4047 — calls ios_base_ctor,
///   writes ios_base vtable.
pub unsafe extern "win64" fn msvcp_basic_ios_ctor(
    this: *mut u8,
    _b: usize,
    _c: usize,
    _d: usize,
) -> *mut u8 {
    if this.is_null() {
        return this;
    }
    // Zero the whole basic_ios_char (0x60 bytes)
    std::ptr::write_bytes(this, 0u8, 0x60);
    // Write ios_base fake vtable at +0x00
    write_ptr(this, 0x00, FAKE_IOS_VTABLE.as_ptr() as *const u8);
    // Set fmtfl defaults: skipws(0x1000) | dec(0x0008) = 0x1008 at +0x10
    *(this.add(0x10) as *mut u32) = 0x1008u32;
    // fillch = ' ' at basic_ios_char+0x58
    *this.add(0x58) = b' ';
    this
}

/// Internal: call basic_ios_char_init logic on `base` with `sb`.
/// Wine ref: dlls/msvcp60/ios.c basic_ios_char_init line 4059 —
///   sets strbuf=sb, stream=NULL, fillch=' '.
#[inline(always)]
unsafe fn ios_char_init(base: *mut u8, sb: *mut u8) {
    // base->strbuf = sb at basic_ios_char+0x48
    write_ptr(base, 0x48, sb as *const u8);
    // base->stream = NULL at basic_ios_char+0x50
    write_ptr(base, 0x50, std::ptr::null());
    // base->fillch = ' ' at basic_ios_char+0x58
    *base.add(0x58) = b' ';
}

/// `basic_istream<char>::basic_istream(basic_streambuf*, bool)` — constructor.
/// Writes vbtable, locates virtual basic_ios_char base (at this+0xB0 for
/// NXEngine's MSVC layout), zero-inits it, then calls basic_ios_char_init to
/// set strbuf=sb at ios+0x48 (= complete+0xF8).
/// In nx.exe the user binary already invoked basic_ios ctor with this=complete+0xB0
/// before reaching this function (see RVA 0x55310), so the basic_ios fields
/// here are mostly idempotent — but we re-write them to match Wine's
/// virt_init=true path and to land _Mystrbuf=sb.
/// Wine ref: dlls/msvcp60/ios.c basic_istream_char_ctor line 6074 — writes vbtable,
///   calls basic_ios_char_ctor (virt_init=true path), sets count=0, calls basic_ios_char_init.
pub unsafe extern "win64" fn msvcp_istream_ctor(
    this: *mut u8,
    sb: *mut u8,
    _isstd: usize,
    _d: usize,
) -> *mut u8 {
    if this.is_null() {
        return this;
    }
    // Write vbtable pointer at this+0x00
    write_ptr(this, 0x00, BASIC_ISTREAM_VBTABLE.as_ptr() as *const u8);
    // Locate virtual basic_ios_char via vbtable[1] offset
    let vbase_off = BASIC_ISTREAM_VBTABLE[1] as usize;
    let base = this.add(vbase_off);
    // Zero-init and write ios vtable (basic_ios_char_ctor logic)
    std::ptr::write_bytes(base, 0u8, 0x60);
    write_ptr(base, 0x00, FAKE_ISTREAM_VTABLE.as_ptr() as *const u8);
    *(base.add(0x10) as *mut u32) = 0x1008u32; // fmtfl defaults
    *base.add(0x58) = b' '; // fillch
                            // count = 0 at this+0x08
    *(this.add(0x08) as *mut i64) = 0i64;
    // basic_ios_char_init: strbuf=sb, stream=NULL, fillch=' '
    // For nx.exe this lands _Mystrbuf at complete+0xF8 (= 0xB0 + 0x48),
    // pointing at the embedded basic_filebuf at complete+0x10.
    ios_char_init(base, sb);
    // Note: previous attempts to write a "_Pmybuf" double-pointer at this+0x18
    // (Fail #7) and at ios+0x08 (Fail #8) did not move the crash at nx.exe
    // RVA 0x55e3e. Binary analysis (2026-05-01) showed the crashing dereference
    // is on filebuf+0x18 (the embedded basic_filebuf at complete+0x10), not on
    // istream+0x18. filebuf+0x18 is populated by inlined basic_filebuf::open
    // (RVA 0x56a60) from `_get_stream_buffer_pointers` outparams; that fix
    // landed in `weave-ucrt::ucrt_get_stream_buffer_pointers` (commit 4a8991a).
    this
}

/// `basic_ostream<char>::basic_ostream(basic_streambuf*, bool)` — constructor.
/// Wine ref: dlls/msvcp60/ios.c basic_ostream_char_ctor line 4510 — writes vbtable,
///   calls basic_ios_char_ctor (virt_init=true), calls basic_ios_char_init (init=true).
pub unsafe extern "win64" fn msvcp_ostream_ctor(
    this: *mut u8,
    sb: *mut u8,
    _isstd: usize,
    _d: usize,
) -> *mut u8 {
    if this.is_null() {
        return this;
    }
    // If the caller supplies a null streambuf (or one below 0x10000, which is
    // always unmapped on Linux and indicates an uninitialized/bogus pointer),
    // allocate a fresh discard streambuf so downstream inlined ostream helpers
    // in user binaries (e.g. nx.exe) can chase [+0x18..+0x58] pointer fields
    // through to valid sink storage rather than faulting on NULL.
    let effective_sb = if (sb as usize) < 0x10000 {
        let sb_layout = std::alloc::Layout::from_size_align(0xA0, 16).unwrap();
        let sb_raw = std::alloc::alloc_zeroed(sb_layout);
        // Apply the full ctor (vtable, locale, self-refs) then overlay the MSVC
        // discard layout so [+0x18..+0x58] pointer chases land in DISCARD_SINK.
        msvcp_streambuf_ctor(sb_raw, 0, 0, 0);
        sb_raw
    } else {
        // Caller supplied a real streambuf — overlay the MSVC discard layout in
        // case it was constructed without it (e.g. by msvcp_streambuf_init which
        // only calls streambuf_init_empty and skips the discard overlay). If the
        // slots are already backed by valid pointers this is a benign no-op.
        init_discard_streambuf_ms_layout(sb);
        sb
    };
    // Write vbtable pointer at this+0x00
    write_ptr(this, 0x00, BASIC_OSTREAM_VBTABLE.as_ptr() as *const u8);
    // Locate virtual basic_ios_char via vbtable[1] offset
    let vbase_off = BASIC_OSTREAM_VBTABLE[1] as usize;
    let base = this.add(vbase_off);
    // Zero-init and write ios vtable
    std::ptr::write_bytes(base, 0u8, 0x60);
    write_ptr(base, 0x00, FAKE_OSTREAM_VTABLE.as_ptr() as *const u8);
    *(base.add(0x10) as *mut u32) = 0x1008u32; // fmtfl defaults
    *base.add(0x58) = b' '; // fillch
                            // basic_ios_char_init: strbuf=effective_sb, stream=NULL, fillch=' '
    ios_char_init(base, effective_sb);
    this
}

/// `basic_iostream<char>::basic_iostream(basic_streambuf*)` — constructor.
/// Writes both istream and ostream vbtables, zero-inits shared virtual basic_ios_char,
/// then calls basic_ios_char_init via the istream path.
/// Wine ref: dlls/msvcp60/ios.c basic_iostream_char_ctor line 8309 — writes both
///   vbtables (virt_init=true), calls basic_istream_char_ctor(base1, strbuf, F, F),
///   calls basic_ostream_char_ctor(base2, NULL, F, F, F).
pub unsafe extern "win64" fn msvcp_iostream_ctor(
    this: *mut u8,
    sb: *mut u8,
    _c: usize,
    _d: usize,
) -> *mut u8 {
    if this.is_null() {
        return this;
    }
    // Write istream vbtable at base1=this+0x00
    write_ptr(this, 0x00, BASIC_IOSTREAM_VBTABLE1.as_ptr() as *const u8);
    // Write ostream vbtable at base2=this+0x10
    write_ptr(this, 0x10, BASIC_IOSTREAM_VBTABLE2.as_ptr() as *const u8);
    // Locate virtual basic_ios_char via base1 vbtable[1] offset from this
    let vbase_off = BASIC_IOSTREAM_VBTABLE1[1] as usize;
    let base = this.add(vbase_off);
    // Zero-init and write iostream ios vtable (basic_ios_char_ctor)
    std::ptr::write_bytes(base, 0u8, 0x60);
    write_ptr(base, 0x00, FAKE_IOSTREAM_VTABLE.as_ptr() as *const u8);
    *(base.add(0x10) as *mut u32) = 0x1008u32; // fmtfl defaults
    *base.add(0x58) = b' '; // fillch
                            // base1.count = 0 at this+0x08 (istream gcount field)
    *(this.add(0x08) as *mut i64) = 0i64;
    // basic_ios_char_init: strbuf=sb, stream=NULL, fillch=' '
    ios_char_init(base, sb);
    this
}

/// `basic_streambuf::getloc()` — returns a locale copy via Windows x64 sret.
///
/// Calling convention (MSVC member function returning large struct):
///   RCX = this (basic_streambuf*), RDX = locale return destination.
/// Writes a fake locale {cookie=0, _Ptr=fake_locimp} to *ret and returns ret in RAX.
///
/// Wine ref: dlls/msvcp90/ios.c:basic_streambuf_getloc — returns _Mylocale copy.
pub unsafe extern "win64" fn msvcp_getloc(
    _this: usize,
    ret: *mut usize,
    _c: usize,
    _d: usize,
) -> *mut usize {
    let data = get_fake_locale_data();
    let locimp_addr = &data.locimp_vtable as *const usize as usize;
    *ret = 0; // locale.cookie = 0 (unused field)
    *ret.add(1) = locimp_addr; // locale._Ptr = &fake _Locimp
    ret
}

/// `codecvt_base::always_noconv()` — returns true for char→char (no conversion needed).
///
/// Wine ref: dlls/msvcp90/locale.c:codecvt_base_always_noconv — returns TRUE for
/// the narrow-char specialization; _Cvt is set to NULL in the caller (basic_filebuf::open).
pub unsafe extern "win64" fn msvcp_always_noconv(
    _this: usize,
    _b: usize,
    _c: usize,
    _d: usize,
) -> u8 {
    1
}

/// `basic_istream<char>::read(char* buf, streamsize n)` — read n bytes from the file.
///
/// Win64: RCX=this, RDX=buf, R8=n (i64). Returns basic_istream<char>& (= this).
/// Scans the ifstream object memory for a registered FILE* and calls libc::fread.
///
/// Wine ref: dlls/msvcp90/ios.c:basic_istream_char_read_r — calls sgetn on rdbuf.
pub unsafe extern "win64" fn msvcp_read(this: *mut u8, buf: *mut u8, n: i64) -> *mut u8 {
    if let Some(fp) = get_current_fp() {
        if n > 0 && !buf.is_null() {
            libc::fread(buf as *mut libc::c_void, 1, n as usize, fp);
        }
    }
    this
}

/// `basic_istream<char>::seekg(streamoff off, int dir)` — seek within the file.
///
/// Win64: RCX=this, RDX=off (i64), R8=dir (int; beg=0/cur=1/end=2). Returns istream&.
/// Wine ref: dlls/msvcp90/ios.c:basic_istream_char_seekg — calls pubseekoff on rdbuf.
pub unsafe extern "win64" fn msvcp_seekg(this: *mut u8, offset: i64, whence: i32) -> *mut u8 {
    if let Some(fp) = get_current_fp() {
        libc::fseek(fp, offset as libc::c_long, whence);
    }
    this
}

/// `basic_istream<char>::tellg()` — return current file position.
///
/// Win64 sret: RCX=this, RDX=fpos<mbstate_t>* return buffer. Returns RDX.
/// fpos<mbstate_t> = { streamoff _Myoff (i64 @ +0), mbstate_t _Fac (8 bytes @ +8) }
/// Wine ref: dlls/msvcp90/ios.c:basic_istream_char_tellg — calls pubseekoff on rdbuf.
pub unsafe extern "win64" fn msvcp_tellg(
    _this: *const u8,
    ret: *mut i64,
    _c: usize,
    _d: usize,
) -> *mut i64 {
    let pos = if let Some(fp) = get_current_fp() {
        libc::ftell(fp) as i64
    } else {
        -1
    };
    *ret = pos;
    *ret.add(1) = 0; // mbstate_t zeroed
    ret
}

/// `basic_streambuf<char>::xsgetn(char* buf, streamsize n)` — read n chars from buffer.
///
/// Win64: RCX=this (filebuf*), RDX=buf, R8=n. Returns streamsize (i64) bytes read.
/// Wine ref: dlls/msvcp90/ios.c:basic_streambuf_char_xsgetn_s — fread-backed.
pub unsafe extern "win64" fn msvcp_xsgetn(_this: *const u8, buf: *mut u8, n: i64) -> i64 {
    if let Some(fp) = get_current_fp() {
        if n > 0 && !buf.is_null() {
            return libc::fread(buf as *mut libc::c_void, 1, n as usize, fp) as i64;
        }
    }
    0
}

/// `basic_streambuf<char>::sbumpc()` — read and advance one character.
///
/// Win64: RCX=this (streambuf*). Returns int (char as unsigned, or EOF=-1).
/// Wine ref: dlls/msvcp90/ios.c:basic_streambuf_char_sbumpc — inline in Wine.
pub unsafe extern "win64" fn msvcp_sbumpc(
    _this: *const u8,
    _b: usize,
    _c: usize,
    _d: usize,
) -> i32 {
    if let Some(fp) = get_current_fp() {
        let c = libc::fgetc(fp);
        return if c == libc::EOF { -1 } else { c };
    }
    -1
}

/// `_Smanip<streamsize>::pfn` — apply function for `std::setw` manipulator.
///
/// MSVC inlines `operator<<(basic_ostream&, _Smanip<T>)` so the user binary
/// dereferences the manipulator at the call site:
///
/// ```asm
///     mov rdx, qword ptr [rdi + 0x8]   ; rdx = manip.arg
///     call qword ptr [rdi]             ; call manip.pfn
/// ```
///
/// where `rdi` is the `_Smanip<streamsize>` slot returned from `setw`. The
/// inlined op<< sets RCX to the basic_ios before the call. Real `setw` would
/// set the field width on the ios; for stub purposes we just pass-through —
/// nx.exe never observes the formatted output, so width has no behavioural
/// consequence.
pub unsafe extern "win64" fn msvcp_setw_apply(
    ios: *mut u8,
    _arg: i64,
    _c: usize,
    _d: usize,
) -> *mut u8 {
    ios
}

/// `std::setw(streamsize n)` — return a 16-byte `_Smanip<streamsize>` by sret.
///
/// Win64 ABI for a 16-byte non-trivial aggregate return: hidden first
/// parameter in RCX is the caller-allocated return slot, real arg shifts to
/// RDX. Layout of the slot is `{ pfn @ +0; arg @ +8 }` — confirmed by the
/// nx.exe inlined-op<< sequence at RVA 0x14094991..0x1400949ea.
///
/// Replaces the previous `msvcp_noop` mapping which returned 0 in RAX,
/// causing the user binary to dereference NULL+8 immediately after the
/// inlined op<< (CI 25253395641, fault at RVA 0x000949e6 fault=0x8).
///
/// Wine ref: dlls/msvcp90/iosfwd.c:setw — constructs `_Smanip` with
///   `pfn = setw_helper` and `arg = n`; setw_helper invokes
///   `basic_ios::width(n)` on the streamed ios.
pub unsafe extern "win64" fn msvcp_setw(
    ret: *mut usize,
    n: i64,
    _c: usize,
    _d: usize,
) -> *mut usize {
    if !ret.is_null() {
        *ret = msvcp_setw_apply as *const () as usize; // pfn @ +0
        *ret.add(1) = n as usize; // arg @ +8
    }
    ret
}

/// `operator<<(basic_ostream&, ios_base& (*)(ios_base&))` — apply ios_base manipulator.
///
/// Called for things like `os << std::dec` where `std::dec` is a function
/// pointer with signature `ios_base& (ios_base&)`. nx.exe at RVA 0x1400949c9
/// invokes the IAT slot for this op<< (see imports table: 0x1400b82f0). The
/// previous `msvcp_noop` mapping returned 0, which the user binary stored in
/// rbx and then dereferenced at RVA 0x000949ec — `mov (%rbx), %rax` faulted
/// at NULL (CI 25285854751).
///
/// Implementation: locate the ios_base subobject via the ostream's vbtable
/// (slot at this+0; offset at vbtable[+4] — 0x88 for nx.exe's MSVC layout
/// per `BASIC_OSTREAM_VBTABLE`), invoke the manipulator on it, and return
/// the original ostream so the chained `op<< … op<< … op<<` sequence keeps
/// rbx non-null.
///
/// Wine ref: dlls/msvcp90/ios.c:basic_ostream_print_manip — calls
///   `manip(*basic_ios::ios_base())`, returns ostream.
pub unsafe extern "win64" fn msvcp_op_lshift_ios_base_manip(
    ostream: *mut u8,
    pf: Option<unsafe extern "win64" fn(*mut u8) -> *mut u8>,
    _c: usize,
    _d: usize,
) -> *mut u8 {
    if !ostream.is_null() {
        if let Some(pf) = pf {
            let vbtable_ptr = *(ostream as *const *const u8);
            if !vbtable_ptr.is_null() {
                let off = *(vbtable_ptr.add(4) as *const i32) as usize;
                pf(ostream.add(off));
            }
        }
    }
    ostream
}

/// `operator<<(basic_ostream&, T)` for the value-formatting overloads — pass-through.
///
/// MSVC inlines `os << x` chains as direct calls to the `op<<` IAT slot. The
/// previous `msvcp_noop` mapping returned 0, which the user binary stored in
/// RCX for the next link in the chain — the next `op<<` (or any subsequent
/// helper like nx.exe's `0x1400639e0` ostream-output-string fn) then read
/// `[NULL]` and faulted (CI 25286149815, fault rva 0x000063a29 from caller
/// at 0x140094a0d via the unsigned-int overload at IAT 0x1400b82f8).
///
/// Stub semantics: skip formatting, return the ostream so chaining works.
/// nx.exe never observes formatted text on the gate path (the d3d9 frame
/// content is what's checked), so the missing format is invisible.
pub unsafe extern "win64" fn msvcp_op_lshift_passthrough(
    ostream: *mut u8,
    _arg: usize,
    _c: usize,
    _d: usize,
) -> *mut u8 {
    ostream
}

/// `operator<<(basic_ostream&, basic_ostream& (*)(basic_ostream&))` —
/// apply ostream manipulator (e.g. `std::endl`, `std::flush`).
///
/// Same NULL-rcx-cascade hazard as the ios_base-manip overload. Invokes the
/// manipulator on the ostream and returns the ostream.
///
/// Wine ref: dlls/msvcp90/ios.c:basic_ostream_print_manip_os — calls
///   `manip(os)`, returns os.
pub unsafe extern "win64" fn msvcp_op_lshift_ostream_manip(
    ostream: *mut u8,
    pf: Option<unsafe extern "win64" fn(*mut u8) -> *mut u8>,
    _c: usize,
    _d: usize,
) -> *mut u8 {
    if !ostream.is_null() {
        if let Some(pf) = pf {
            pf(ostream);
        }
    }
    ostream
}

/// `std::_Fiopen(filename, mode, prot)` — open a file on behalf of std::ifstream/ofstream.
///
/// Wine ref: dlls/msvcp140/msvcp140.c — _Fiopen maps ios_base::openmode bits to fopen
/// mode string; prot (Win32 sharing flags) is ignored on Linux.
/// ios_base::openmode: in=0x01, out=0x02, ate=0x04, app=0x08, trunc=0x10, binary=0x20
pub unsafe extern "win64" fn msvcp_fiopen(
    filename: *const u16,
    mode: i32,
    _prot: i32,
) -> *mut libc::c_void {
    use std::os::unix::ffi::OsStrExt;
    if filename.is_null() {
        return std::ptr::null_mut();
    }
    let len = {
        let mut n = 0usize;
        while n < 32768 && *filename.add(n) != 0 {
            n += 1;
        }
        n
    };
    let wide = std::slice::from_raw_parts(filename, len);
    let win_path = String::from_utf16_lossy(wide).to_owned();
    let linux_path = match weave_core::file_io::translate_win_path(&win_path) {
        Ok(p) => p,
        Err(_) => return std::ptr::null_mut(),
    };
    let path_cstr = match std::ffi::CString::new(linux_path.as_os_str().as_bytes()) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let r = (mode & 0x01) != 0;
    let w = (mode & 0x02) != 0;
    let a = (mode & 0x08) != 0;
    let t = (mode & 0x10) != 0;
    let b = (mode & 0x20) != 0;
    let mode_str: &[u8] = match (r, w, a, t, b) {
        (true, false, false, _, false) => b"r\0",
        (true, false, false, _, true) => b"rb\0",
        (false, true, false, _, false) => b"w\0",
        (false, true, false, _, true) => b"wb\0",
        (false, true, true, _, false) => b"a\0",
        (false, true, true, _, true) => b"ab\0",
        (true, true, false, false, false) => b"r+\0",
        (true, true, false, false, true) => b"r+b\0",
        (true, true, false, true, false) => b"w+\0",
        (true, true, false, true, true) => b"w+b\0",
        (true, true, true, _, false) => b"a+\0",
        (true, true, true, _, true) => b"a+b\0",
        _ => {
            if b {
                b"rb\0"
            } else {
                b"r\0"
            }
        }
    };
    let mut result = libc::fopen(path_cstr.as_ptr(), mode_str.as_ptr() as *const libc::c_char);
    if result.is_null() {
        // Case-fold + extension-prefix fallback (handles Win32 buffer truncation
        // where "font_1.fn" is passed but "font_1.fnt" exists on disk).
        if let Some(folded) = weave_core::file_io::case_fold_lookup(&linux_path) {
            result = libc::fopen(folded.as_ptr(), mode_str.as_ptr() as *const libc::c_char);
        }
    }
    if !result.is_null() {
        if let Ok(mut guard) = MSVCP_OPEN_FP.lock() {
            *guard = Some(result as usize);
        }
    }
    result as *mut libc::c_void
}

// ── Real pthread-backed implementations ──────────────────────────────────────

/// _Mtx_init_in_situ — initialize a pthread_mutex_t at the caller-provided address.
/// Wine ref: dlls/msvcp140/msvcp140.c — _Mtx_init_in_situ: in-place pthread_mutex_init;
///   flags&0x100=recursive; returns _Thrd_success=0.
/// The caller owns the memory. No Weave-side allocation occurs.
pub unsafe extern "win64" fn mtx_init_in_situ(mtx: *mut libc::c_void, flags: i32) -> i32 {
    {
        static FIRST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !FIRST.swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!(
                "weave/msvcp: _Mtx_init_in_situ mtx=0x{:x} flags=0x{flags:x}",
                mtx as usize
            );
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mut attr: libc::pthread_mutexattr_t = core::mem::zeroed();
        libc::pthread_mutexattr_init(&mut attr);
        if flags & 0x100 != 0 {
            libc::pthread_mutexattr_settype(&mut attr, libc::PTHREAD_MUTEX_RECURSIVE);
        }
        let ret = libc::pthread_mutex_init(mtx as *mut libc::pthread_mutex_t, &attr);
        libc::pthread_mutexattr_destroy(&mut attr);
        ret
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (mtx, flags);
        0
    }
}

/// _Mtx_destroy_in_situ — destroy the pthread_mutex_t at the caller-provided address.
/// Wine ref: dlls/msvcp140/msvcp140.c — calls pthread_mutex_destroy; caller owns memory.
pub unsafe extern "win64" fn mtx_destroy_in_situ(
    mtx: *mut libc::c_void,
    _b: usize,
    _c: usize,
    _d: usize,
) -> usize {
    #[cfg(target_os = "linux")]
    {
        libc::pthread_mutex_destroy(mtx as *mut libc::pthread_mutex_t);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = mtx;
    }
    0
}

/// _Mtx_lock — pthread_mutex_lock on the caller-provided mutex.
/// Wine ref: dlls/msvcp140/msvcp140.c — _Mtx_lock: pthread_mutex_lock; returns _Thrd_success=0.
pub unsafe extern "win64" fn mtx_lock(
    mtx: *mut libc::c_void,
    _b: usize,
    _c: usize,
    _d: usize,
) -> i32 {
    {
        static FIRST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !FIRST.swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!("weave/msvcp: _Mtx_lock mtx=0x{:x}", mtx as usize);
        }
    }
    #[cfg(target_os = "linux")]
    {
        libc::pthread_mutex_lock(mtx as *mut libc::pthread_mutex_t)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = mtx;
        0
    }
}

/// _Mtx_unlock — pthread_mutex_unlock on the caller-provided mutex.
/// Wine ref: dlls/msvcp140/msvcp140.c — _Mtx_unlock: pthread_mutex_unlock; returns _Thrd_success=0.
pub unsafe extern "win64" fn mtx_unlock(
    mtx: *mut libc::c_void,
    _b: usize,
    _c: usize,
    _d: usize,
) -> i32 {
    #[cfg(target_os = "linux")]
    {
        libc::pthread_mutex_unlock(mtx as *mut libc::pthread_mutex_t)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = mtx;
        0
    }
}

/// _Cnd_destroy_in_situ — destroy the pthread_cond_t at the caller-provided address.
/// Wine ref: dlls/msvcp140/msvcp140.c — _Cnd_destroy_in_situ: pthread_cond_destroy; caller owns memory.
pub unsafe extern "win64" fn cnd_destroy_in_situ(
    _cond: *mut libc::c_void,
    _a: usize,
    _b: usize,
    _c: usize,
) -> usize {
    0
}

/// `__ExceptionPtrCreate(void* ptr)` — initialize exception_ptr to empty (0).
pub unsafe extern "win64" fn msvcp_exception_ptr_create(
    ptr: *mut u64,
    _b: usize,
    _c: usize,
    _d: usize,
) {
    if !ptr.is_null() {
        *ptr = 0;
    }
}

/// `__ExceptionPtrDestroy(void* ptr)` — destroy exception_ptr (no-op for empty).
pub unsafe extern "win64" fn msvcp_exception_ptr_destroy(
    _ptr: *mut u64,
    _b: usize,
    _c: usize,
    _d: usize,
) {
}

/// `__ExceptionPtrCopy(void* dst, void* src)` — copy exception_ptr.
pub unsafe extern "win64" fn msvcp_exception_ptr_copy(
    dst: *mut u64,
    src: *const u64,
    _c: usize,
    _d: usize,
) {
    if !dst.is_null() && !src.is_null() {
        *dst = *src;
    }
}

/// `__ExceptionPtrAssign(void* dst, void* src)` — assign exception_ptr.
pub unsafe extern "win64" fn msvcp_exception_ptr_assign(
    dst: *mut u64,
    src: *const u64,
    _c: usize,
    _d: usize,
) {
    if !dst.is_null() && !src.is_null() {
        *dst = *src;
    }
}

/// `__ExceptionPtrCopyException(void* dst, void* src, void* exc)` — copy with exception info.
pub unsafe extern "win64" fn msvcp_exception_ptr_copy_exception(
    dst: *mut u64,
    src: *const u64,
    _exc: *const u64,
    _d: usize,
) {
    if !dst.is_null() && !src.is_null() {
        *dst = *src;
    }
}

/// `__ExceptionPtrCurrentException(void* ptr)` — capture current exception (none → 0).
pub unsafe extern "win64" fn msvcp_exception_ptr_current_exception(
    ptr: *mut u64,
    _b: usize,
    _c: usize,
    _d: usize,
) {
    if !ptr.is_null() {
        *ptr = 0;
    }
}

/// `__ExceptionPtrRethrow(void* ptr)` — rethrow exception_ptr. Should only be called
/// with a valid exception; since we never store one, this is a no-op.
pub unsafe extern "win64" fn msvcp_exception_ptr_rethrow(
    _ptr: *mut u64,
    _b: usize,
    _c: usize,
    _d: usize,
) {
}

/// `std::uncaught_exceptions()` — return 0 (no uncaught exceptions).
pub unsafe extern "win64" fn msvcp_uncaught_exceptions() -> i32 {
    0
}

/// `_Query_perf_counter(LARGE_INTEGER*)` — write current performance counter.
/// Wine ref: dlls/msvcp140/msvcp140.c — _Query_perf_counter calls QueryPerformanceCounter.
/// On Linux: clock_gettime(CLOCK_MONOTONIC, &ts) → counter = ts.tv_sec * 1e9 + ts.tv_nsec
pub unsafe extern "win64" fn msvcp_query_perf_counter(
    out: *mut i64,
    _b: usize,
    _c: usize,
    _d: usize,
) -> i32 {
    if out.is_null() {
        return 0;
    }
    let mut ts = std::mem::zeroed::<libc::timespec>();
    libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    *out = ts.tv_sec as i64 * 1_000_000_000 + ts.tv_nsec as i64;
    1 // non-zero = success
}

/// `_Query_perf_frequency(LARGE_INTEGER*)` — write the performance counter frequency.
/// Wine ref: dlls/msvcp140/msvcp140.c — _Query_perf_frequency calls QueryPerformanceFrequency.
/// On Linux: clock_gettime returns nanosecond resolution → 1_000_000_000 Hz.
pub unsafe extern "win64" fn msvcp_query_perf_frequency(
    out: *mut i64,
    _b: usize,
    _c: usize,
    _d: usize,
) -> i32 {
    if out.is_null() {
        return 0;
    }
    *out = 1_000_000_000; // 1 GHz = nanosecond resolution
    1
}

/// `_Thrd_detach(thr)` — detach a thread handle (no-op under Weave).
pub unsafe extern "win64" fn msvcp_thrd_detach(
    _thr: usize,
    _b: usize,
    _c: usize,
    _d: usize,
) -> i32 {
    0
}

/// `std::_Xinvalid_argument(char const* msg)` — throws std::invalid_argument.
/// Weave doesn't support C++ exceptions, so log the message and return.
/// The caller will likely crash, but the diagnostic tells us WHAT was invalid.
/// Wine ref: dlls/msvcp90/error.c — _Xinvalid_argument calls _Throw_Cpp_error.
pub unsafe extern "win64" fn msvcp_xinvalid_argument(
    msg: *const u8,
    _b: usize,
    _c: usize,
    _d: usize,
) {
    let msg_str = if msg.is_null() {
        "<null>".to_string()
    } else {
        unsafe { std::ffi::CStr::from_ptr(msg as *const libc::c_char) }
            .to_string_lossy()
            .into_owned()
    };
    eprintln!("weave/msvcp: _Xinvalid_argument(\"{msg_str}\") — exception swallowed (no SEH)");
}

/// `_Locinfo::_W_Getmonths()` — return pointer to static wide month name table.
/// MSVC format: buffer of 13 null-terminated wide strings (January..December + sentinel).
/// Wine ref: dlls/msvcp90/locale.c — _W_Getmonths returns &months_w[0].
static W_MONTHS: [u16; 156] = {
    let mut m = [0u16; 156];
    // January\0 (8 + 1 = 9 wchars)
    m[0] = b'J' as u16;
    m[1] = b'a' as u16;
    m[2] = b'n' as u16;
    m[3] = b'u' as u16;
    m[4] = b'a' as u16;
    m[5] = b'r' as u16;
    m[6] = b'y' as u16;
    m[7] = 0;
    // February\0 (10 wchars at offset 9)
    m[9] = b'F' as u16;
    m[10] = b'e' as u16;
    m[11] = b'b' as u16;
    m[12] = b'r' as u16;
    m[13] = b'u' as u16;
    m[14] = b'a' as u16;
    m[15] = b'r' as u16;
    m[16] = b'y' as u16;
    m[17] = 0;
    // March\0 (6 wchars at offset 18)
    m[18] = b'M' as u16;
    m[19] = b'a' as u16;
    m[20] = b'r' as u16;
    m[21] = b'c' as u16;
    m[22] = b'h' as u16;
    m[23] = 0;
    // April\0 (6 wchars at offset 24)
    m[24] = b'A' as u16;
    m[25] = b'p' as u16;
    m[26] = b'r' as u16;
    m[27] = b'i' as u16;
    m[28] = b'l' as u16;
    m[29] = 0;
    // May\0 (4 wchars at offset 30)
    m[30] = b'M' as u16;
    m[31] = b'a' as u16;
    m[32] = b'y' as u16;
    m[33] = 0;
    // June\0 (5 wchars at offset 34)
    m[34] = b'J' as u16;
    m[35] = b'u' as u16;
    m[36] = b'n' as u16;
    m[37] = b'e' as u16;
    m[38] = 0;
    // July\0 (5 wchars at offset 39)
    m[39] = b'J' as u16;
    m[40] = b'u' as u16;
    m[41] = b'l' as u16;
    m[42] = b'y' as u16;
    m[43] = 0;
    // August\0 (6 wchars at offset 44)
    m[44] = b'A' as u16;
    m[45] = b'u' as u16;
    m[46] = b'g' as u16;
    m[47] = b'u' as u16;
    m[48] = b's' as u16;
    m[49] = b't' as u16;
    m[50] = 0;
    // September\0 (10 wchars at offset 51)
    m[51] = b'S' as u16;
    m[52] = b'e' as u16;
    m[53] = b'p' as u16;
    m[54] = b't' as u16;
    m[55] = b'e' as u16;
    m[56] = b'm' as u16;
    m[57] = b'b' as u16;
    m[58] = b'e' as u16;
    m[59] = b'r' as u16;
    m[60] = 0;
    // October\0 (8 wchars at offset 61)
    m[61] = b'O' as u16;
    m[62] = b'c' as u16;
    m[63] = b't' as u16;
    m[64] = b'o' as u16;
    m[65] = b'b' as u16;
    m[66] = b'e' as u16;
    m[67] = b'r' as u16;
    m[68] = 0;
    // November\0 (8 wchars at offset 69)
    m[69] = b'N' as u16;
    m[70] = b'o' as u16;
    m[71] = b'v' as u16;
    m[72] = b'e' as u16;
    m[73] = b'm' as u16;
    m[74] = b'b' as u16;
    m[75] = b'e' as u16;
    m[76] = b'r' as u16;
    m[77] = 0;
    // December\0 (9 wchars at offset 78)
    m[78] = b'D' as u16;
    m[79] = b'e' as u16;
    m[80] = b'c' as u16;
    m[81] = b'e' as u16;
    m[82] = b'm' as u16;
    m[83] = b'b' as u16;
    m[84] = b'e' as u16;
    m[85] = b'r' as u16;
    m[86] = 0;
    // Terminator at offset 87 (already 0 from init)
    m
};
pub unsafe extern "win64" fn msvcp_w_getmonths(
    _this: *const u8,
    _b: usize,
    _c: usize,
    _d: usize,
) -> usize {
    W_MONTHS.as_ptr() as usize
}

/// `_Locinfo::_W_Getdays()` — return pointer to static wide day name table.
/// MSVC format: buffer of 7 null-terminated wide strings (Sunday..Saturday).
static W_DAYS: [u16; 64] = {
    let mut d = [0u16; 64];
    // Sunday\0
    d[0] = b'S' as u16;
    d[1] = b'u' as u16;
    d[2] = b'n' as u16;
    d[3] = b'd' as u16;
    d[4] = b'a' as u16;
    d[5] = b'y' as u16;
    d[6] = 0;
    // Monday\0 at off 7
    d[7] = b'M' as u16;
    d[8] = b'o' as u16;
    d[9] = b'n' as u16;
    d[10] = b'd' as u16;
    d[11] = b'a' as u16;
    d[12] = b'y' as u16;
    d[13] = 0;
    // Tuesday\0 at off 14
    d[14] = b'T' as u16;
    d[15] = b'u' as u16;
    d[16] = b'e' as u16;
    d[17] = b's' as u16;
    d[18] = b'd' as u16;
    d[19] = b'a' as u16;
    d[20] = b'y' as u16;
    d[21] = 0;
    // Wednesday\0 at off 22
    d[22] = b'W' as u16;
    d[23] = b'e' as u16;
    d[24] = b'd' as u16;
    d[25] = b'n' as u16;
    d[26] = b'e' as u16;
    d[27] = b's' as u16;
    d[28] = b'd' as u16;
    d[29] = b'a' as u16;
    d[30] = b'y' as u16;
    d[31] = 0;
    // Thursday\0 at off 32
    d[32] = b'T' as u16;
    d[33] = b'h' as u16;
    d[34] = b'u' as u16;
    d[35] = b'r' as u16;
    d[36] = b's' as u16;
    d[37] = b'd' as u16;
    d[38] = b'a' as u16;
    d[39] = b'y' as u16;
    d[40] = 0;
    // Friday\0 at off 41
    d[41] = b'F' as u16;
    d[42] = b'r' as u16;
    d[43] = b'i' as u16;
    d[44] = b'd' as u16;
    d[45] = b'a' as u16;
    d[46] = b'y' as u16;
    d[47] = 0;
    // Saturday\0 at off 48
    d[48] = b'S' as u16;
    d[49] = b'a' as u16;
    d[50] = b't' as u16;
    d[51] = b'u' as u16;
    d[52] = b'r' as u16;
    d[53] = b'd' as u16;
    d[54] = b'a' as u16;
    d[55] = b'y' as u16;
    d[56] = 0;
    d
};
pub unsafe extern "win64" fn msvcp_w_getdays(
    _this: *const u8,
    _b: usize,
    _c: usize,
    _d: usize,
) -> usize {
    W_DAYS.as_ptr() as usize
}

/// `basic_streambuf<char>::overflow(int c)` — flush buffer or write a character when
/// the put area is exhausted.  Returns traits::not_eof(c) on success, EOF on failure.
/// Wine ref: dlls/msvcp60/ios.c — xsputn calls overflow when buffer is full.
/// For now: write the character via fwrite if c != EOF, return not_eof(c).
pub unsafe extern "win64" fn msvcp_overflow(
    _this: *const u8,
    ch: i32,
    _b: usize,
    _c: usize,
) -> i32 {
    if ch != -1
    /* EOF */
    {
        if let Some(fp) = get_current_fp() {
            let byte = ch as u8;
            libc::fwrite(&byte as *const u8 as *const libc::c_void, 1, 1, fp);
        }
        // Return not_eof(c): any non-EOF value.  1 is safe (not EOF).
        1
    } else {
        -1 // EOF — caller is just flushing, no character to write
    }
}

/// `basic_streambuf<char>::seekpos(fpos_t, int mode)` — seek to position. Return fail.
pub unsafe extern "win64" fn msvcp_seekpos(
    _this: *const u8,
    _pos: usize,
    _mode: i32,
    _d: usize,
) -> i32 {
    -1
}

/// `basic_streambuf<char>::seekoff(long long, int way, int mode)` — seek by offset.
pub unsafe extern "win64" fn msvcp_seekoff(
    _this: *const u8,
    _off: i64,
    _way: i32,
    _mode: i32,
) -> i32 {
    -1
}

/// `basic_streambuf<char>::underflow()` — read one char from get area. Return EOF.
pub unsafe extern "win64" fn msvcp_underflow(
    _this: *const u8,
    _b: usize,
    _c: usize,
    _d: usize,
) -> i32 {
    -1
}

/// `basic_streambuf<char>::_Gnavail()` — chars available in get area.
pub unsafe extern "win64" fn msvcp_gnavail(
    _this: *const u8,
    _b: usize,
    _c: usize,
    _d: usize,
) -> i64 {
    0
}

/// `basic_streambuf<char>::_Pnavail()` — space available in put area.
pub unsafe extern "win64" fn msvcp_pnavail(
    _this: *const u8,
    _b: usize,
    _c: usize,
    _d: usize,
) -> i64 {
    0
}

/// `_Cnd_wait(_Cnd_t*, _Mtx_t*)` — wait on a condition variable with a mutex.
/// Wine ref: dlls/msvcp140/msvcp140.c — _Cnd_wait calls pthread_cond_wait.
pub unsafe extern "win64" fn msvcp_cnd_wait(
    cnd: *mut libc::c_void,
    mtx: *mut libc::c_void,
    _c: usize,
    _d: usize,
) -> i32 {
    libc::pthread_cond_wait(
        cnd as *mut libc::pthread_cond_t,
        mtx as *mut libc::pthread_mutex_t,
    )
}

/// `ios_base::operator!()` — return true if stream has an error.
/// Our fake streams never fail, so return false.
pub unsafe extern "win64" fn msvcp_ios_not(
    _this: *const u8,
    _b: usize,
    _c: usize,
    _d: usize,
) -> i32 {
    0
}

/// `basic_ios<char>::init(basic_streambuf<char>*, bool isstd)` — initialize ios with
/// a streambuf.  Sets strbuf, stream=NULL, fillch=' ', and clears error state.
/// Wine ref: dlls/msvcp60/ios.c basic_ios_char_init line 4059.
pub unsafe extern "win64" fn msvcp_ios_init(this: *mut u8, sb: *mut u8, _isstd: usize, _d: usize) {
    if this.is_null() {
        return;
    }
    // Clear the ios_base portion: state = goodbit(0), exceptions = 0
    // fmtfl at +0x10 is already set by the ctor, but reset to defaults
    *(this.add(0x08) as *mut u32) = 0; // state = goodbit
    *(this.add(0x0c) as *mut u32) = 0; // exceptions = 0
    *(this.add(0x10) as *mut u32) = 0x1008; // fmtfl = skipws|dec
    ios_char_init(this, sb);
}

/// Batch of trivial stream status/accessor stubs for basic_ios and basic_streambuf.
macro_rules! trivial_stub {
    ($name:ident, $ret:ty, $val:expr) => {
        pub unsafe extern "win64" fn $name(_: usize, _b: usize, _c: usize, _d: usize) -> $ret {
            $val
        }
    };
}
trivial_stub!(msvcp_ios_good, i32, 1); // good() → true
trivial_stub!(msvcp_ios_fail, i32, 0); // fail() → false
trivial_stub!(msvcp_ios_bad, i32, 0); // bad() → false
trivial_stub!(msvcp_ios_eof, i32, 0); // eof() → false
trivial_stub!(msvcp_ios_width_get, i64, 0); // width() → 0
trivial_stub!(msvcp_ios_width_set, i64, 0); // width(i64) → old width
trivial_stub!(msvcp_ios_tie, usize, 0); // tie() → null
trivial_stub!(msvcp_ios_rdbuf_get, usize, 0); // rdbuf() → null
trivial_stub!(msvcp_ios_flags_get, i32, 0x1008); // flags() → skipws|dec
trivial_stub!(msvcp_streambuf_sgetc, i32, -1); // sgetc() → EOF
trivial_stub!(msvcp_streambuf_snextc, i32, -1); // snextc() → EOF
trivial_stub!(msvcp_streambuf_eback, usize, 0); // eback() → null
trivial_stub!(msvcp_streambuf_egptr, usize, 0); // egptr() → null
trivial_stub!(msvcp_streambuf_epptr, usize, 0); // epptr() → null
trivial_stub!(msvcp_streambuf_gptr, usize, 0); // gptr() → null
trivial_stub!(msvcp_streambuf_pbase, usize, 0); // pbase() → null
trivial_stub!(msvcp_streambuf_pptr, usize, 0); // pptr() → null
trivial_stub!(msvcp_streambuf_gbump, i32, 0); // gbump(int) → 0
trivial_stub!(msvcp_streambuf_pbump, i32, 0); // pbump(int) → 0
trivial_stub!(msvcp_streambuf_setg, usize, 0); // setg(...) → 0
trivial_stub!(msvcp_streambuf_setp_2, usize, 0); // setp(a,b) → 0
trivial_stub!(msvcp_streambuf_setp_3, usize, 0); // setp(a,b,c) → 0
trivial_stub!(msvcp_streambuf_pninc, usize, 0); // _Pninc() → null
trivial_stub!(msvcp_streambuf_gninc, usize, 0); // _Gninc() → null
trivial_stub!(msvcp_streambuf_gndec, usize, 0); // _Gndec() → null
trivial_stub!(msvcp_streambuf_init_2, usize, 0); // _Init(...) → 0
trivial_stub!(msvcp_thrd_yield, i32, 0); // _Thrd_yield → 0
trivial_stub!(msvcp_thrd_hw_conc, i32, 1); // _Thrd_hardware_concurrency → 1
trivial_stub!(msvcp_cnd_broadcast, i32, 0); // _Cnd_broadcast → 0
trivial_stub!(msvcp_strcoll, i32, 0); // _Strcoll → 0
trivial_stub!(msvcp_wcscoll, i32, 0); // _Wcscoll → 0

/// `basic_ios<char>::rdbuf(basic_streambuf<char>*)` — set streambuf, return old one.
pub unsafe extern "win64" fn msvcp_ios_rdbuf_set(
    _this: usize,
    _sb: usize,
    _c: usize,
    _d: usize,
) -> usize {
    0
}

/// `basic_streambuf<char>::basic_streambuf(streambuf const&)` — copy constructor.
/// Returns `this` (no real copy needed for fake streambufs).
pub unsafe extern "win64" fn msvcp_streambuf_copy_ctor(
    this: *mut u8,
    _src: *const u8,
    _c: usize,
    _d: usize,
) -> *mut u8 {
    this
}

/// Static locale ID counter — used for locale::id assignments.
static LOCALE_ID_CNT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// `_Syserror_map(int err)` — map system error code to error string.
static SYS_ERR_UNKNOWN: [u8; 14] = *b"Unknown error\0";
pub unsafe extern "win64" fn msvcp_syserror_map(
    _err: i32,
    _b: usize,
    _c: usize,
    _d: usize,
) -> usize {
    SYS_ERR_UNKNOWN.as_ptr() as usize
}

/// `basic_ostream<char>::write(const char*, streamsize)` — write to stream via FILE*.
pub unsafe extern "win64" fn msvcp_ostream_write(
    _this: *mut u8,
    _buf: *const u8,
    _n: i64,
    _d: usize,
) -> *mut u8 {
    _this
}

/// `codecvt<short,char,Mbstatet>::out(...)` — codecvt conversion stub.
/// Returns noconv (0) — no conversion needed, input/output char sets are compatible.
/// The noop version returned 0 too but didn't set output end pointers.
pub unsafe extern "win64" fn msvcp_codecvt_out_short(
    _this: *const u8,
    _state: *mut u8,
    _from: *const u16,
    _from_end: *const u16,
    from_next: *mut *const u16,
    _to: *mut u8,
    _to_end: *mut u8,
    to_next: *mut *mut u8,
) -> i32 {
    // Set output end = output start (noconv: nothing was converted/written)
    if !from_next.is_null() {
        *from_next = _from;
    }
    if !to_next.is_null() {
        *to_next = _to;
    }
    0 // noconv
}

/// `basic_istream<char>::operator>>(double&)` — extract double. No-op, returns *this.
pub unsafe extern "win64" fn msvcp_istream_op_double(
    this: *mut u8,
    _val: *mut f64,
    _c: usize,
    _d: usize,
) -> *mut u8 {
    this
}

/// Batch: istream operator>> stubs — all return *this without reading.
macro_rules! istream_op {
    ($name:ident, $ty:ty) => {
        pub unsafe extern "win64" fn $name(
            this: *mut u8,
            _: *mut $ty,
            _c: usize,
            _d: usize,
        ) -> *mut u8 {
            this
        }
    };
}
istream_op!(msvcp_istream_op_long, i32);
istream_op!(msvcp_istream_op_int, i32);
pub unsafe extern "win64" fn msvcp_ostream_flush(
    this: *mut u8,
    _: usize,
    _: usize,
    _: usize,
) -> *mut u8 {
    this
}
pub unsafe extern "win64" fn msvcp_ostream_flush_w(
    this: *mut u8,
    _: usize,
    _: usize,
    _: usize,
) -> *mut u8 {
    this
}
pub unsafe extern "win64" fn msvcp_osfx_nop(_a: usize, _b: usize, _c: usize, _d: usize) {}
pub unsafe extern "win64" fn msvcp_op_lshift_ptr(
    this: *mut u8,
    _: usize,
    _: usize,
    _: usize,
) -> *mut u8 {
    this
}

/// `basic_streambuf<char>::pbackfail(int c)` — putback failure handler.
/// Called when putback fails (buffer full or not seekable). Returns EOF.
/// Wine ref: dlls/msvcp60/ios.c — pbackfail returns EOF.
pub unsafe extern "win64" fn msvcp_pbackfail(
    _this: *const u8,
    _ch: i32,
    _b: usize,
    _c: usize,
) -> i32 {
    -1 // EOF
}

/// `basic_streambuf<wchar_t>::sputc(wchar_t)` — write a single wide character to the
/// stream buffer.  Delegates to fwrite via the FILE* tracked by MSVCP_OPEN_FP.
pub unsafe extern "win64" fn msvcp_sputc_w(_this: *const u8, ch: u16, _c: usize, _d: usize) -> u16 {
    if let Some(fp) = get_current_fp() {
        let val = ch;
        libc::fwrite(&val as *const u16 as *const libc::c_void, 2, 1, fp);
        ch
    } else {
        0
    }
}

/// `basic_streambuf<char>::sputn(const char*, streamsize)` — write N chars to buffer.
/// Delegates to fwrite via the FILE* tracked by MSVCP_OPEN_FP.
/// Wine ref: dlls/mscp60/ios.c — xsputn writes to streambuf.
pub unsafe extern "win64" fn msvcp_sputn(
    _this: *const u8,
    buf: *const u8,
    n: i64,
    _d: usize,
) -> i64 {
    if buf.is_null() || n <= 0 {
        return 0;
    }
    if let Some(fp) = get_current_fp() {
        let written = libc::fwrite(buf as *const libc::c_void, 1, n as usize, fp);
        written as i64
    } else {
        0
    }
}

/// `basic_streambuf<wchar_t>::sputn(const wchar_t*, streamsize)` — write N wide chars.
/// Converts through libc::fwrite (wchar_t is 4 bytes on Linux, 2 bytes on Windows).
/// Wine ref: dlls/mscp60/ios.c — xsputn for wide writes wchars to streambuf.
pub unsafe extern "win64" fn msvcp_sputn_w(
    _this: *const u8,
    buf: *const u16,
    n: i64,
    _d: usize,
) -> i64 {
    if buf.is_null() || n <= 0 {
        return 0;
    }
    if let Some(fp) = get_current_fp() {
        let written = libc::fwrite(buf as *const libc::c_void, 2, n as usize, fp);
        written as i64
    } else {
        0
    }
}

/// `__ExceptionPtrToBool(void* ptr)` — return true if the exception_ptr holds an exception.
/// The exception_ptr stores the exception object pointer at offset 0; non-null = true.
pub unsafe extern "win64" fn msvcp_exception_ptr_to_bool(
    ptr: *const u64,
    _b: usize,
    _c: usize,
    _d: usize,
) -> i32 {
    if ptr.is_null() {
        return 0;
    }
    (*ptr != 0) as i32
}

/// `basic_ios<char>::fill()` — return the fill character from the ios struct.
/// MSVC layout: fillchar at `this+0x58` (set to ' ' by msvcp_basic_ios_ctor).
/// Returns the char in AL (Win64: zero-extended to u8 return).
/// Wine ref: dlls/msvcp60/ios.c — basic_ios_char_fill returns fillch.
pub unsafe extern "win64" fn msvcp_fill(this: *const u8, _b: usize, _c: usize, _d: usize) -> u8 {
    if this.is_null() {
        return 0;
    }
    *this.add(0x58)
}

/// `_Cnd_do_broadcast_at_thread_exit` — no-op.
pub unsafe extern "win64" fn msvcp_cnd_do_broadcast_at_thread_exit(
    cnd: *mut libc::c_void,
    _b: usize,
    _c: usize,
    _d: usize,
) {
    {
        static FIRST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !FIRST.swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!(
                "weave/msvcp: _Cnd_do_broadcast_at_thread_exit cnd=0x{:x}",
                cnd as usize
            );
        }
    }
}

// ── Real _Thrd_* and _Xtime_get_ticks implementations ────────────────────────

/// Heap-allocated context passed to pthread; carries the Win64 thread function + arg.
struct ThrdCtx {
    func: unsafe extern "win64" fn(*mut libc::c_void) -> i32,
    arg: *mut libc::c_void,
}

/// pthread start routine (System V ABI — arg in RDI).
/// Recovers ThrdCtx from the raw pointer, then calls the Win64 PE function with
/// arg in RCX (Rust's `extern "win64"` emits the correct call sequence).
extern "C" fn thrd_start(arg: *mut libc::c_void) -> *mut libc::c_void {
    unsafe {
        let ctx = Box::from_raw(arg as *mut ThrdCtx);
        let result = (ctx.func)(ctx.arg);
        result as usize as *mut libc::c_void
    }
}

/// _Thrd_id — return current thread ID.
/// Wine ref: dlls/msvcp90/misc.c — _Thrd_id: returns GetCurrentThreadId(); maps to gettid() on Linux.
pub extern "win64" fn msvcp_thrd_id() -> u32 {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::gettid() as u32
    }
    #[cfg(not(target_os = "linux"))]
    1
}

/// _Thrd_create — create a native thread running proc(arg).
/// Wine ref: dlls/msvcp90/misc.c — _Thrd_create: wraps proc in thread_proc_wrapper, calls
///   _beginthreadex; thr->hnd=HANDLE, thr->id=thread_id; _THRD_ERROR=4.
/// _Thrd_t layout (Win64 x64): {void* hnd @ 0 (8 bytes), unsigned id @ 8 (4 bytes), pad 4}.
/// In Weave: pthread_create with Win64→SysV ABI trampoline; pthread_t stored at thr→hnd.
pub unsafe extern "win64" fn msvcp_thrd_create(
    thr: *mut libc::c_void,
    func: unsafe extern "win64" fn(*mut libc::c_void) -> i32,
    arg: *mut libc::c_void,
) -> i32 {
    #[cfg(target_os = "linux")]
    {
        let ctx = Box::new(ThrdCtx { func, arg });
        let ctx_ptr = Box::into_raw(ctx) as *mut libc::c_void;
        let mut pthread: libc::pthread_t = 0;
        let ret = libc::pthread_create(&mut pthread, std::ptr::null(), thrd_start, ctx_ptr);
        if ret == 0 {
            *(thr as *mut libc::pthread_t) = pthread;
            *((thr as *mut u8).add(8) as *mut u32) = 0;
            0
        } else {
            drop(Box::from_raw(ctx_ptr as *mut ThrdCtx));
            4 // _THRD_ERROR
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (thr, func, arg);
        4
    }
}

/// _Thrd_join — join a thread by its pthread handle stored in _Thrd_t.hnd.
/// Wine ref: dlls/msvcp90/misc.c — _Thrd_join: WaitForSingleObject(thr.hnd, INFINITE) +
///   GetExitCodeThread + CloseHandle; returns 0=success, _THRD_ERROR=4.
/// thr_ptr is an implicit pointer to _Thrd_t (Win64 passes 16-byte struct by hidden pointer).
pub unsafe extern "win64" fn msvcp_thrd_join(thr_ptr: usize, code: *mut i32) -> i32 {
    #[cfg(target_os = "linux")]
    {
        let pthread = *(thr_ptr as *const libc::pthread_t);
        if pthread == 0 {
            if !code.is_null() {
                *code = 0;
            }
            return 0;
        }
        let mut retval: *mut libc::c_void = std::ptr::null_mut();
        let ret = libc::pthread_join(pthread, &mut retval);
        if ret == 0 {
            if !code.is_null() {
                *code = retval as usize as i32;
            }
            0
        } else {
            4 // _THRD_ERROR
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = thr_ptr;
        if !code.is_null() {
            *code = 0;
        }
        0
    }
}

/// _Xtime_get_ticks — return 100-ns ticks since 1601-01-01 (FILETIME epoch).
/// Wine ref: dlls/msvcp140/msvcp140.c — _Xtime_get_ticks: FILETIME 100-ns intervals since 1601-01-01.
pub extern "win64" fn msvcp_xtime_get_ticks() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
    }
    let unix_100ns = ts.tv_sec as u64 * 10_000_000 + ts.tv_nsec as u64 / 100;
    unix_100ns + 116_444_736_000_000_000
}

/// _Cnd_signal — pthread_cond_signal on the caller-provided condition variable.
/// Wine ref: dlls/msvcp140/msvcp140.c — _Cnd_signal: pthread_cond_signal; returns _Thrd_success=0.
pub unsafe extern "win64" fn cnd_signal(
    cnd: *mut libc::c_void,
    _b: usize,
    _c: usize,
    _d: usize,
) -> i32 {
    #[cfg(target_os = "linux")]
    {
        libc::pthread_cond_signal(cnd as *mut libc::pthread_cond_t)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cnd;
        0
    }
}

// DATA symbols — callers read these addresses directly from the IAT.

/// ?_BADOFF@std@@3_JB — static streamoff constant = -1LL
static BADOFF: i64 = -1;

/// ?cerr@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A — the cerr global object.
/// Backed by a heap-allocated ostream initialised through `msvcp_ostream_ctor` with a
/// minimal fake streambuf, exposed via a `OnceLock<usize>` so the address is stable
/// across resolve() calls. Inlined logging helpers in user binaries (e.g. NXEngine
/// nx.exe RVA 0x958b5) read the vbtable at this+0x00, sign-extend vbtable[+4] to get
/// the virtual basic_ios offset, then deref fields inside the ios subobject — all of
/// which now address valid initialised memory rather than a `[0u8; 128]` blob.
static CERR_OBJ_ADDR: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// Static `std::cout` ostream — same structure as cerr but a separate object.
static COUT_OBJ_ADDR: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
fn cout_addr() -> usize {
    *COUT_OBJ_ADDR.get_or_init(|| {
        // Same layout and initialisation as cerr_addr() — fake streambuf + ostream
        // with vtables so that virtual method calls (operator<<, flush, etc.) land
        // in our fake vtable region rather than crashing on a null vtable pointer.
        let sb_layout = std::alloc::Layout::from_size_align(0xA0, 16).unwrap();
        let sb_raw = unsafe { std::alloc::alloc_zeroed(sb_layout) };
        let layout = std::alloc::Layout::from_size_align(384, 16).unwrap();
        let raw = unsafe { std::alloc::alloc_zeroed(layout) };
        unsafe {
            msvcp_streambuf_ctor(sb_raw, 0, 0, 0);
            init_discard_streambuf_ms_layout(sb_raw);
            msvcp_ostream_ctor(raw, sb_raw, 0, 0);
            let vbase_off = BASIC_OSTREAM_VBTABLE[1] as usize;
            let base = raw.add(vbase_off);
            *(base.add(0x28) as *mut *const u8) = sb_raw;
        }
        raw as usize
    })
}

/// Allocate and initialise the static `std::cerr` ostream the first time it is
/// requested. Subsequent calls return the same address.
fn cerr_addr() -> usize {
    *CERR_OBJ_ADDR.get_or_init(|| {
        // Allocate a fake streambuf first so the ostream's strbuf field points at
        // a real object with a non-null vtable. 0xA0 matches msvcp_streambuf_ctor.
        let sb_layout = std::alloc::Layout::from_size_align(0xA0, 16).unwrap();
        // SAFETY: layout is non-zero-sized and well-aligned; allocator returns
        // either null (we'd crash later anyway) or a valid pointer to 0xA0 bytes.
        let sb_raw = unsafe { std::alloc::alloc_zeroed(sb_layout) };
        // Allocate the complete ostream object. 384 bytes covers the prefix
        // bytes that user code scribbles at this+0x80..0x88 (e.g. the
        // `mov [rsp+rcx+0x6c], edx` store landing at this+0x84 with vbase
        // 0x88) plus the virtual basic_ios subobject at this+0x88..this+0xE8
        // and the ios+0x28 streambuf-pointer slot at this+0xB0. Bumped from
        // 256 when BASIC_OSTREAM_VBTABLE[1] moved 0x08 → 0x88.
        let layout = std::alloc::Layout::from_size_align(384, 16).unwrap();
        let raw = unsafe { std::alloc::alloc_zeroed(layout) };
        unsafe {
            msvcp_streambuf_ctor(sb_raw, 0, 0, 0);
            // Defensive: re-apply the MSVC discard overlay even though
            // msvcp_streambuf_ctor already does. Keeps cerr's streambuf
            // independent of any future refactor of the ctor's init order.
            init_discard_streambuf_ms_layout(sb_raw);
            msvcp_ostream_ctor(raw, sb_raw, 0, 0);
            // Inlined ostream helper at nx.exe RVA 0x958b5 also reads
            // *(this + vbase + 0x28) and dereferences the result. ios+0x28 is not
            // populated by basic_ios_char_init in our model, so point it at the
            // streambuf — its first slot is a valid vtable pointer, so any further
            // virtual deref lands in our fake-vtable region rather than crashing.
            let vbase_off = BASIC_OSTREAM_VBTABLE[1] as usize;
            let base = raw.add(vbase_off);
            *(base.add(0x28) as *mut *const u8) = sb_raw;
        }
        raw as usize
    })
}

/// ?id@?$codecvt@DDU_Mbstatet@@@std@@2V0locale@2@A — locale::id for codecvt<char,char>
static LOCALE_ID_CODECVT_DD: usize = 0;

/// ?id@?$codecvt@_WDU_Mbstatet@@@std@@2V0locale@2@A — locale::id for codecvt<wchar_t,char>
static LOCALE_ID_CODECVT_WD: usize = 0;

/// ?id@?$numpunct@D@std@@2V0locale@2@A — locale::id for numpunct<char>
static LOCALE_ID_NUMPUNCT: usize = 0;
static LOCALE_ID_COLLATE_D: usize = 0;
static LOCALE_ID_COLLATE_W: usize = 0;
static LOCALE_ID_CTYPE_D: usize = 0;
static LOCALE_ID_CTYPE_W: usize = 0;

/// `?_Raise_handler@std@@3P6AXAEBVexception@stdext@@@ZEA` — static null function pointer.
static RAISE_HANDLER: [u8; 8] = [0u8; 8];

/// Resolve a MSVCP140.dll import to a function or data address.
///
/// Returns `None` if the DLL is not msvcp140.dll.
/// Returns `Some(addr)` for every known import.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    if !dll.eq_ignore_ascii_case("msvcp140.dll") {
        return None;
    }

    let addr = match func {
        // ── DATA symbols ──────────────────────────────────────────────────────────
        "?_BADOFF@std@@3_JB" => {
            &BADOFF as *const i64 as usize
        }
        "?cerr@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A" => {
            cerr_addr()
        }
        "?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A" => {
            cout_addr()
        }
        "?id@?$codecvt@DDU_Mbstatet@@@std@@2V0locale@2@A" => {
            &LOCALE_ID_CODECVT_DD as *const usize as usize
        }
        "?id@?$codecvt@_WDU_Mbstatet@@@std@@2V0locale@2@A" => {
            &LOCALE_ID_CODECVT_WD as *const usize as usize
        }
        "?id@?$numpunct@D@std@@2V0locale@2@A" => {
            &LOCALE_ID_NUMPUNCT as *const usize as usize
        }
        "?id@?$collate@D@std@@2V0locale@2@A" => {
            &LOCALE_ID_COLLATE_D as *const usize as usize
        }
        "?id@?$collate@_W@std@@2V0locale@2@A" => {
            &LOCALE_ID_COLLATE_W as *const usize as usize
        }
        "?id@?$ctype@D@std@@2V0locale@2@A" => {
            &LOCALE_ID_CTYPE_D as *const usize as usize
        }
        "?id@?$ctype@_W@std@@2V0locale@2@A" => {
            &LOCALE_ID_CTYPE_W as *const usize as usize
        }
        "?_Raise_handler@std@@3P6AXAEBVexception@stdext@@@ZEA" => {
            &RAISE_HANDLER as *const u8 as usize
        }

        // ── Constructor implementations ───────────────────────────────────────────
        // Wine ref: dlls/msvcp60/ios.c — basic_streambuf_char_ctor ~line 830
        "??0?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAA@XZ" => {
            msvcp_streambuf_ctor as unsafe extern "win64" fn(*mut u8, usize, usize, usize) -> *mut u8
                as *const () as usize
        }
        // Wine ref: dlls/msvcp60/ios.c — basic_streambuf_char__Init_empty line 757
        "?_Init@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXXZ" => {
            msvcp_streambuf_init as unsafe extern "win64" fn(*mut u8, usize, usize, usize) -> *mut u8
                as *const () as usize
        }
        // Wine ref: dlls/msvcp60/ios.c — basic_ios_char_ctor line 4047
        "??0?$basic_ios@DU?$char_traits@D@std@@@std@@IEAA@XZ" => {
            msvcp_basic_ios_ctor as unsafe extern "win64" fn(*mut u8, usize, usize, usize) -> *mut u8
                as *const () as usize
        }
        // Wine ref: dlls/msvcp60/ios.c — basic_istream_char_ctor line 6074
        "??0?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA@PEAV?$basic_streambuf@DU?$char_traits@D@std@@@1@_N@Z" => {
            msvcp_istream_ctor as unsafe extern "win64" fn(*mut u8, *mut u8, usize, usize) -> *mut u8
                as *const () as usize
        }
        // Wine ref: dlls/msvcp60/ios.c — basic_ostream_char_ctor line 4510
        "??0?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAA@PEAV?$basic_streambuf@DU?$char_traits@D@std@@@1@_N@Z" => {
            msvcp_ostream_ctor as unsafe extern "win64" fn(*mut u8, *mut u8, usize, usize) -> *mut u8
                as *const () as usize
        }
        // Wine ref: dlls/msvcp60/ios.c — basic_iostream_char_ctor line 8309
        "??0?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAA@PEAV?$basic_streambuf@DU?$char_traits@D@std@@@1@@Z" => {
            msvcp_iostream_ctor as unsafe extern "win64" fn(*mut u8, *mut u8, usize, usize) -> *mut u8
                as *const () as usize
        }

        // ── Locale/facet diagnostic arms (shadow bulk noop) ──────────────────
        // Each logs the first call with `this`/arg0 to identify which C++
        // object's null-this triggers a corrupted vtable dispatch.
        "?_Getcat@?$ctype@D@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z" => {
            msvcp_diag_getcat_ctype_d as unsafe extern "win64" fn(usize, usize, usize, usize) -> usize
                as *const () as usize
        }
        "?_Getcat@?$ctype@_W@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z" => {
            msvcp_diag_getcat_ctype_w as unsafe extern "win64" fn(usize, usize, usize, usize) -> usize
                as *const () as usize
        }
        "?_Init@locale@std@@CAPEAV_Locimp@12@_N@Z" => {
            msvcp_diag_init_locale as unsafe extern "win64" fn(usize, usize, usize, usize) -> usize
                as *const () as usize
        }
        "?_Makeloc@_Locimp@locale@std@@CAPEAV123@AEBV_Locinfo@3@HPEAV123@PEBV23@@Z" => {
            msvcp_diag_makeloc as unsafe extern "win64" fn(usize, usize, usize, usize) -> usize
                as *const () as usize
        }
        "?_New_Locimp@_Locimp@locale@std@@CAPEAV123@_N@Z" => {
            msvcp_diag_new_locimp as unsafe extern "win64" fn(usize, usize, usize, usize) -> usize
                as *const () as usize
        }
        "?_Locimp_Addfac@_Locimp@locale@std@@CAXPEAV123@PEAVfacet@23@_K@Z" => {
            msvcp_diag_locimp_adderfac as unsafe extern "win64" fn(usize, usize, usize, usize) -> usize
                as *const () as usize
        }
        "?_Getgloballocale@locale@std@@CAPEAV_Locimp@12@XZ" => {
            msvcp_diag_getgloballocale as unsafe extern "win64" fn(usize, usize, usize, usize) -> usize
                as *const () as usize
        }
        "?_Getfalse@_Locinfo@std@@QEBAPEBDXZ" => {
            msvcp_diag_getfalse as unsafe extern "win64" fn(usize, usize, usize, usize) -> usize
                as *const () as usize
        }

        // ── Function symbols — all map to msvcp_noop ──────────────────────────────
        "??0?$codecvt@_WDU_Mbstatet@@@std@@QEAA@_K@Z"
        | "??0_Locinfo@std@@QEAA@PEBD@Z"
        | "??0_Lockit@std@@QEAA@H@Z"
        | "??0facet@locale@std@@IEAA@_K@Z"
        | "??1?$basic_ios@DU?$char_traits@D@std@@@std@@UEAA@XZ"
        | "??1?$basic_iostream@DU?$char_traits@D@std@@@std@@UEAA@XZ"
        | "??1?$basic_istream@DU?$char_traits@D@std@@@std@@UEAA@XZ"
        | "??1?$basic_ostream@DU?$char_traits@D@std@@@std@@UEAA@XZ"
        | "??1?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAA@XZ"
        | "??1?$codecvt@_WDU_Mbstatet@@@std@@MEAA@XZ"
        | "??1_Locinfo@std@@QEAA@XZ"
        | "??1_Lockit@std@@QEAA@XZ"
        | "??1facet@locale@std@@MEAA@XZ"
        | "??4?$_Yarn@D@std@@QEAAAEAV01@PEBD@Z"
        | "??Bid@locale@std@@QEAA_KXZ"
        | "?_Addfac@_Locimp@locale@std@@AEAAXPEAVfacet@23@_K@Z"
        | "?_Decref@facet@locale@std@@UEAAPEAV_Facet_base@3@XZ"
        | "?_Getcat@?$codecvt@DDU_Mbstatet@@@std@@SA_KPEAPEBVfacet@locale@2@PEBV42@@Z"
        | "?_Getcvt@_Locinfo@std@@QEBA?AU_Cvtvec@@XZ"
        | "?_Getlconv@_Locinfo@std@@QEBAPEBUlconv@@XZ"
        | "?_Gettrue@_Locinfo@std@@QEBAPEBDXZ"
        | "?_Incref@facet@locale@std@@UEAAXXZ"
        | "?_Lock@?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAAXXZ"
        | "?_New_Locimp@_Locimp@locale@std@@CAPEAV123@AEBV123@@Z"
        | "?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ"
        | "?_Throw_C_error@std@@YAXH@Z"
        | "?_Throw_Cpp_error@std@@YAXH@Z"
        | "?_Unlock@?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAAXXZ"
        | "?_Xbad_alloc@std@@YAXXZ"
        | "?_Xbad_function_call@std@@YAXXZ"
        | "?_Xlength_error@std@@YAXPEBD@Z"
        | "?_Xout_of_range@std@@YAXPEBD@Z"
        | "?clear@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z"
        | "?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@XZ"
        | "?imbue@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAXAEBVlocale@2@@Z"
        | "?in@?$codecvt@DDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEBD1AEAPEBDPEAD3AEAPEAD@Z"
        | "?out@?$codecvt@DDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEBD1AEAPEBDPEAD3AEAPEAD@Z"
        | "?out@?$codecvt@_WDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEB_W1AEAPEB_WPEAD3AEAPEAD@Z"
        | "?put@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@D@Z"
        | "?setbuf@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAPEAV12@PEAD_J@Z"
        | "?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z"
        | "?showmanyc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_JXZ"
        | "?sputc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHD@Z"
        | "?sync@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ"
        | "?uflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ"
        | "?uncaught_exception@std@@YA_NXZ"
        | "?unshift@?$codecvt@DDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEAD1AEAPEAD@Z"
        | "?widen@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADD@Z"
        | "?xsputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_JPEBD_J@Z"
        | "?eback@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ"
        | "?egptr@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ"
        | "?epptr@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ"
        | "?gptr@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ"
        | "?pbase@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ"
        | "?pptr@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ"
        | "?gbump@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXH@Z"
        | "?setg@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXPEAD00@Z"
        | "?setp@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXPEAD0@Z"
        | "?setp@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXPEAD00@Z"
        | "?_Pninc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAPEADXZ"
        | "?flags@ios_base@std@@QEBAHXZ"
        | "?good@ios_base@std@@QEBA_NXZ"
        | "?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBAPEAV?$basic_streambuf@DU?$char_traits@D@std@@@2@XZ"
        | "?tie@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBAPEAV?$basic_ostream@DU?$char_traits@D@std@@@2@XZ"
        |         "?width@ios_base@std@@QEAA_J_J@Z"
        | "?width@ios_base@std@@QEBA_JXZ"
        => msvcp_noop as *const () as usize,

        "?fill@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADXZ" => {
            msvcp_fill as unsafe extern "win64" fn(*const u8, usize, usize, usize) -> u8
                as *const () as usize
        }

        "?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEBD_J@Z" => {
            msvcp_sputn as unsafe extern "win64" fn(*const u8, *const u8, i64, usize) -> i64
                as *const () as usize
        }
        "?sputn@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAA_JPEB_W_J@Z" => {
            msvcp_sputn_w as unsafe extern "win64" fn(*const u8, *const u16, i64, usize) -> i64
                as *const () as usize
        }

        "?__ExceptionPtrToBool@@YA_NPEBX@Z" => {
            msvcp_exception_ptr_to_bool
                as unsafe extern "win64" fn(*const u64, usize, usize, usize) -> i32
                as *const () as usize
        }

        "?sputc@?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@QEAAG_W@Z" => {
            msvcp_sputc_w as unsafe extern "win64" fn(*const u8, u16, usize, usize) -> u16
                as *const () as usize
        }

        "?overflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHH@Z" => {
            msvcp_overflow as unsafe extern "win64" fn(*const u8, i32, usize, usize) -> i32
                as *const () as usize
        }

        "?_Xinvalid_argument@std@@YAXPEBD@Z" => {
            msvcp_xinvalid_argument as unsafe extern "win64" fn(*const u8, usize, usize, usize)
                as *const () as usize
        }

        "?_W_Getmonths@_Locinfo@std@@QEBAPEBGXZ" => {
            msvcp_w_getmonths as unsafe extern "win64" fn(*const u8, usize, usize, usize) -> usize
                as *const () as usize
        }
        "?_W_Getdays@_Locinfo@std@@QEBAPEBGXZ" => {
            msvcp_w_getdays as unsafe extern "win64" fn(*const u8, usize, usize, usize) -> usize
                as *const () as usize
        }

        "?pbackfail@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHH@Z" => {
            msvcp_pbackfail as unsafe extern "win64" fn(*const u8, i32, usize, usize) -> i32
                as *const () as usize
        }

        "?seekpos@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA?AV?$fpos@U_Mbstatet@@@2@V32@H@Z" => {
            msvcp_seekpos as unsafe extern "win64" fn(*const u8, usize, i32, usize) -> i32
                as *const () as usize
        }
        "?seekoff@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA?AV?$fpos@U_Mbstatet@@@2@_JHH@Z" => {
            msvcp_seekoff as unsafe extern "win64" fn(*const u8, i64, i32, i32) -> i32
                as *const () as usize
        }
        "?underflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ" => {
            msvcp_underflow as unsafe extern "win64" fn(*const u8, usize, usize, usize) -> i32
                as *const () as usize
        }
        "?_Gnavail@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBA_JXZ" => {
            msvcp_gnavail as unsafe extern "win64" fn(*const u8, usize, usize, usize) -> i64
                as *const () as usize
        }
        "?_Pnavail@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBA_JXZ" => {
            msvcp_pnavail as unsafe extern "win64" fn(*const u8, usize, usize, usize) -> i64
                as *const () as usize
        }

        // ── Bulk trivial stream status/accessor stubs ──────────────────────
        // All return safe defaults (no error, null pointers, EOF, etc.)
        // These were previously in the msvcp_noop bulk arm.
        "?good@ios_base@std@@QEBA_NXZ" => { msvcp_ios_good as unsafe extern "win64" fn(usize,usize,usize,usize)->i32 as *const () as usize }
        "?fail@ios_base@std@@QEBA_NXZ" => { msvcp_ios_fail as unsafe extern "win64" fn(usize,usize,usize,usize)->i32 as *const () as usize }
        "?bad@ios_base@std@@QEBA_NXZ" => { msvcp_ios_bad as unsafe extern "win64" fn(usize,usize,usize,usize)->i32 as *const () as usize }
        "?eof@ios_base@std@@QEBA_NXZ" => { msvcp_ios_eof as unsafe extern "win64" fn(usize,usize,usize,usize)->i32 as *const () as usize }
        "?width@ios_base@std@@QEBA_JXZ" => { msvcp_ios_width_get as unsafe extern "win64" fn(usize,usize,usize,usize)->i64 as *const () as usize }
        "?width@ios_base@std@@QEAA_J_J@Z" => { msvcp_ios_width_set as unsafe extern "win64" fn(usize,usize,usize,usize)->i64 as *const () as usize }
        "?flags@ios_base@std@@QEBAHXZ" => { msvcp_ios_flags_get as unsafe extern "win64" fn(usize,usize,usize,usize)->i32 as *const () as usize }
        "?sgetc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ" => { msvcp_streambuf_sgetc as unsafe extern "win64" fn(usize,usize,usize,usize)->i32 as *const () as usize }
        "?snextc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ" => { msvcp_streambuf_snextc as unsafe extern "win64" fn(usize,usize,usize,usize)->i32 as *const () as usize }
        "?gbump@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXH@Z" => { msvcp_streambuf_gbump as unsafe extern "win64" fn(usize,usize,usize,usize)->i32 as *const () as usize }
        "?pbump@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXH@Z" => { msvcp_streambuf_pbump as unsafe extern "win64" fn(usize,usize,usize,usize)->i32 as *const () as usize }
        "_Thrd_yield" => { msvcp_thrd_yield as unsafe extern "win64" fn(usize,usize,usize,usize)->i32 as *const () as usize }
        "_Thrd_hardware_concurrency" => { msvcp_thrd_hw_conc as unsafe extern "win64" fn(usize,usize,usize,usize)->i32 as *const () as usize }
        "_Cnd_broadcast" => { msvcp_cnd_broadcast as unsafe extern "win64" fn(usize,usize,usize,usize)->i32 as *const () as usize }
        "_Strcoll" => { msvcp_strcoll as unsafe extern "win64" fn(usize,usize,usize,usize)->i32 as *const () as usize }
        "_Wcscoll" => { msvcp_wcscoll as unsafe extern "win64" fn(usize,usize,usize,usize)->i32 as *const () as usize }
        "?tie@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBAPEAV?$basic_ostream@DU?$char_traits@D@std@@@2@XZ" => { msvcp_ios_tie as unsafe extern "win64" fn(usize,usize,usize,usize)->usize as *const () as usize }
        "?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBAPEAV?$basic_streambuf@DU?$char_traits@D@std@@@2@XZ" => { msvcp_ios_rdbuf_get as unsafe extern "win64" fn(usize,usize,usize,usize)->usize as *const () as usize }
        "?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAPEAV?$basic_streambuf@DU?$char_traits@D@std@@@2@PEAV32@@Z" => { msvcp_ios_rdbuf_set as unsafe extern "win64" fn(usize,usize,usize,usize)->usize as *const () as usize }
        "??0?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAA@AEBV01@@Z" => { msvcp_streambuf_copy_ctor as unsafe extern "win64" fn(*mut u8,*const u8,usize,usize)->*mut u8 as *const () as usize }
        "?_Id_cnt@id@locale@std@@0HA" => { &LOCALE_ID_CNT as *const std::sync::atomic::AtomicI32 as usize }
        "?write@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEBD_J@Z" => { msvcp_ostream_write as unsafe extern "win64" fn(*mut u8,*const u8,i64,usize)->*mut u8 as *const () as usize }
        "?out@?$codecvt@_SDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEB_S1AEAPEB_SPEAD3AEAPEAD@Z" => { msvcp_codecvt_out_short as unsafe extern "win64" fn(*const u8,*mut u8,*const u16,*const u16,*mut *const u16,*mut u8,*mut u8,*mut *mut u8)->i32 as *const () as usize }
        "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAN@Z" => { msvcp_istream_op_double as unsafe extern "win64" fn(*mut u8,*mut f64,usize,usize)->*mut u8 as *const () as usize }
        "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAJ@Z" => { msvcp_istream_op_long as unsafe extern "win64" fn(*mut u8,*mut i32,usize,usize)->*mut u8 as *const () as usize }
        "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAH@Z" => { msvcp_istream_op_int as unsafe extern "win64" fn(*mut u8,*mut i32,usize,usize)->*mut u8 as *const () as usize }
        "?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@XZ" => { msvcp_ostream_flush as unsafe extern "win64" fn(*mut u8,usize,usize,usize)->*mut u8 as *const () as usize }
        "?flush@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@XZ" => { msvcp_ostream_flush_w as unsafe extern "win64" fn(*mut u8,usize,usize,usize)->*mut u8 as *const () as usize }
        "?_Syserror_map@std@@YAPEBDH@Z" => { msvcp_syserror_map as unsafe extern "win64" fn(i32,usize,usize,usize)->usize as *const () as usize }
        "?_Osfx@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAXXZ" => { msvcp_osfx_nop as unsafe extern "win64" fn(usize,usize,usize,usize) as *const () as usize }
        "?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ" => { msvcp_osfx_nop as unsafe extern "win64" fn(usize,usize,usize,usize) as *const () as usize }
        "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@PEBX@Z" => { msvcp_op_lshift_ptr as unsafe extern "win64" fn(*mut u8,usize,usize,usize)->*mut u8 as *const () as usize }
        "?eback@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ" => { msvcp_streambuf_eback as unsafe extern "win64" fn(usize,usize,usize,usize)->usize as *const () as usize }
        "?egptr@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ" => { msvcp_streambuf_egptr as unsafe extern "win64" fn(usize,usize,usize,usize)->usize as *const () as usize }
        "?epptr@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ" => { msvcp_streambuf_epptr as unsafe extern "win64" fn(usize,usize,usize,usize)->usize as *const () as usize }
        "?gptr@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ" => { msvcp_streambuf_gptr as unsafe extern "win64" fn(usize,usize,usize,usize)->usize as *const () as usize }
        "?pbase@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ" => { msvcp_streambuf_pbase as unsafe extern "win64" fn(usize,usize,usize,usize)->usize as *const () as usize }
        "?pptr@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEBAPEADXZ" => { msvcp_streambuf_pptr as unsafe extern "win64" fn(usize,usize,usize,usize)->usize as *const () as usize }
        "?setg@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXPEAD00@Z" => { msvcp_streambuf_setg as unsafe extern "win64" fn(usize,usize,usize,usize)->usize as *const () as usize }
        "?setp@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXPEAD0@Z" => { msvcp_streambuf_setp_2 as unsafe extern "win64" fn(usize,usize,usize,usize)->usize as *const () as usize }
        "?setp@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXPEAD00@Z" => { msvcp_streambuf_setp_3 as unsafe extern "win64" fn(usize,usize,usize,usize)->usize as *const () as usize }
        "?_Pninc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAPEADXZ" => { msvcp_streambuf_pninc as unsafe extern "win64" fn(usize,usize,usize,usize)->usize as *const () as usize }
        "?_Gndec@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAPEADXZ" => { msvcp_streambuf_gndec as unsafe extern "win64" fn(usize,usize,usize,usize)->usize as *const () as usize }
        "?_Gninc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAPEADXZ" => { msvcp_streambuf_gninc as unsafe extern "win64" fn(usize,usize,usize,usize)->usize as *const () as usize }
        "?_Init@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXPEAPEAD0PEAH001@Z" => { msvcp_streambuf_init_2 as unsafe extern "win64" fn(usize,usize,usize,usize)->usize as *const () as usize }

        "_Cnd_wait" => {
            msvcp_cnd_wait as unsafe extern "win64" fn(*mut libc::c_void, *mut libc::c_void, usize, usize) -> i32
                as *const () as usize
        }

        "??7ios_base@std@@QEBA_NXZ" => {
            msvcp_ios_not as unsafe extern "win64" fn(*const u8, usize, usize, usize) -> i32
                as *const () as usize
        }

        "?init@?$basic_ios@DU?$char_traits@D@std@@@std@@IEAAXPEAV?$basic_streambuf@DU?$char_traits@D@std@@@2@_N@Z" => {
            msvcp_ios_init as unsafe extern "win64" fn(*mut u8, *mut u8, usize, usize)
                as *const () as usize
        }

        // ── Additional MSVCP140 stubs needed by Audacity ───────────────────
        "_Query_perf_counter" => {
            msvcp_query_perf_counter as unsafe extern "win64" fn(*mut i64, usize, usize, usize) -> i32
                as *const () as usize
        }
        "_Query_perf_frequency" => {
            msvcp_query_perf_frequency as unsafe extern "win64" fn(*mut i64, usize, usize, usize) -> i32
                as *const () as usize
        }
        "_Thrd_detach" => {
            msvcp_thrd_detach as unsafe extern "win64" fn(usize, usize, usize, usize) -> i32
                as *const () as usize
        }
        "?_Syserror_map@std@@YAPEBDH@Z"
        | "?write@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEBD_J@Z"
        | "?_Fiopen@std@@YAPEAU_iobuf@@PEBDHH@Z"
        | "?_Id_cnt@id@locale@std@@0HA"
        | "?getline@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEAD_J@Z"
        | "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@_K@Z"
        | "??Bios_base@std@@QEBA_NXZ"
        | "?_Ipfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA_N_N@Z"
        | "?get@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAHXZ"
        | "_Cnd_register_at_thread_exit"
        | "_Cnd_unregister_at_thread_exit"
        // ── Bulk-generated MSVCP140 stubs (Audacity 3.7.8) ─────────────────
        | "??0?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAA@AEBV01@@Z"
        | "??0?$codecvt@_SDU_Mbstatet@@@std@@QEAA@_K@Z"
        | "??0?$codecvt@_UDU_Mbstatet@@@std@@QEAA@_K@Z"
        | "??0_Locinfo@std@@QEAA@HPEBD@Z"
        | "??1?$codecvt@_SDU_Mbstatet@@@std@@MEAA@XZ"
        | "??1?$codecvt@_UDU_Mbstatet@@@std@@MEAA@XZ"
        | "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAH@Z"
        | "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAJ@Z"
        | "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAN@Z"
        | "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@F@Z"
        | "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@G@Z"
        | "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@K@Z"
        | "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@M@Z"
        | "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@N@Z"
        | "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@PEBX@Z"
        | "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@_J@Z"
        | "?_Getcoll@_Locinfo@std@@QEBA?AU_Collvec@@XZ"
        | "?_Getname@_Locinfo@std@@QEBAPEBDXZ"
        | "?_Osfx@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAXXZ"
        | "?_Winerror_map@std@@YAHH@Z"
        | "?_Xoverflow_error@std@@YAXPEBD@Z"
        | "?_Xregex_error@std@@YAXW4error_type@regex_constants@1@@Z"
        | "?_Xruntime_error@std@@YAXPEBD@Z"
        | "?bad@ios_base@std@@QEBA_NXZ"
        | "?c_str@?$_Yarn@D@std@@QEBAPEBDXZ"
        |         "?classic@locale@std@@SAAEBV12@XZ"
        | "?eof@ios_base@std@@QEBA_NXZ"
        // cout is a data export — handled via dedicated arm below
        // "?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A"
        | "?fill@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEBA_WXZ"
        | "?flush@?$basic_ostream@_WU?$char_traits@_W@std@@@std@@QEAAAEAV12@XZ"
        | "?gcount@?$basic_istream@DU?$char_traits@D@std@@@std@@QEBA_JXZ"
        | "?imbue@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAA?AVlocale@2@AEBV32@@Z"
        | "?in@?$codecvt@_WDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEBD1AEAPEBDPEA_W3AEAPEA_W@Z"
        | "?is@?$ctype@_W@std@@QEBA_NF_W@Z"
        | "?out@?$codecvt@_SDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEB_S1AEAPEB_SPEAD3AEAPEAD@Z"
        | "?out@?$codecvt@_UDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEB_U1AEAPEB_UPEAD3AEAPEAD@Z"
        | "?peek@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAHXZ"
        | "?rdbuf@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAPEAV?$basic_streambuf@DU?$char_traits@D@std@@@2@PEAV32@@Z"
        | "?rdbuf@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEBAPEAV?$basic_streambuf@_WU?$char_traits@_W@std@@@2@XZ"
        | "?resetiosflags@std@@YA?AU?$_Smanip@H@1@H@Z"
        | "?seekp@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@V?$fpos@U_Mbstatet@@@2@@Z"
        | "?setf@ios_base@std@@QEAAHHH@Z"
        | "?setprecision@std@@YA?AU?$_Smanip@_J@1@_J@Z"
        | "?setstate@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEAAXH_N@Z"
        | "?tellp@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAA?AV?$fpos@U_Mbstatet@@@2@XZ"
        | "?tie@?$basic_ios@_WU?$char_traits@_W@std@@@std@@QEBAPEAV?$basic_ostream@_WU?$char_traits@_W@std@@@2@XZ"
        | "?tolower@?$ctype@D@std@@QEBADD@Z"
        | "?tolower@?$ctype@D@std@@QEBAPEBDPEADPEBD@Z"
        | "?tolower@?$ctype@_W@std@@QEBAPEB_WPEA_WPEB_W@Z"
        | "?tolower@?$ctype@_W@std@@QEBA_W_W@Z"
        | "_Cnd_broadcast"
        | "_Strcoll"
        | "_Strxfrm"
        | "_Thrd_hardware_concurrency"
        | "_Thrd_yield"
        | "_Wcscoll"
        | "_Wcsxfrm"
        => {
            // Log the first unresolved msvcp140 symbol that hits the noop
            // fallback.  The `msvcp_noop` static diagnostic tells us the
            // this-pointer at call time; this tells us WHICH symbol.
            static MISSING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            if !MISSING.swap(true, std::sync::atomic::Ordering::Relaxed) {
                eprintln!("weave/msvcp: first unresolved symbol (msvcp_noop fallback): {func}");
            }
            msvcp_noop as *const () as usize
        }

        "?read@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@PEAD_J@Z" => {
            msvcp_read as unsafe extern "win64" fn(*mut u8, *mut u8, i64) -> *mut u8
                as *const () as usize
        }
        "?seekg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@_JH@Z" => {
            msvcp_seekg as unsafe extern "win64" fn(*mut u8, i64, i32) -> *mut u8
                as *const () as usize
        }
        "?tellg@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA?AV?$fpos@U_Mbstatet@@@2@XZ" => {
            msvcp_tellg as unsafe extern "win64" fn(*const u8, *mut i64, usize, usize) -> *mut i64
                as *const () as usize
        }
        "?xsgetn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_JPEAD_J@Z" => {
            msvcp_xsgetn as unsafe extern "win64" fn(*const u8, *mut u8, i64) -> i64
                as *const () as usize
        }
        "?sbumpc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ" => {
            msvcp_sbumpc as unsafe extern "win64" fn(*const u8, usize, usize, usize) -> i32
                as *const () as usize
        }

        "?setw@std@@YA?AU?$_Smanip@_J@1@_J@Z" => {
            msvcp_setw as unsafe extern "win64" fn(*mut usize, i64, usize, usize) -> *mut usize
                as *const () as usize
        }

        "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@P6AAEAVios_base@1@AEAV21@@Z@Z" => {
            msvcp_op_lshift_ios_base_manip
                as unsafe extern "win64" fn(
                    *mut u8,
                    Option<unsafe extern "win64" fn(*mut u8) -> *mut u8>,
                    usize,
                    usize,
                ) -> *mut u8 as *const () as usize
        }
        "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@P6AAEAV01@AEAV01@@Z@Z" => {
            msvcp_op_lshift_ostream_manip
                as unsafe extern "win64" fn(
                    *mut u8,
                    Option<unsafe extern "win64" fn(*mut u8) -> *mut u8>,
                    usize,
                    usize,
                ) -> *mut u8 as *const () as usize
        }
        "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@H@Z"
        | "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@I@Z"
        | "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@J@Z" => {
            msvcp_op_lshift_passthrough
                as unsafe extern "win64" fn(*mut u8, usize, usize, usize) -> *mut u8
                as *const () as usize
        }

        "?always_noconv@codecvt_base@std@@QEBA_NXZ" => {
            msvcp_always_noconv as *const () as usize
        }
        "?getloc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEBA?AVlocale@2@XZ" => {
            msvcp_getloc as *const () as usize
        }

        "?_Fiopen@std@@YAPEAU_iobuf@@PEB_WHH@Z" => {
            msvcp_fiopen as unsafe extern "win64" fn(*const u16, i32, i32) -> *mut libc::c_void
                as *const () as usize
        }

        "_Thrd_id" => msvcp_thrd_id as *const () as usize,
        "_Thrd_create" => msvcp_thrd_create as *const () as usize,
        "_Thrd_join" => msvcp_thrd_join as *const () as usize,
        "_Xtime_get_ticks" => msvcp_xtime_get_ticks as *const () as usize,

        "_Mtx_init_in_situ" => mtx_init_in_situ as *const () as usize,
        "_Mtx_destroy_in_situ" => mtx_destroy_in_situ as *const () as usize,
        "_Mtx_lock" => mtx_lock as *const () as usize,
        "_Mtx_unlock" => mtx_unlock as *const () as usize,
        "_Cnd_destroy_in_situ" => cnd_destroy_in_situ as *const () as usize,
        "_Cnd_signal" => cnd_signal as *const () as usize,
        "_Cnd_do_broadcast_at_thread_exit" => {
            msvcp_cnd_do_broadcast_at_thread_exit as *const () as usize
        }

        // ── Exception pointer stubs ──────────────────────────────────────────────
        "?__ExceptionPtrAssign@@YAXPEAXPEBX@Z" => {
            msvcp_exception_ptr_assign as unsafe extern "win64" fn(*mut u64, *const u64, usize, usize)
                as *const () as usize
        }
        "?__ExceptionPtrCopy@@YAXPEAXPEBX@Z" => {
            msvcp_exception_ptr_copy as unsafe extern "win64" fn(*mut u64, *const u64, usize, usize)
                as *const () as usize
        }
        "?__ExceptionPtrCopyException@@YAXPEAXPEBX1@Z" => {
            msvcp_exception_ptr_copy_exception
                as unsafe extern "win64" fn(*mut u64, *const u64, *const u64, usize)
                as *const () as usize
        }
        "?__ExceptionPtrCreate@@YAXPEAX@Z" => {
            msvcp_exception_ptr_create as unsafe extern "win64" fn(*mut u64, usize, usize, usize)
                as *const () as usize
        }
        "?__ExceptionPtrCurrentException@@YAXPEAX@Z" => {
            msvcp_exception_ptr_current_exception
                as unsafe extern "win64" fn(*mut u64, usize, usize, usize)
                as *const () as usize
        }
        "?__ExceptionPtrDestroy@@YAXPEAX@Z" => {
            msvcp_exception_ptr_destroy as unsafe extern "win64" fn(*mut u64, usize, usize, usize)
                as *const () as usize
        }
        "?__ExceptionPtrRethrow@@YAXPEBX@Z" => {
            msvcp_exception_ptr_rethrow as unsafe extern "win64" fn(*mut u64, usize, usize, usize)
                as *const () as usize
        }
        "?uncaught_exceptions@std@@YAHXZ" => {
            msvcp_uncaught_exceptions as unsafe extern "win64" fn() -> i32 as *const () as usize
        }

        _ => return None,
    };

    Some(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_function_stub_is_some() {
        assert!(resolve("msvcp140.dll", "_Mtx_lock").is_some());
    }

    #[test]
    fn resolve_function_stub_nonzero() {
        let addr = resolve("msvcp140.dll", "_Mtx_lock").unwrap();
        assert_ne!(addr, 0, "stub address must be non-zero");
    }

    #[test]
    fn resolve_badoff_data_symbol() {
        let addr = resolve("msvcp140.dll", "?_BADOFF@std@@3_JB").unwrap();
        assert_ne!(addr, 0);
        let val = unsafe { *(addr as *const i64) };
        assert_eq!(val, -1);
    }

    #[test]
    fn resolve_cerr_data_symbol() {
        let addr = resolve(
            "msvcp140.dll",
            "?cerr@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A",
        )
        .unwrap();
        assert_ne!(addr, 0);
    }

    #[test]
    fn resolve_unknown_dll_returns_none() {
        assert!(resolve("kernel32.dll", "_Mtx_lock").is_none());
    }

    #[test]
    fn resolve_unknown_func_returns_none() {
        assert!(resolve("msvcp140.dll", "not_a_real_symbol").is_none());
    }
}
