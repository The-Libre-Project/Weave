//! MSVCP140.dll stubs for Weave.
//!
//! All 80 imports used by NXEngine-evo (nx.exe) are resolved here.
//! Function stubs are no-op — they accept any Win64 arguments and return 0.
//! Real pthread implementations for _Mtx_* and _Cnd_* added in TASK-3.
#![allow(clippy::missing_safety_doc)]
//! Real implementations of _Thrd_* come in TASK-4.
//!
//! Wine ref: dlls/msvcp140/msvcp140.c — _Mtx_init_in_situ(mtx, flags),
//!   _Mtx_lock(mtx) returns _Thrd_success = 0.
//! Do NOT add warn_once logging here — these methods are called many times per frame.

/// Single no-op stub for all remaining function symbols.
/// Win64 ABI places return value in RAX; returning 0 covers void, ptr, and int return types.
pub unsafe extern "win64" fn msvcp_noop(_a: usize, _b: usize, _c: usize, _d: usize) -> usize {
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
    // Set self-referential pointer fields
    streambuf_init_empty(this);
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
                            // basic_ios_char_init: strbuf=sb, stream=NULL, fillch=' '
    ios_char_init(base, sb);
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
    cnd: *mut libc::c_void,
    _b: usize,
    _c: usize,
    _d: usize,
) -> usize {
    #[cfg(target_os = "linux")]
    {
        libc::pthread_cond_destroy(cnd as *mut libc::pthread_cond_t);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cnd;
    }
    0
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
        "?id@?$codecvt@DDU_Mbstatet@@@std@@2V0locale@2@A" => {
            &LOCALE_ID_CODECVT_DD as *const usize as usize
        }
        "?id@?$codecvt@_WDU_Mbstatet@@@std@@2V0locale@2@A" => {
            &LOCALE_ID_CODECVT_WD as *const usize as usize
        }
        "?id@?$numpunct@D@std@@2V0locale@2@A" => {
            &LOCALE_ID_NUMPUNCT as *const usize as usize
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
        | "?_Getfalse@_Locinfo@std@@QEBAPEBDXZ"
        | "?_Getgloballocale@locale@std@@CAPEAV_Locimp@12@XZ"
        | "?_Getlconv@_Locinfo@std@@QEBAPEBUlconv@@XZ"
        | "?_Gettrue@_Locinfo@std@@QEBAPEBDXZ"
        | "?_Incref@facet@locale@std@@UEAAXXZ"
        | "?_Init@locale@std@@CAPEAV_Locimp@12@_N@Z"
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
        | "?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEBD_J@Z"
        | "?sync@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ"
        | "?uflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ"
        | "?uncaught_exception@std@@YA_NXZ"
        | "?unshift@?$codecvt@DDU_Mbstatet@@@std@@QEBAHAEAU_Mbstatet@@PEAD1AEAPEAD@Z"
        | "?widen@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADD@Z"
        | "?xsputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_JPEBD_J@Z"
        => msvcp_noop as *const () as usize,

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
        | "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@I@Z" => {
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
