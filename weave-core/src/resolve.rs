//! Global import resolver registration.
//!
//! `weave-cli` registers the full resolver chain once at startup. Stub crates
//! (e.g. `weave-kernel32`) call `resolve()` at runtime for dynamic imports
//! like `LoadLibraryExW` / `GetProcAddress`.

use std::sync::OnceLock;

/// A function that resolves a (dll, func) pair to a stub address.
pub type ResolveFn = fn(&str, &str) -> Option<usize>;

static RESOLVER: OnceLock<ResolveFn> = OnceLock::new();

/// Register the global import resolver. Call once from `weave-cli` before
/// jumping to the PE entry point. Subsequent calls are silently ignored.
pub fn set(f: ResolveFn) {
    let _ = RESOLVER.set(f);
}

/// Resolve a `(dll, func)` pair via the registered resolver.
/// Returns `None` if no resolver has been registered or the symbol is unknown.
pub fn resolve(dll: &str, func: &str) -> Option<usize> {
    RESOLVER.get().and_then(|f| f(dll, func))
}
