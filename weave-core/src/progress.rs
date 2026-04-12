use std::sync::OnceLock;
use std::time::Instant;

static START: OnceLock<Instant> = OnceLock::new();

#[inline]
pub fn mark_phase(name: &str) {
    let start = START.get_or_init(Instant::now);
    let ms = start.elapsed().as_millis();
    eprintln!("PHASE: {} t={}", name, ms);
}
