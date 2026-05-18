/// Convert a Unix timespec (seconds + nanoseconds since 1970-01-01) to a Windows
/// FILETIME (100-nanosecond intervals since 1601-01-01).
///
/// The epoch offset is 11,644,473,600 seconds (from 1601-01-01 to 1970-01-01).
/// Linux `st_ctime` (change-time) is used as a creation-time proxy when no true
/// birth-time is available.
///
/// # Overflow
/// `secs` is saturating-added to the epoch offset; values before 1601 are clamped
/// to 0 (which represents 1601-01-01). No panic.
pub fn unix_to_filetime(secs: i64, nsecs: i64) -> u64 {
    let secs_since_1601 = secs.saturating_add(11_644_473_600) as u64;
    secs_since_1601 * 10_000_000 + (nsecs as u64) / 100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_to_filetime_epoch() {
        // Unix epoch (1970-01-01 00:00:00 UTC) → FILETIME = 116444736000000000
        assert_eq!(unix_to_filetime(0, 0), 116_444_736_000_000_000u64);
        // 1 second = 10,000,000 100-ns ticks
        assert_eq!(unix_to_filetime(1, 0), 116_444_736_010_000_000u64);
    }
}
