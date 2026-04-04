//! Desktop notification support for Weave.
//!
//! Sends Linux desktop notifications by spawning `notify-send` (libnotify CLI).
//! All calls are best-effort: if `notify-send` is not installed or the spawn
//! fails, the error is silently ignored so the guest application continues
//! running normally.

use std::io;

/// Send a desktop notification with a title and body.
///
/// Spawns `notify-send <title> <body>` as a detached subprocess. Returns
/// `Ok(())` as soon as the process is spawned — not when the notification
/// is delivered. Returns `Ok(())` silently if `notify-send` is not installed.
pub fn send(title: &str, body: &str) -> io::Result<()> {
    match std::process::Command::new("notify-send")
        .arg(title)
        .arg(body)
        .spawn()
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_returns_ok() {
        // On macOS (dev), notify-send is not installed — send() must return Ok.
        // On Linux with notify-send present, the subprocess is spawned and also Ok.
        assert!(send("Weave test", "notification unit test").is_ok());
    }
}