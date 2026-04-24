//! Periodic thread-state sampler for diagnosing stalls.
//!
//! When `WEAVE_STALL_TRACE=1` is set at process start, `start_if_enabled()`
//! spawns a background sampler thread that every second reads
//! `/proc/self/task/*/{comm,syscall}` and emits one compact stderr line per
//! sample round. Useful for pinpointing where the guest is stuck when stderr
//! stops flowing but the process remains alive.
//!
//! The 1 Hz interval is intentionally coarse: the nxengine gate's stderr
//! capture is unbuffered and the parent only reads after the child dies, so a
//! higher sample rate risks overflowing the ~64 KiB pipe buffer and silently
//! truncating the log. 20 seconds at 1 Hz = 20 lines ≈ 16 KiB, well under.
//!
//! Linux-only. Compiles to a no-op on other platforms.
//!
//! Output format:
//! ```text
//! weave/stall t=500ms n=3 [tid=123 nx sc=202 pc=0x7f...] [tid=124 stall-trace sc=0 pc=0x55...]
//! ```
//! `sc` is the first token of `/proc/self/task/<tid>/syscall`: the syscall
//! number when the thread is in a kernel call, `-1` when blocked in a
//! non-syscall kernel path, or the literal `running` when executing user-space
//! code. See syscall(2) / the arch syscall table.
//!
//! `pc` is the last token of the same file — the user-space program counter at
//! syscall entry when `sc` is numeric. When `sc=running` there is no PC to
//! read from `/proc/.../syscall`, so `pc` is backfilled from
//! `/proc/.../stat` field 30 (kstkeip / last kernel-observed PC).

use std::sync::OnceLock;

static STALL_TRACE_ENABLED: OnceLock<bool> = OnceLock::new();

/// Returns true iff `WEAVE_STALL_TRACE=1` was set when this process started.
/// The result is cached after the first call.
pub fn enabled() -> bool {
    *STALL_TRACE_ENABLED.get_or_init(|| {
        std::env::var("WEAVE_STALL_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

/// Spawn the sampler thread if `WEAVE_STALL_TRACE=1`. Safe to call multiple
/// times — only the first call spawns a thread (guarded by a OnceLock).
#[cfg(target_os = "linux")]
pub fn start_if_enabled() {
    if !enabled() {
        return;
    }
    static SPAWNED: OnceLock<()> = OnceLock::new();
    SPAWNED.get_or_init(|| {
        let _ = std::thread::Builder::new()
            .name("stall-trace".into())
            .spawn(sampler_loop);
    });
}

#[cfg(not(target_os = "linux"))]
pub fn start_if_enabled() {}

#[cfg(target_os = "linux")]
fn sampler_loop() {
    let start = std::time::Instant::now();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let t_ms = start.elapsed().as_millis();
        let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
            continue;
        };
        let mut line = format!("weave/stall t={t_ms}ms");
        let mut n = 0usize;
        let mut threads = String::new();
        for entry in tasks.flatten() {
            let tid_os = entry.file_name();
            let tid = tid_os.to_string_lossy();
            let comm = std::fs::read_to_string(format!("/proc/self/task/{tid}/comm"))
                .unwrap_or_default()
                .trim()
                .to_string();
            // /proc/self/task/<tid>/syscall format:
            //   "<nr> <arg0> <arg1> ... <sp> <pc>"   — thread in a numbered syscall
            //   "running"                             — thread in user-space
            //   "-1 0x<sp> 0x<pc>"                    — blocked in non-syscall kernel path
            let syscall_raw = std::fs::read_to_string(format!("/proc/self/task/{tid}/syscall"))
                .unwrap_or_default();
            let toks: Vec<&str> = syscall_raw.split_whitespace().collect();
            let (sc_nr, mut pc) = match toks.split_first() {
                Some((first, rest)) if !rest.is_empty() => {
                    (*first, rest.last().copied().unwrap_or("-").to_string())
                }
                Some((first, _)) => (*first, "-".to_string()),
                None => ("?", "-".to_string()),
            };
            // When the thread is running user code, /proc/.../syscall has no PC.
            // Fall back to /proc/.../stat field 30 (kstkeip) so we still get a
            // location for purely user-space stalls. Stat's comm field is in
            // parens and can contain spaces — split from the last ')'.
            if pc == "-" {
                if let Ok(stat) = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")) {
                    if let Some(post_comm) = stat.rsplit_once(')').map(|(_, r)| r) {
                        let fields: Vec<&str> = post_comm.split_whitespace().collect();
                        // fields[0] = state (field 3), so kstkeip (field 30) = fields[27].
                        // kstkeip is printed as %lu (unsigned decimal); reformat as hex.
                        if let Some(kstkeip) = fields.get(27).and_then(|s| s.parse::<u64>().ok()) {
                            pc = format!("0x{kstkeip:x}");
                        }
                    }
                }
            }
            threads.push_str(&format!(" [tid={tid} {comm} sc={sc_nr} pc={pc}]"));
            n += 1;
        }
        line.push_str(&format!(" n={n}{threads}"));
        eprintln!("{line}");
    }
}
