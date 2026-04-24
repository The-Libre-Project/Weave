//! Periodic thread-state sampler for diagnosing stalls.
//!
//! When `WEAVE_STALL_TRACE=1` is set at process start, `start_if_enabled()`
//! records the calling thread's TID as the profile target, installs a
//! `SIGPROF` handler that captures the interrupted RIP into a global atomic,
//! and spawns a background sampler thread that every second reads
//! `/proc/self/task/*/{comm,syscall,stat}` and emits one compact stderr line
//! per sample round. For the target thread the sampler also sends a `SIGPROF`
//! via `tgkill` and reads back the captured user-space RIP, giving an exact
//! location even when the thread is in a CPU-bound user-code loop (where
//! kstkeip reads 0 and `/proc/.../syscall` has no PC).
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
//! weave/stall t=1000ms n=2 [tid=123 nx sc=running pc=0x0 prof=0x1400a98d0] ...
//! ```
//! `sc` is the first token of `/proc/self/task/<tid>/syscall`: the syscall
//! number when the thread is in a kernel call, `-1` when blocked in a
//! non-syscall kernel path, or `running` when executing user-space code.
//!
//! `pc` comes from the syscall file's trailing RIP field when sc is numeric,
//! or from `/proc/.../stat` field 30 (kstkeip) as a fallback.
//!
//! `prof=...` is the SIGPROF-sampled user RIP for the target thread, captured
//! at the moment the signal was delivered. Only printed for the profile
//! target; other threads show `prof=-`.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

static STALL_TRACE_ENABLED: OnceLock<bool> = OnceLock::new();
static TARGET_TID: AtomicI32 = AtomicI32::new(0);
static LAST_PROF_RIP: AtomicU64 = AtomicU64::new(0);

/// Returns true iff `WEAVE_STALL_TRACE=1` was set when this process started.
/// The result is cached after the first call.
pub fn enabled() -> bool {
    *STALL_TRACE_ENABLED.get_or_init(|| {
        std::env::var("WEAVE_STALL_TRACE")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

/// Install the SIGPROF handler, record the calling thread's TID as the
/// profile target, and spawn the sampler thread if `WEAVE_STALL_TRACE=1`.
/// Must be called from the thread that will run the guest PE — we profile
/// that thread via `tgkill(SIGPROF)` on each sample round.
///
/// Safe to call multiple times; only the first invocation does work.
#[cfg(target_os = "linux")]
pub fn start_if_enabled() {
    if !enabled() {
        return;
    }
    static SPAWNED: OnceLock<()> = OnceLock::new();
    SPAWNED.get_or_init(|| {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
        TARGET_TID.store(tid, Ordering::Relaxed);
        install_sigprof_handler();
        let _ = std::thread::Builder::new()
            .name("stall-trace".into())
            .spawn(sampler_loop);
    });
}

#[cfg(not(target_os = "linux"))]
pub fn start_if_enabled() {}

#[cfg(target_os = "linux")]
fn install_sigprof_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigprof_handler as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGPROF, &sa, std::ptr::null_mut());
    }
}

/// Async-signal-safe SIGPROF handler.
///
/// Pulls the interrupted RIP out of `ucontext_t.uc_mcontext.gregs[REG_RIP]`
/// and stores it into a global atomic for the sampler thread to read.
/// Does not allocate, does not touch stdlib I/O, does nothing else.
#[cfg(target_os = "linux")]
extern "C" fn sigprof_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    ctx: *mut libc::c_void,
) {
    if ctx.is_null() {
        return;
    }
    unsafe {
        let uc = &*(ctx as *const libc::ucontext_t);
        let rip = uc.uc_mcontext.gregs[libc::REG_RIP as usize] as u64;
        LAST_PROF_RIP.store(rip, Ordering::Relaxed);
    }
}

/// Send SIGPROF to the target thread and wait briefly for the handler to
/// store its RIP. Returns the captured RIP, or 0 if the signal could not be
/// delivered or the handler did not run in time.
#[cfg(target_os = "linux")]
fn sample_target_rip() -> u64 {
    let tid = TARGET_TID.load(Ordering::Relaxed);
    if tid == 0 {
        return 0;
    }
    LAST_PROF_RIP.store(0, Ordering::Relaxed);
    let pid = unsafe { libc::getpid() };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_tgkill,
            pid as libc::c_long,
            tid as libc::c_long,
            libc::SIGPROF as libc::c_long,
        )
    };
    if rc != 0 {
        return 0;
    }
    // Give the handler time to run on the target thread.
    std::thread::sleep(std::time::Duration::from_millis(5));
    LAST_PROF_RIP.load(Ordering::Relaxed)
}

#[cfg(target_os = "linux")]
fn sampler_loop() {
    let start = std::time::Instant::now();
    let target_tid = TARGET_TID.load(Ordering::Relaxed);
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let t_ms = start.elapsed().as_millis();
        // Sample the target thread's user RIP via SIGPROF before walking
        // /proc so the sample lines up tightly with the comm/syscall read.
        let prof_rip = sample_target_rip();
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
            // Only annotate the profile target with the SIGPROF-captured RIP.
            // Parse the /proc entry's tid; compare as i32 to avoid string ops.
            let is_target = tid.parse::<i32>().ok() == Some(target_tid);
            let prof_str = if is_target && prof_rip != 0 {
                format!("0x{prof_rip:x}")
            } else {
                "-".to_string()
            };
            threads.push_str(&format!(
                " [tid={tid} {comm} sc={sc_nr} pc={pc} prof={prof_str}]"
            ));
            n += 1;
        }
        line.push_str(&format!(" n={n}{threads}"));
        eprintln!("{line}");
    }
}
