#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

static CALLBACK_COUNT: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_ERROR: AtomicU32 = AtomicU32::new(0);
static CALLBACK_BYTES: AtomicU32 = AtomicU32::new(0);
static CALLBACK_OVERLAPPED: AtomicUsize = AtomicUsize::new(0);

unsafe extern "win64" fn watch_completion_callback(error: u32, bytes: u32, overlapped: *mut u8) {
    CALLBACK_ERROR.store(error, Ordering::SeqCst);
    CALLBACK_BYTES.store(bytes, Ordering::SeqCst);
    CALLBACK_OVERLAPPED.store(overlapped as usize, Ordering::SeqCst);
    CALLBACK_COUNT.fetch_add(1, Ordering::SeqCst);
}

fn reset_callback() {
    CALLBACK_COUNT.store(0, Ordering::SeqCst);
    CALLBACK_ERROR.store(0, Ordering::SeqCst);
    CALLBACK_BYTES.store(0, Ordering::SeqCst);
    CALLBACK_OVERLAPPED.store(0, Ordering::SeqCst);
}

fn wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

#[test]
fn overlapped_directory_watch_registers_completes_and_cancels() {
    reset_callback();

    // ── 1. Create a temp directory ──────────────────────────────────────────
    let root = std::env::temp_dir().join(format!("weave-watch-gate-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("create watch fixture dir");
    let wide_root = wide(&root.to_string_lossy());

    // ── 2. Open the directory with FILE_LIST_DIRECTORY access ────────────────
    const FILE_LIST_DIRECTORY: u32 = 0x0001;
    const OPEN_EXISTING: u32 = 3;
    let dir_handle = unsafe {
        weave_kernel32::create_file_w(
            wide_root.as_ptr(),
            FILE_LIST_DIRECTORY,
            0,
            0,
            OPEN_EXISTING,
            0,
            0,
        )
    };
    assert_ne!(dir_handle, usize::MAX, "must open directory handle");

    // ── 3. A1: ReadDirectoryChangesW returns TRUE with ERROR_IO_PENDING ─────
    let mut buffer = [0u8; 256];
    let mut overlapped = [0usize; 4];
    let callback = watch_completion_callback as *const () as usize;

    let result = unsafe {
        weave_kernel32::read_directory_changes_w(
            dir_handle,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
            1,
            std::ptr::null_mut(),
            overlapped.as_mut_ptr() as *mut u8,
            callback,
        )
    };
    assert_eq!(result, 1, "A1: ReadDirectoryChangesW must return TRUE");
    assert_eq!(
        weave_kernel32::get_last_error(),
        997, // ERROR_IO_PENDING
        "A1: last error must be ERROR_IO_PENDING"
    );
    assert_eq!(
        overlapped[0],
        0x103, // STATUS_PENDING
        "A1: overlapped.Internal must be STATUS_PENDING"
    );

    // ── 4. A2: Create a file in the watched directory ────────────────────────
    let file_path = root.join("new_file.txt");
    std::fs::write(&file_path, b"test data").expect("create watched file");

    // Wait alertably so the inotify fd is polled and the callback fires.
    unsafe { weave_kernel32::wait_for_multiple_objects_ex(0, std::ptr::null(), 0, 5000, 1) };

    // ── 5. Verify A2 callback ────────────────────────────────────────────────
    assert_eq!(
        CALLBACK_COUNT.load(Ordering::SeqCst),
        1,
        "A2: callback must fire exactly once"
    );
    assert_eq!(
        CALLBACK_ERROR.load(Ordering::SeqCst),
        0,
        "A2: callback error must be 0 (success)"
    );
    assert!(
        CALLBACK_BYTES.load(Ordering::SeqCst) > 0,
        "A2: callback bytes must be > 0"
    );
    assert_eq!(
        CALLBACK_OVERLAPPED.load(Ordering::SeqCst),
        overlapped.as_mut_ptr() as usize,
        "A2: callback must receive the original OVERLAPPED pointer"
    );

    // ── 6. A3: CancelIoEx cancels with ERROR_OPERATION_ABORTED ──────────────
    reset_callback();
    let mut cancelled_overlapped = [0usize; 4];
    let result2 = unsafe {
        weave_kernel32::read_directory_changes_w(
            dir_handle,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
            1,
            std::ptr::null_mut(),
            cancelled_overlapped.as_mut_ptr() as *mut u8,
            callback,
        )
    };
    assert_eq!(result2, 1, "A3: second watch must register");

    let cancel_result = unsafe {
        weave_kernel32::cancel_io_ex(dir_handle, cancelled_overlapped.as_mut_ptr() as usize)
    };
    assert_eq!(
        cancel_result, 1,
        "A3: CancelIoEx must return TRUE for active watch"
    );

    // Verify no more cancellations succeed.
    let cancel_result2 = unsafe {
        weave_kernel32::cancel_io_ex(dir_handle, cancelled_overlapped.as_mut_ptr() as usize)
    };
    assert_eq!(cancel_result2, 0, "A3: second cancel must return FALSE");

    unsafe { weave_kernel32::wait_for_multiple_objects_ex(0, std::ptr::null(), 0, 5000, 1) };

    assert_eq!(
        CALLBACK_COUNT.load(Ordering::SeqCst),
        1,
        "A3: cancelled callback must fire exactly once"
    );
    assert_eq!(
        CALLBACK_ERROR.load(Ordering::SeqCst),
        995,
        "A3: cancelled callback error must be 995 (ERROR_OPERATION_ABORTED)"
    );

    // ── 7. Close handle (tests cleanup) ─────────────────────────────────────
    assert_eq!(
        weave_kernel32::close_handle(dir_handle),
        1,
        "A3: CloseHandle must succeed"
    );

    // Cleanup
    let _ = std::fs::remove_file(&file_path);
    let _ = std::fs::remove_dir(&root);
}
