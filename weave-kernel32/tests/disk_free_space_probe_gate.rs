// Probe gate — TASK-1: GetDiskFreeSpaceExW + GetDiskFreeSpaceW real statvfs() implementation.
//
// Only runs on Linux x86_64 where statvfs(2) is available and the win64
// calling convention is supported.
//
// Test plan:
//   1. Call GetDiskFreeSpaceExW with null lpDirectoryName (defaults to "/").
//      Assert: returns TRUE, free_bytes_available <= total_bytes, total_bytes > 0.
//   2. Call GetDiskFreeSpaceW with null lpRootPathName (defaults to "/").
//      Assert: returns TRUE, bytes_per_sector == 512, sectors_per_cluster > 0,
//      total_clusters > 0.
//   3. Verify all three output pointers for GetDiskFreeSpaceExW are independently
//      nullable (no crash when passing null for any subset).

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use weave_kernel32::{get_disk_free_space_ex_w, get_disk_free_space_w};

#[test]
fn get_disk_free_space_ex_w_null_path_returns_real_values() {
    let mut free_bytes_available: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut total_free_bytes: u64 = 0;

    let ret = unsafe {
        get_disk_free_space_ex_w(
            std::ptr::null(), // lpDirectoryName — null → defaults to "/"
            &mut free_bytes_available as *mut u64,
            &mut total_bytes as *mut u64,
            &mut total_free_bytes as *mut u64,
        )
    };

    // Tier A assertions:
    assert_eq!(ret, 1, "GetDiskFreeSpaceExW must return TRUE (1)");
    assert!(
        total_bytes > 0,
        "total_bytes must be > 0, got {total_bytes}"
    );
    assert!(
        free_bytes_available <= total_bytes,
        "free_bytes_available ({free_bytes_available}) must be <= total_bytes ({total_bytes})"
    );
}

#[test]
fn get_disk_free_space_ex_w_nullable_output_pointers_do_not_crash() {
    // All three output pointers are individually nullable per Wine behavioral contract.
    let mut total_bytes: u64 = 0;

    // Only total_bytes provided; avail and free are null.
    let ret = unsafe {
        get_disk_free_space_ex_w(
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut total_bytes as *mut u64,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(
        ret, 1,
        "GetDiskFreeSpaceExW with partial nulls must return TRUE"
    );
    assert!(
        total_bytes > 0,
        "total_bytes must be > 0 even with partial null output"
    );

    // All three output pointers null — must not crash.
    let ret = unsafe {
        get_disk_free_space_ex_w(
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(
        ret, 1,
        "GetDiskFreeSpaceExW with all-null outputs must return TRUE"
    );
}

#[test]
fn get_disk_free_space_w_null_path_returns_real_cluster_values() {
    let mut sectors_per_cluster: u32 = 0;
    let mut bytes_per_sector: u32 = 0;
    let mut free_clusters: u32 = 0;
    let mut total_clusters: u32 = 0;

    let ret = unsafe {
        get_disk_free_space_w(
            std::ptr::null(), // lpRootPathName — null → defaults to "/"
            &mut sectors_per_cluster as *mut u32,
            &mut bytes_per_sector as *mut u32,
            &mut free_clusters as *mut u32,
            &mut total_clusters as *mut u32,
        )
    };

    // Tier A assertions:
    assert_eq!(ret, 1, "GetDiskFreeSpaceW must return TRUE (1)");
    assert_eq!(
        bytes_per_sector, 512,
        "bytes_per_sector must be 512, got {bytes_per_sector}"
    );
    assert!(
        sectors_per_cluster > 0,
        "sectors_per_cluster must be > 0, got {sectors_per_cluster}"
    );
    assert!(
        total_clusters > 0,
        "total_clusters must be > 0, got {total_clusters}"
    );
}
