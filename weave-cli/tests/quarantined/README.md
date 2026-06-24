# Quarantined Tests

Tests in this directory have `#[ignore]` applied and are moved out of
`hello_world.rs` to keep the main test file focused on active, passing gates.
They are **not** deleted — they remain in the `weave-cli` crate and can be run
explicitly when needed.

## How to run

```sh
# Run all quarantined tests
cargo test -p weave-cli -- --ignored

# Run a specific quarantined test
cargo test -p weave-cli sevenzip_m13_roundtrip_gate -- --ignored

# Run all tests in a quarantined category file
cargo test -p weave-cli --test quarantined/m13_roundtrip -- --ignored
```

Each test retains its original `#[ignore]` attribute and its platform guard
(`cfg!(target_os = "linux")`) — you must run on Linux.

## Categories

| File | Tests | Reason for quarantine |
|------|-------|----------------------|
| `m13_roundtrip.rs` | `sevenzip_m13_roundtrip_gate`, `sevenzip_m13_store_roundtrip_gate`, `sevenzip_m13_v23_roundtrip_gate` | M13 MSVC residual — MSVC-built 7za.exe fails with `0x80070057` in the archive metadata write path. Classified `MSVC_INTERNAL_PATH_UNRESOLVED`. See `docs/reference/KNOWN-BUG-CLASSES.md` and `docs/milestones/M13-7za-roundtrip.md` § "Residual". |
| `npp_editor_roundtrip.rs` | `notepad_m15_edit_save_roundtrip_gate` | M15 Tier A gate — Notepad++ save-via-message roundtrip. Marked `#[ignore]` per M6/E3-M2 pattern; the CI run that removes ignore + passes is the §11 promotion evidence. See `docs/milestones/M15-notepad-editor-roundtrip.md`. |
| `qdir_shell_namespace.rs` | `q_dir_shell_namespace_gate` | Flaky under Xvfb — window detection timing varies. Proved IShellFolder path works on CI (run 27926668511). See `docs/reference/KNOWN-BUG-CLASSES.md` § "Xvfb timing race". |

## Restoration condition

Each test's doc comment documents its specific restoration condition.
In general, a test leaves quarantine when:
1. The underlying Weave fix is implemented and tested.
2. The `#[ignore]` is removed and the test passes on CI.
3. The promotion evidence (CI run ID) is recorded in the doc comment.
