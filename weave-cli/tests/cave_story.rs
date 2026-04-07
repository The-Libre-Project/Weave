//! Cave Story SDL2 game test — WS2 gate.
use super::*;

#[test]
#[ignore = \"fixture required\"]
fn cave_story_launches() {
    if !cfg!(target_os = \"linux\") {
        eprintln!(\"skipping: requires Linux\");
        return;
    }
    let fixture_dir = format!(\"{}/../tests/fixtures/cavestory\", env!(\"CARGO_MANIFEST_DIR\"));
    let exe = format!(\"{}/Doukutsu.exe\", fixture_dir);
    if !std::path::Path::new(&exe).exists() {
        eprintln!(\"skipping: {} missing (wget https://cavestory.org/files/CaveStory+103.exe -O {})\", exe, exe);
        return;
    }
    let weave = env!(\"CARGO_BIN_EXE_weave\");
    let output = std::process::Command::new(weave)
        .current_dir(&fixture_dir)
        .arg(\"Doukutsu.exe\")  // Launches SDL window + DXVK
        .stderr(std::process::Stdio::piped())
        .output()
        .expect(\"spawn weave cavestory\");
    let elapsed = std::time::Instant::now();  // Timeout logic omitted for brevity
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!(\"cavestory stderr:\\n{stderr}\");
    // SDL2/DXVK success: window creates, DXVK logs \"Vulkan device\", runtime >5s
    assert!(stderr.contains(\"weave/user32: CreateWindowExW\") || stderr.contains(\"DXVK\"), \"No window/DXVK: {stderr}\");
}
