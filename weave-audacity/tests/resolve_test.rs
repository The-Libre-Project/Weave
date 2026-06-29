//! Quick test to verify that weave_audacity::resolve handles portaudio ordinals.
//! Run: cargo test -p weave-audacity --test resolve_test

#[test]
fn resolve_portaudio_ordinal_4() {
    let addr = weave_audacity::resolve("portaudio_x64.dll", "#4");
    assert!(addr.is_some(), "resolve(#4) must return Some for portaudio stub");
    assert!(addr.unwrap() != 0, "stub address must not be 0");
}

#[test]
fn resolve_portaudio_ordinal_70() {
    let addr = weave_audacity::resolve("portaudio_x64.dll", "#70");
    assert!(addr.is_some(), "resolve(#70) must return Some for portaudio stub");
}

#[test]
fn resolve_portaudio_ordinal_75() {
    let addr = weave_audacity::resolve("portaudio_x64.dll", "#75");
    assert!(addr.is_some(), "resolve(#75) must return Some for portaudio stub");
}

#[test]
fn resolve_portaudio_named_initialize() {
    let addr = weave_audacity::resolve("portaudio_x64.dll", "Pa_Initialize");
    assert!(addr.is_some(), "resolve(Pa_Initialize) must return Some");
}

#[test]
fn resolve_portaudio_named_get_host_api_info() {
    let addr = weave_audacity::resolve("portaudio_x64.dll", "Pa_GetHostApiInfo");
    assert!(addr.is_some(), "resolve(Pa_GetHostApiInfo) must return Some");
}

#[test]
fn resolve_unknown_returns_none() {
    let addr = weave_audacity::resolve("portaudio_x64.dll", "Pa_NonexistentFunction");
    assert!(addr.is_none(), "unknown func must return None");
}

#[test]
fn resolve_wrong_dll_returns_none() {
    let addr = weave_audacity::resolve("kernel32.dll", "#4");
    assert!(addr.is_none(), "wrong dll must return None");
}
