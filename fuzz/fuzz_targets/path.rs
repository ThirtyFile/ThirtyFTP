#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (current, requested) = text.split_once('\0').unwrap_or(("", &text));
    if let Some(path) = thirtyftp::fuzzing::resolve_path(current, requested) {
        // A resolved path is absolute and resolves to itself
        assert!(path.starts_with('/'));
        assert!(!path.split('/').any(|part| part == ".." || part == "."));
        assert_eq!(thirtyftp::fuzzing::resolve_path("/", &path), Some(path.clone()));
    }
});
