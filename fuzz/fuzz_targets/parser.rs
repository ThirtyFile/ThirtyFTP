#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A line as the codec gives it: UTF-8, lossily
    let line = String::from_utf8_lossy(data);
    thirtyftp::fuzzing::parse_command(&line);
});
