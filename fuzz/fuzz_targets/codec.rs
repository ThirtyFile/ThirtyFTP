#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first byte chooses the line limit and where the input is cut in two, so that the reads end in the middle of lines and Telnet commands
    let Some((&first, rest)) = data.split_first() else { return };
    let cut = (first as usize * rest.len()) / 256;
    let (a, b) = rest.split_at(cut);
    thirtyftp::fuzzing::read_lines(&[a, b], 1 + (first as usize % 64));
});
