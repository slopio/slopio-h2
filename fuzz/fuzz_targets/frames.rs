#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| slopio_h2::fuzz::frames(data));
