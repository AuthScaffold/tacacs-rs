#![no_main]

use libfuzzer_sys::fuzz_target;
use tacacsrs_messages::header::Header;

fuzz_target!(|data: &[u8]| {
    // Header::from_bytes must never panic on arbitrary input.
    let _ = Header::from_bytes(data);
});
