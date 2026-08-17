#![no_main]

use libfuzzer_sys::fuzz_target;
use tacacsrs_messages::header::Header;

fuzz_target!(|data: &[u8]| {
    // Header::from_bytes must never panic on arbitrary input.
    if let Ok(header) = Header::from_bytes(data) {
        // Serializing and re-parsing must produce identical bytes.
        let serialised = header.to_bytes();
        let reparsed = Header::from_bytes(&serialised).expect("failed to re-parse the serialized header");
        assert_eq!(
            serialised,
            reparsed.to_bytes(),
            "header round-trip produced different bytes"
        );
    }
});
