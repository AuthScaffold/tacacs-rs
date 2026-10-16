#![no_main]

use libfuzzer_sys::fuzz_target;
use tacacsrs_protocol::accounting::request::AccountingRequest;
use tacacsrs_protocol::traits::TacacsBodyTrait;

fuzz_target!(|data: &[u8]| {
    // AccountingRequest::from_bytes must never panic on arbitrary input.
    if let Ok(request) = AccountingRequest::from_bytes(data) {
        // Serializing and re-parsing must succeed and produce identical bytes.
        let serialised = request
            .to_bytes()
            .expect("parsed accounting request must serialize");
        let reparsed = AccountingRequest::from_bytes(&serialised)
            .expect("failed to re-parse the serialized accounting request");
        assert_eq!(
            serialised,
            reparsed
                .to_bytes()
                .expect("reparsed accounting request must serialize"),
            "accounting request round-trip produced different bytes"
        );
    }
});
