#![no_main]

use libfuzzer_sys::fuzz_target;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::traits::TacacsBodyTrait;

fuzz_target!(|data: &[u8]| {
    // AccountingRequest::from_bytes must never panic on arbitrary input.
    if let Ok(request) = AccountingRequest::from_bytes(data) {
        // Round-trip invariant: serialising and re-parsing must succeed and
        // produce bit-identical output.
        let serialised = request.to_bytes();
        let reparsed = AccountingRequest::from_bytes(&serialised)
            .expect("re-parse of serialised accounting request failed");
        assert_eq!(
            serialised,
            reparsed.to_bytes(),
            "accounting request round-trip produced different bytes"
        );
    }
});
