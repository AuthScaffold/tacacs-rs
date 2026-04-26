#![no_main]

use libfuzzer_sys::fuzz_target;
use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::traits::TacacsBodyTrait;

fuzz_target!(|data: &[u8]| {
    // AccountingReply::from_bytes must never panic on arbitrary input.
    if let Ok(reply) = AccountingReply::from_bytes(data) {
        // Round-trip invariant: serialising and re-parsing must succeed and
        // produce bit-identical output.
        let serialised = reply.to_bytes();
        let reparsed = AccountingReply::from_bytes(&serialised)
            .expect("re-parse of serialised accounting reply failed");
        assert_eq!(
            serialised,
            reparsed.to_bytes(),
            "accounting reply round-trip produced different bytes"
        );
    }
});
