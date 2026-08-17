#![no_main]

use libfuzzer_sys::fuzz_target;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::packet::Packet;
use tacacsrs_messages::traits::TacacsBodyTrait;

fuzz_target!(|data: &[u8]| {
    // Exercise the full packet-level parsing path for the header and body.
    // Neither Packet::from_bytes nor AccountingRequest::from_packet must panic
    // on arbitrary input.
    let Ok(packet) = Packet::from_bytes(data) else {
        return;
    };

    if let Ok(request) = AccountingRequest::from_packet(&packet) {
        // Serializing and re-parsing must succeed and produce identical bytes.
        let serialised = request.to_bytes();
        let reparsed = AccountingRequest::from_bytes(&serialised)
            .expect("failed to re-parse the serialized accounting request");
        assert_eq!(
            serialised,
            reparsed.to_bytes(),
            "packet-level accounting request round-trip produced different bytes"
        );
    }
});
