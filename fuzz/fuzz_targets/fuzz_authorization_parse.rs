#![no_main]

use libfuzzer_sys::fuzz_target;

use tacacsrs_protocol::authorization::{reply::AuthorizationReply, request::AuthorizationRequest};
use tacacsrs_protocol::body::TacacsBodyTrait;
use tacacsrs_protocol::packet::Packet;

fuzz_target!(|data: &[u8]| {
    // Body-level parsing: from_bytes must never panic, and any body that parses
    // must round-trip through to_bytes()/from_bytes() to identical bytes.
    if let Ok(request) = AuthorizationRequest::from_bytes(data) {
        round_trip_request(&request);
    }
    if let Ok(reply) = AuthorizationReply::from_bytes(data) {
        round_trip_reply(&reply);
    }

    // Packet-level parsing: only AuthorizationRequest exposes from_packet, which
    // matches the protocol crate's own surface. AuthorizationReply is parsed
    // from the body only.
    if let Ok(packet) = Packet::from_bytes(data) {
        if let Ok(request) = AuthorizationRequest::from_packet(&packet) {
            round_trip_request(&request);
        }
    }
});

fn round_trip_request(request: &AuthorizationRequest) {
    let serialised = request
        .to_bytes()
        .expect("parsed authorization request must serialize");
    let reparsed = AuthorizationRequest::from_bytes(&serialised)
        .expect("failed to re-parse the serialized authorization request");
    assert_eq!(
        serialised,
        reparsed
            .to_bytes()
            .expect("reparsed authorization request must serialize"),
        "authorization request round-trip produced different bytes"
    );
}

fn round_trip_reply(reply: &AuthorizationReply) {
    let serialised = reply
        .to_bytes()
        .expect("parsed authorization reply must serialize");
    let reparsed = AuthorizationReply::from_bytes(&serialised)
        .expect("failed to re-parse the serialized authorization reply");
    assert_eq!(
        serialised,
        reparsed
            .to_bytes()
            .expect("reparsed authorization reply must serialize"),
        "authorization reply round-trip produced different bytes"
    );
}
