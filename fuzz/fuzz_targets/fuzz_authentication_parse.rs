#![no_main]

use libfuzzer_sys::fuzz_target;

use tacacsrs_protocol::authentication::{
    continue_packet::AuthenticationContinue, reply::AuthenticationReply, start::AuthenticationStart,
};
use tacacsrs_protocol::body::TacacsBodyTrait;
use tacacsrs_protocol::packet::Packet;

fuzz_target!(|data: &[u8]| {
    // Body-level parsing: from_bytes must never panic, and any body that parses
    // must round-trip through to_bytes()/from_bytes() to identical bytes.
    if let Ok(start) = AuthenticationStart::from_bytes(data) {
        round_trip_start(&start);
    }
    if let Ok(reply) = AuthenticationReply::from_bytes(data) {
        round_trip_reply(&reply);
    }
    if let Ok(continuation) = AuthenticationContinue::from_bytes(data) {
        round_trip_continue(&continuation);
    }

    // Packet-level parsing: from_packet must never panic on an arbitrary packet,
    // and the decoded body must round-trip the same way.
    if let Ok(packet) = Packet::from_bytes(data) {
        if let Ok(start) = AuthenticationStart::from_packet(&packet) {
            round_trip_start(&start);
        }
        if let Ok(reply) = AuthenticationReply::from_packet(&packet) {
            round_trip_reply(&reply);
        }
        if let Ok(continuation) = AuthenticationContinue::from_packet(&packet) {
            round_trip_continue(&continuation);
        }
    }
});

fn round_trip_start(start: &AuthenticationStart) {
    let serialised = start
        .to_bytes()
        .expect("parsed authentication start must serialize");
    let reparsed = AuthenticationStart::from_bytes(&serialised)
        .expect("failed to re-parse the serialized authentication start");
    assert_eq!(
        serialised,
        reparsed
            .to_bytes()
            .expect("reparsed authentication start must serialize"),
        "authentication start round-trip produced different bytes"
    );
}

fn round_trip_reply(reply: &AuthenticationReply) {
    let serialised = reply
        .to_bytes()
        .expect("parsed authentication reply must serialize");
    let reparsed = AuthenticationReply::from_bytes(&serialised)
        .expect("failed to re-parse the serialized authentication reply");
    assert_eq!(
        serialised,
        reparsed
            .to_bytes()
            .expect("reparsed authentication reply must serialize"),
        "authentication reply round-trip produced different bytes"
    );
}

fn round_trip_continue(continuation: &AuthenticationContinue) {
    let serialised = continuation
        .to_bytes()
        .expect("parsed authentication continue must serialize");
    let reparsed = AuthenticationContinue::from_bytes(&serialised)
        .expect("failed to re-parse the serialized authentication continue");
    assert_eq!(
        serialised,
        reparsed
            .to_bytes()
            .expect("reparsed authentication continue must serialize"),
        "authentication continue round-trip produced different bytes"
    );
}
