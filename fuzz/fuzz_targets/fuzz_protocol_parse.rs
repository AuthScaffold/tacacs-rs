#![no_main]

use libfuzzer_sys::fuzz_target;

use tacacsrs_protocol::accounting::{reply::AccountingReply, request::AccountingRequest};
use tacacsrs_protocol::authentication::{
    continue_packet::AuthenticationContinue, reply::AuthenticationReply, start::AuthenticationStart,
};
use tacacsrs_protocol::authorization::{reply::AuthorizationReply, request::AuthorizationRequest};
use tacacsrs_protocol::packet::Packet;

fuzz_target!(|data: &[u8]| {
    let _ = Packet::from_bytes(data);
    let _ = AccountingRequest::from_bytes(data);
    let _ = AccountingReply::from_bytes(data);
    let _ = AuthenticationStart::from_bytes(data);
    let _ = AuthenticationContinue::from_bytes(data);
    let _ = AuthenticationReply::from_bytes(data);
    let _ = AuthorizationRequest::from_bytes(data);
    let _ = AuthorizationReply::from_bytes(data);
});
