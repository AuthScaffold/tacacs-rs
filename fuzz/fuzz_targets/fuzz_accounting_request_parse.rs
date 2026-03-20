#![no_main]

use libfuzzer_sys::fuzz_target;
use tacacsrs_messages::accounting::request::AccountingRequest;

fuzz_target!(|data: &[u8]| {
    // AccountingRequest::from_bytes must never panic on arbitrary input.
    let _ = AccountingRequest::from_bytes(data);
});
