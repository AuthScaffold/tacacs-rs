#![no_main]

use libfuzzer_sys::fuzz_target;
use tacacsrs_messages::accounting::reply::AccountingReply;

fuzz_target!(|data: &[u8]| {
    // AccountingReply::from_bytes must never panic on arbitrary input.
    let _ = AccountingReply::from_bytes(data);
});
