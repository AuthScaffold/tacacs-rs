//! Session-to-flow I/O adapters.
//!
//! Concrete TACACS+ flow logic lives in external flow crates (for example
//! `tacacsrs-flows`). This module wires networking [`crate::session::Session`]
//! into shared flow I/O traits from `tacacsrs-flow-abstractions`.

mod accounting_session;
