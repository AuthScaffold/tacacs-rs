//! Session-facing flow traits.
//!
//! Concrete TACACS+ flow logic lives in `tacacsrs-flows`; this module wires
//! networking [`crate::session::Session`] into those flow I/O traits.

pub mod accounting_session;
