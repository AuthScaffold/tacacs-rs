//! Shared fake types and helpers for agent runtime tests.
//!
//! The fixtures are grouped by purpose. Production modules can import only the
//! required fake servers and domain request builders.

mod fake_upstream;
mod requests;

pub(crate) use fake_upstream::{FakeConnection, FakeConnector};
pub(crate) use requests::build_authorization_request;
#[cfg(unix)]
pub(crate) use requests::build_request;
