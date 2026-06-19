//! Shared fake types and helpers for agent runtime tests.
//!
//! Test fixtures are grouped by purpose so production modules can import only
//! the behavior they need: reusable fake upstreams and domain request builders.

mod fake_upstream;
mod requests;

pub(crate) use fake_upstream::{FakeConnection, FakeConnector};
pub(crate) use requests::build_authorization_request;
#[cfg(unix)]
pub(crate) use requests::build_request;
