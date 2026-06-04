//! TACACS+ single-connection capability negotiation.

mod state;
mod tracker;

pub(crate) use state::SingleConnectionState;
pub(crate) use tracker::{LocalSingleConnectState, SingleConnectFlag};
