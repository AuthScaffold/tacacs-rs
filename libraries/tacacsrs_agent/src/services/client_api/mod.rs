//! Local client API operations over managed upstream connections.
//!
//! The upstream bridge converts local client API requests into TACACS+ messages
//! and sends them through the shared upstream manager. Only TACACS+ messages
//! cross the server boundary. [`ClientApiHandle`] is the public entry point. A
//! host adapts it to an IPC server; the agent runtime does not own the IPC
//! transport or the protobuf schema.

mod handle;
mod upstream_bridge;

pub use handle::ClientApiHandle;
pub(crate) use upstream_bridge::UpstreamBridge;
