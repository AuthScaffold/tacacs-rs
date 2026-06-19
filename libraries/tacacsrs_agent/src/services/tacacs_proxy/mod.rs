//! Raw TACACS+ proxy service.
//!
//! The proxy accepts one downstream TACACS+ session per local connection,
//! rewrites only the TACACS+ session id, and forwards packet bodies unchanged
//! through the managed upstream session selected by [`crate::upstream::manager`].

mod listener;
mod service;
mod upstream_bridge;

pub(crate) use service::TacacsProxyService;
