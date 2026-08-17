//! Raw TACACS+ proxy service.
//!
//! The proxy accepts downstream TACACS+ sessions on each local connection. It
//! changes only the TACACS+ session ID and forwards packet bodies without
//! changes. [`crate::upstream::manager`] selects the managed server session.

mod listener;
mod service;
mod upstream_bridge;

pub(crate) use service::TacacsProxyService;
