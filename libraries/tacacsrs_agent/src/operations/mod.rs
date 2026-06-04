//! Typed operation execution entry points.
//!
//! Accounting and authorization share the same routing and failover machinery,
//! but each operation has its own request/response types and upstream send
//! method. This module keeps those typed adapters together so adding another
//! TACACS+ operation has an obvious home.

mod accounting;
mod authorization;
mod routed;
