//! Operation-aware endpoint routing over prepared transport inputs.
//!
//! [`RoutedClient`] owns one catalog, operation cursors, circuit state, and
//! reconnect serialization. Clones retain that catalog across retries.
//! [`RoutedClient::with_endpoints`] builds a replacement without changing old
//! clients. Clone an [`Endpoint`] to preserve its cache identity; construct a
//! new endpoint when any prepared input or eligibility changes.
//!
//! Use [`BoundEndpoint::connection`] for typed exchanges or raw conversations.
//! Report outcomes through the binding, not through a newly published catalog.
//! Combine bindings with [`crate::retry`] for conservative, bounded retries.
//! Call [`RoutedClient::retire_replaced`] after publishing a replacement.
//! This API does not yet impose an absolute deadline or expose close/join.
//!
//! Run the agent-free loopback example with:
//! `cargo run -p tacacsrs-networking --example routed_accounting`.

mod circuit;
mod catalog;
mod client;
mod connector;
mod operation;

pub use catalog::Endpoint;
pub use client::{BoundEndpoint, RoutedClient};
pub use connector::{EndpointConnector, NativeConnector};
pub use operation::OperationKind;
