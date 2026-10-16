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
//! Arm [`BoundEndpoint::observe_failure`] only during upstream I/O. Disarm it
//! after a valid reply or local validation failure. Dropping an armed guard
//! invalidates the captured connection before the next bind and schedules owned,
//! bounded retirement. Do not keep it armed during downstream waits.
//! Combine bindings with [`crate::retry`] for conservative, bounded retries.
//! Schedule [`RoutedClient::retire_replaced_until`] when publishing a replacement.
//! Removed endpoints remain usable by captured catalogs until that cutoff.
//! [`RoutedClient::close_and_join`] closes the whole related catalog family,
//! including historical endpoints and owned setup tasks, under one deadline.
//! Custom connectors must honor their close/join contract. Request deadlines
//! remain caller-supplied through [`crate::RequestDeadline`].
//!
//! Run the agent-free loopback example with:
//! `cargo run -p tacacsrs-networking --example routed_accounting`.

mod circuit;
mod catalog;
mod client;
mod connector;
mod lifecycle;
mod operation;

pub use catalog::Endpoint;
pub use client::{BoundEndpoint, FailureObservation, RoutedClient};
pub use connector::{EndpointConnector, NativeConnector};
pub use operation::OperationKind;
