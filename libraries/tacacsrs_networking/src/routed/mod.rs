//! Operation-aware endpoint routing over prepared transport inputs.
//!
//! [`RoutedClient`] owns one catalog, operation cursors, circuit state, and
//! reconnect serialization. Clones retain that catalog across retries.
//! [`RoutedClient::with_endpoints`] builds a replacement without changing old
//! clients. Clone an [`Endpoint`] to preserve its cache identity; construct a
//! new endpoint when any prepared input or eligibility changes.
//!
//! Report a TACACS+ `ERROR` through [`BoundEndpoint::note_failure`] even after the
//! first reply. A failure opens the circuit for that endpoint and operation and
//! retires its cached connection. Other operations keep their routes and connections.
//! [`crate::retry`] determines whether the current request can use another endpoint.
//!
//! Use [`BoundEndpoint::connection`] for typed exchanges or raw conversations.
//! Report outcomes through the binding, not through a newly published catalog.
//! Arm [`BoundEndpoint::observe_failure`] only during upstream I/O, with the
//! deadline that bounds that I/O. Disarm it after a valid reply or local
//! validation failure. Call [`FailureObservation::fail`] after an upstream
//! failure. A recorded failure invalidates the captured connection before the
//! next bind and schedules owned, bounded retirement. Dropping an armed guard
//! records a failure only after its deadline expires, so caller cancellation
//! does not open a circuit. Do not keep it armed during downstream waits.
//! When every eligible endpoint has an open circuit, [`RoutedClient::bind`]
//! still tries those endpoints as a last resort.
//! Combine bindings with [`crate::retry`] for conservative, bounded retries.
//! Schedule [`RoutedClient::retire_replaced_until`] when publishing a replacement.
//! Removed endpoints remain usable by captured catalogs until that cutoff.
//! Use [`RoutedClient::retire_replaced_with_deadlines`] to select cutoffs per endpoint,
//! including already-retiring historical generations. Unpublished candidates are excluded.
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
