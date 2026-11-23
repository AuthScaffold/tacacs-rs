//! Operation-aware endpoint routing over prepared transport inputs.
//!
//! [`RoutedClient`] owns one catalog, operation cursors, circuit state, and
//! reconnect serialization. Clones retain that catalog across retries.
//! [`RoutedClient::with_endpoints`] builds a replacement without changing old
//! clients. Clone an [`Endpoint`] to preserve its cache identity; construct a
//! new endpoint when any prepared input or eligibility changes.
//!
//! Each endpoint has one cached connection. Every operation that routes to the
//! endpoint shares it. Circuits and active positions are kept per operation.
//!
//! Report a TACACS+ `ERROR` through [`BoundEndpoint::note_server_failure`] even after the
//! first reply. A failure opens the circuit for that endpoint and operation and
//! moves that operation to the next endpoint. The shared connection stays open
//! for the other operations. If the next endpoint already has a connection, the
//! moved operation uses it. [`crate::retry`] determines whether the current
//! request can use another endpoint.
//!
//! Use [`BoundEndpoint::connection`] for typed exchanges or raw conversations.
//! Report outcomes through the binding, not through a newly published catalog.
//! Arm [`BoundEndpoint::observe_failure`] only during upstream I/O, with the
//! deadline that bounds that I/O. Disarm it after a valid reply or local
//! validation failure. Call [`FailureObservation::fail`] after an upstream
//! I/O failure. An I/O failure invalidates the shared connection before the
//! next bind and schedules owned, bounded retirement. An I/O failure on a
//! connection that completed a valid exchange keeps the circuit closed, so the
//! next bind of each operation reconnects to the same endpoint. Report every valid reply through
//! [`BoundEndpoint::note_success`] so the client can tell these connections apart. Dropping an armed guard
//! records a failure only after its deadline expires, so caller cancellation
//! does not open a circuit. Do not keep it armed during downstream waits.
//! When every eligible endpoint has an open circuit, [`RoutedClient::bind`]
//! still tries those endpoints as a last resort. When no operation route prefers
//! an endpoint and no binding holds its connection, the client retires that
//! connection. For example, after every operation returns to a recovered
//! endpoint, the backup endpoint's connection closes.
//! Combine bindings with [`crate::retry`] for conservative, bounded retries.
//! [`RoutedClient::bind_excluding`] skips endpoints already tried for the
//! current request so each retry visits a distinct server. Separate requests
//! can revisit an endpoint through live selection, including a due recovery trial.
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

mod binding;
mod circuit;
mod catalog;
mod client;
mod connector;
mod lifecycle;
mod operation;

pub use catalog::Endpoint;
pub use binding::{BoundEndpoint, FailureObservation};
pub use client::RoutedClient;
pub use connector::{EndpointConnector, NativeConnector};
pub use operation::OperationKind;
