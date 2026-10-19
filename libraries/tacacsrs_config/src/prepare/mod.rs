//! Derives native runtime endpoints from canonical YANG configuration.
//!
//! This module is the final stage of the configuration flow:
//!
//! ```text
//! canonical  ->  enumerate  ->  resolve  ->  materialize  ->  prepare
//! ```
//!
//! [`resolution_plan`] expands no references and performs no provider I/O.
//! Materialization resolves a closed plan into staged generated values, then
//! validates the complete candidate set without changing the source snapshot.
//! [`prepare_endpoint`] projects a materialized server into a native networking
//! endpoint.

mod formats;
mod endpoint;
mod materialization;
mod planning;
mod readiness;
mod payload;

pub use payload::{
    ConfigurationMaterialBudget, enumerated_payload_bytes, server_payload_bytes,
    source_payload_bytes,
};

pub use materialization::{
    enumerate_materialized_servers, materialize_server, materialize_servers,
    materialize_planned_servers, MaterializationError, MaterializationErrorKind,
    MaterializedServer,
};
pub use planning::{resolution_plan, ServerResolutionPlan};
pub use endpoint::{prepare_endpoint, PrepareOptions};
pub use readiness::validate_materialized_servers;
