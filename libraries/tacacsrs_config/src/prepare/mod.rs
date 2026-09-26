//! Derives runtime inputs from canonical YANG configuration.
//!
//! Credential planning expands no references and performs no provider I/O.
//! Materialization resolves a closed plan into staged generated values, then
//! validates the complete candidate set without changing the source snapshot.

mod formats;
mod materialization;
mod planning;

pub use materialization::{
    enumerate_materialized_servers, materialize_server, materialize_servers, MaterializationError,
    MaterializationErrorKind,
};
pub use planning::resolution_plan;
