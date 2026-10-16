//! Executes a bounded retry plan without configuration, routing, or IPC dependencies.
//!
//! The caller selects endpoints and classifies each attempt. This module owns
//! replay decisions and releases discarded replies before the next attempt.
//! Unknown delivery outcomes are never replayed automatically.
//!
//! The executor starts no background tasks. Dropping its future stops further
//! attempts; runners must make their attempt resources safe to drop during cancellation.
//!
//! # Example
//!
//! ```
//! use async_trait::async_trait;
//! use tacacsrs_networking::retry::{
//!     Attempt, AttemptDisposition, FailoverAttempt, FailoverOutcome, FailoverPlan,
//!     run_with_failover,
//! };
//!
//! struct Request;
//!
//! #[async_trait]
//! impl FailoverAttempt for Request {
//!     type Value = u32;
//!     type Error = &'static str;
//!
//!     async fn attempt(&mut self, attempt_index: usize) -> Attempt<u32, &'static str> {
//!         if attempt_index == 0 {
//!             Attempt::Failed { error: "not sent", disposition: AttemptDisposition::NotSent }
//!         } else {
//!             Attempt::Accepted(42)
//!         }
//!     }
//! }
//!
//! # #[tokio::main]
//! # async fn main() {
//! let outcome = run_with_failover(FailoverPlan::new(2), &mut Request).await;
//! assert!(matches!(outcome, FailoverOutcome::Accepted(42)));
//! # }
//! ```

mod executor;
mod plan;

pub use executor::{Attempt, FailoverAttempt, FailoverOutcome, run_with_failover};
pub use plan::{AttemptDisposition, FailoverPlan};
