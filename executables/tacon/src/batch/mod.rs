//! Batch mode processing for TACACS+ requests
//!
//! This module reads and runs multiple TACACS+ requests from a JSON batch file.
//! It supports parallel runs and load tests.
//!
//! # Module Structure
//!
//! - [`types`]: Data structures for batch files, requests, and results
//! - [`executor`]: Run strategies (sequential, parallel, load test)
//! - [`progress`]: Progress display and result summaries

mod executor;
mod progress;
mod types;

use anyhow::Context;
use std::path::Path;

// Re-export public types
// RequestResult is part of the public API (returned by execute_batch)
#[allow(unused_imports)]
pub use types::{BatchFile, RequestResult};

// Re-export the run functions.
pub use executor::execute_batch;
#[cfg(target_os = "linux")]
pub use executor::execute_batch_via_service;

// Re-export display functions
pub use progress::print_results_summary;

/// Loads and parses a batch file from disk
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed as valid JSON.
pub fn load_batch_file(path: &Path) -> anyhow::Result<BatchFile> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read batch file: {}", path.display()))?;

    serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse batch file as JSON: {}", path.display()))
}
