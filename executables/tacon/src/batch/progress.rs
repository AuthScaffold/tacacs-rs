//! Progress display utilities for batch execution
//!
//! This module handles the visual progress display during batch
//! and load test execution.

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

use super::types::{LoadTestResult, RequestResult};

/// Configuration for progress display
pub struct ProgressConfig {
    /// Total number of requests expected
    pub total_requests: usize,
    /// Update interval for the progress bar
    pub update_interval: Duration,
    /// Width of the progress bar in characters
    pub bar_width: usize,
}

impl Default for ProgressConfig {
    fn default() -> Self {
        Self {
            total_requests: 0,
            update_interval: Duration::from_millis(100),
            bar_width: 40,
        }
    }
}

/// Handles for tracking and stopping progress display
pub struct ProgressTracker {
    /// Counter for completed requests
    pub completed: Arc<AtomicUsize>,
    /// Flag indicating if execution has failed
    pub failed: Arc<AtomicBool>,
    /// Storage for the first failure message
    pub first_failure: Arc<tokio::sync::Mutex<Option<String>>>,
    /// Handle to the progress display task
    handle: Option<JoinHandle<()>>,
}

#[allow(dead_code)] // Methods provide a clean API for future use and testing
impl ProgressTracker {
    /// Creates a new progress tracker and spawns the progress display task
    pub fn new(config: ProgressConfig) -> Self {
        let completed = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicBool::new(false));
        let first_failure = Arc::new(tokio::sync::Mutex::new(None));

        let progress_completed = Arc::clone(&completed);
        let progress_failed = Arc::clone(&failed);
        let total_requests = config.total_requests;
        let bar_width = config.bar_width;
        let update_interval = config.update_interval;
        let start_time = Instant::now();

        let handle = tokio::spawn(async move {
            loop {
                let count = progress_completed.load(Ordering::Relaxed);
                let elapsed = start_time.elapsed();
                let elapsed_secs = elapsed.as_secs_f64();
                let throughput = if elapsed_secs > 0.0 {
                    count as f64 / elapsed_secs
                } else {
                    0.0
                };

                let progress = if total_requests > 0 {
                    count as f64 / total_requests as f64
                } else {
                    0.0
                };
                let filled = (progress * bar_width as f64) as usize;
                let empty = bar_width - filled;

                // Build the progress bar
                let bar: String = std::iter::repeat('█')
                    .take(filled)
                    .chain(std::iter::repeat('░').take(empty))
                    .collect();

                // Print progress line (using \r to overwrite)
                print!(
                    "\r  [{bar}] {count:>7}/{total_requests:<7} | {throughput:>8.1} req/s | {elapsed:>6.1}s ",
                    elapsed = elapsed_secs
                );
                let _ = std::io::stdout().flush();

                // Check if we should stop
                if count >= total_requests || progress_failed.load(Ordering::Relaxed) {
                    break;
                }

                tokio::time::sleep(update_interval).await;
            }
            println!(); // Final newline
        });

        Self {
            completed,
            failed,
            first_failure,
            handle: Some(handle),
        }
    }

    /// Creates a tracker without spawning a progress display task
    /// Useful for silent execution or testing
    pub fn silent() -> Self {
        Self {
            completed: Arc::new(AtomicUsize::new(0)),
            failed: Arc::new(AtomicBool::new(false)),
            first_failure: Arc::new(tokio::sync::Mutex::new(None)),
            handle: None,
        }
    }

    /// Records a successful request completion
    pub fn record_success(&self) {
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a failure and stores the error message (only the first failure is stored)
    pub async fn record_failure(&self, message: String) {
        if !self.failed.swap(true, Ordering::Relaxed) {
            let mut failure = self.first_failure.lock().await;
            *failure = Some(message);
        }
    }

    /// Returns true if a failure has been recorded
    pub fn has_failed(&self) -> bool {
        self.failed.load(Ordering::Relaxed)
    }

    /// Waits for the progress display task to complete
    pub async fn finish(mut self) -> Option<String> {
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
        self.first_failure.lock().await.clone()
    }

    /// Gets the count of completed requests
    pub fn completed_count(&self) -> usize {
        self.completed.load(Ordering::Relaxed)
    }
}

/// Prints a summary of load test results
pub fn print_load_test_summary(result: &LoadTestResult) {
    println!("\n=== Load Test Results ===");
    println!("Total requests planned: {}", result.total_requests);
    println!("Successful requests:    {}", result.successful_requests);
    println!("Failed requests:        {}", result.failed_requests);
    println!("Duration:               {:.2?}", result.duration);
    println!(
        "Throughput:             {:.2} requests/second",
        result.requests_per_second
    );

    if let Some(failure) = &result.first_failure {
        println!("\nFirst failure: {failure}");
    } else {
        println!("\nStatus: SUCCESS - All requests completed successfully");
    }
}

/// Prints a summary of batch execution results
pub fn print_results_summary(results: &[RequestResult]) {
    println!("\n=== Batch Execution Summary ===");

    let successful = results.iter().filter(|r| r.result.is_ok()).count();
    let failed = results.len() - successful;

    for result in results {
        let status = if result.result.is_ok() { "✓" } else { "✗" };
        let message = match &result.result {
            Ok(msg) | Err(msg) => msg.clone(),
        };
        println!(
            "  [{status}] Request {} ({}): {message}",
            result.index + 1,
            result.request_type
        );
    }

    println!("\nTotal: {successful} succeeded, {failed} failed");
}
