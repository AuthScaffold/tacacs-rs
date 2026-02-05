//! Batch mode processing for TACACS+ requests
//!
//! This module handles reading and executing multiple TACACS+ requests
//! from a JSON batch file, with support for parallel execution and load testing.

use anyhow::Context;
use futures::future::join_all;
use futures::stream::{self, StreamExt};
use serde::Deserialize;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_networking::session::Session;
use tacacsrs_networking::SingleConnectionState;

use crate::cli::Cli;
use crate::commands::accounting::send_accounting_request;
use crate::connection::{establish_connection, Connection};

/// Custom flags that can be set on TACACS+ packet headers
#[derive(Debug, Deserialize, Default, Clone, Copy)]
pub struct CustomFlags {
    /// Set TAC_PLUS_CUSTOM_FLAG_1 (0x40) on the packet header
    #[serde(default)]
    pub custom_flag_1: bool,

    /// Set TAC_PLUS_CUSTOM_FLAG_2 (0x80) on the packet header
    #[serde(default)]
    pub custom_flag_2: bool,
}

impl CustomFlags {
    /// Converts the custom flags to TacacsFlags
    pub fn to_tacacs_flags(self) -> TacacsFlags {
        let mut flags = TacacsFlags::empty();
        if self.custom_flag_1 {
            flags |= TacacsFlags::TAC_PLUS_CUSTOM_FLAG_1;
        }
        if self.custom_flag_2 {
            flags |= TacacsFlags::TAC_PLUS_CUSTOM_FLAG_2;
        }
        flags
    }
}

/// Batch file structure containing metadata and requests
#[derive(Debug, Deserialize)]
pub struct BatchFile {
    /// Metadata controlling batch execution behavior
    #[serde(default)]
    pub metadata: BatchMetadata,

    /// List of requests to execute
    pub requests: Vec<BatchRequest>,
}

/// Metadata controlling how the batch is executed
#[derive(Debug, Deserialize, Default)]
pub struct BatchMetadata {
    /// If true, all requests are sent in parallel; otherwise sequential
    #[serde(default)]
    pub parallel: bool,

    /// Optional description of this batch
    #[serde(default)]
    pub description: Option<String>,

    /// Optional load testing configuration
    #[serde(default)]
    pub load_test: Option<LoadTestConfig>,
}

/// Configuration for load testing mode
#[derive(Debug, Deserialize, Clone)]
pub struct LoadTestConfig {
    /// Number of times to repeat all requests
    pub repetitions: usize,

    /// Maximum number of parallel requests at any time
    #[serde(default = "default_max_parallel")]
    pub max_parallel: usize,
}

fn default_max_parallel() -> usize {
    10
}

/// A single request in the batch file
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BatchRequest {
    /// Accounting request
    Accounting(AccountingRequest),

    /// Authentication request
    Authentication(AuthenticationRequest),

    /// Authorization request
    Authorization(AuthorizationRequest),
}

/// Arguments for an accounting request
#[derive(Debug, Deserialize)]
pub struct AccountingRequest {
    /// Username executing the command
    pub user: String,

    /// Port identifier (e.g., "tty0")
    pub port: String,

    /// Remote address of the client
    pub rem_addr: String,

    /// Command being executed
    pub cmd: String,

    /// Optional command arguments
    #[serde(default)]
    pub cmd_args: Vec<String>,

    /// Optional custom flags to set on the packet header
    #[serde(default)]
    pub custom_flags: CustomFlags,

    /// Optional custom session ID (if not provided, a random one is generated)
    #[serde(default)]
    pub session_id: Option<u32>,
}

/// Arguments for an authentication request
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields will be used when authentication is implemented
pub struct AuthenticationRequest {
    /// Username to authenticate
    pub user: String,

    /// Port identifier
    pub port: String,

    /// Remote address of the client
    pub rem_addr: String,

    /// Password (for PAP) or other credentials
    #[serde(default)]
    pub password: Option<String>,

    /// Optional custom flags to set on the packet header
    #[serde(default)]
    pub custom_flags: CustomFlags,

    /// Optional custom session ID (if not provided, a random one is generated)
    #[serde(default)]
    pub session_id: Option<u32>,
}

/// Arguments for an authorization request
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields will be used when authorization is implemented
pub struct AuthorizationRequest {
    /// Username requesting authorization
    pub user: String,

    /// Port identifier
    pub port: String,

    /// Remote address of the client
    pub rem_addr: String,

    /// Command to authorize
    #[serde(default)]
    pub cmd: Option<String>,

    /// Command arguments to authorize
    #[serde(default)]
    pub cmd_args: Vec<String>,

    /// Service type (e.g., "shell")
    #[serde(default = "default_service")]
    pub service: String,

    /// Optional custom flags to set on the packet header
    #[serde(default)]
    pub custom_flags: CustomFlags,

    /// Optional custom session ID (if not provided, a random one is generated)
    #[serde(default)]
    pub session_id: Option<u32>,
}

fn default_service() -> String {
    "shell".to_owned()
}

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

/// Result of executing a single batch request
#[derive(Debug)]
pub struct RequestResult {
    /// Index of the request in the batch
    pub index: usize,

    /// Type of request that was executed
    pub request_type: &'static str,

    /// Result of the request (Ok or error message)
    pub result: Result<String, String>,
}

/// Result of executing a load test
#[derive(Debug)]
pub struct LoadTestResult {
    /// Total number of requests executed
    pub total_requests: usize,

    /// Number of successful requests
    pub successful_requests: usize,

    /// Number of failed requests (will be 0 or 1 since we stop on first failure)
    pub failed_requests: usize,

    /// Total duration of the load test
    pub duration: Duration,

    /// First failure encountered, if any
    pub first_failure: Option<String>,

    /// Requests per second throughput
    pub requests_per_second: f64,
}

impl LoadTestResult {
    /// Returns true if the load test completed without failures
    pub fn is_success(&self) -> bool {
        self.first_failure.is_none()
    }
}

/// Executes all requests in a batch file
///
/// This function handles servers that may or may not support single connection mode.
/// The first request is always sent to determine the server's capabilities. If the
/// server doesn't support single connection mode (TAC_PLUS_SINGLE_CONNECT_FLAG not set),
/// subsequent requests will each use a new connection.
///
/// If load testing mode is enabled, this function delegates to `execute_load_test`.
///
/// # Arguments
///
/// * `cli` - The CLI configuration (used to establish new connections if needed)
/// * `connection` - The initial TACACS+ connection
/// * `batch` - The parsed batch file
///
/// # Returns
///
/// A vector of results, one for each request in the batch.
///
/// # Errors
///
/// Returns an error if session creation fails. Individual request failures
/// are captured in the results vector.
pub async fn execute_batch(
    cli: &Cli,
    connection: Connection,
    batch: &BatchFile,
) -> anyhow::Result<Vec<RequestResult>> {
    if let Some(desc) = &batch.metadata.description {
        log::info!("Executing batch: {desc}");
        println!("Batch: {desc}");
    }

    // Check if load testing mode is enabled
    if let Some(load_config) = &batch.metadata.load_test {
        log::info!(
            "Load testing mode enabled: {} repetitions, max {} parallel",
            load_config.repetitions,
            load_config.max_parallel
        );
        println!(
            "\n=== Load Testing Mode ===\nRepetitions: {}\nMax parallel: {}\nTotal requests: {}",
            load_config.repetitions,
            load_config.max_parallel,
            load_config.repetitions * batch.requests.len()
        );

        let result = execute_load_test(cli, connection, &batch.requests, load_config).await?;
        print_load_test_summary(&result);

        // Return empty results since load test has its own summary
        // The caller can check the printed output for details
        if result.is_success() {
            return Ok(vec![]);
        } else {
            anyhow::bail!("Load test failed: {}", result.first_failure.unwrap_or_default());
        }
    }

    let request_count = batch.requests.len();
    log::info!(
        "Processing {request_count} requests (parallel: {})",
        batch.metadata.parallel
    );

    if batch.metadata.parallel {
        execute_parallel(cli, connection, &batch.requests).await
    } else {
        execute_sequential(cli, connection, &batch.requests).await
    }
}

/// Executes a load test by repeating all requests with controlled concurrency
///
/// This function runs all requests multiple times (based on `config.repetitions`)
/// with a maximum of `config.max_parallel` concurrent requests. The test stops
/// immediately on the first failure.
///
/// # Arguments
///
/// * `cli` - The CLI configuration (used to establish new connections)
/// * `connection` - The initial TACACS+ connection (used to probe single-connection support)
/// * `requests` - The requests to repeat
/// * `config` - Load test configuration
///
/// # Returns
///
/// A `LoadTestResult` containing throughput statistics and failure information.
async fn execute_load_test(
    cli: &Cli,
    connection: Connection,
    requests: &[BatchRequest],
    config: &LoadTestConfig,
) -> anyhow::Result<LoadTestResult> {
    let total_requests = requests.len() * config.repetitions;
    let start_time = Instant::now();

    // Atomic flags/counters for tracking progress and stopping on failure
    let failed = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicUsize::new(0));
    let first_failure: Arc<tokio::sync::Mutex<Option<String>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    // First, probe the server to check single-connection support
    log::info!("Probing server for single-connection support...");
    let probe_session = connection
        .create_session_optional_id(None)
        .await
        .context("Failed to create probe session")?;

    // Send a probe request (use first request if available)
    if let Some(first_request) = requests.first() {
        let _ = execute_single_request(&probe_session, first_request).await;
    }

    let single_connection_supported = matches!(
        connection.single_connection_state().await,
        SingleConnectionState::Supported
    );

    if single_connection_supported {
        log::info!("Server supports single connection mode - reusing connections where possible");
    } else {
        log::info!("Server does not support single connection mode - using separate connections");
    }

    // Build a lazy iterator over all request iterations: (repetition_index, request_index, request)
    // We avoid collecting into a Vec to prevent memory issues with large repetition counts
    let all_iterations = (0..config.repetitions).flat_map(|rep| {
        requests
            .iter()
            .enumerate()
            .map(move |(idx, req)| (rep, idx, req))
    });

    println!("Starting load test with {} total requests...\n", total_requests);

    // Use buffered stream to control concurrency
    let cli = cli.clone();
    let failed_clone = Arc::clone(&failed);
    let completed_clone = Arc::clone(&completed);
    let first_failure_clone = Arc::clone(&first_failure);

    // Spawn a background task to print live progress
    let progress_completed = Arc::clone(&completed);
    let progress_failed = Arc::clone(&failed);
    let progress_start = start_time;
    let progress_handle = tokio::spawn(async move {
        let bar_width = 40;
        loop {
            let count = progress_completed.load(Ordering::Relaxed);
            let elapsed = progress_start.elapsed();
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
            use std::io::Write;
            let _ = std::io::stdout().flush();

            // Check if we should stop
            if count >= total_requests || progress_failed.load(Ordering::Relaxed) {
                break;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        println!(); // Final newline
    });

    let results: Vec<bool> = stream::iter(all_iterations)
        .map(|(rep, idx, request)| {
            let cli = cli.clone();
            let failed = Arc::clone(&failed_clone);
            let completed = Arc::clone(&completed_clone);
            let first_failure = Arc::clone(&first_failure_clone);

            async move {
                // Check if we should stop due to a previous failure
                if failed.load(Ordering::Relaxed) {
                    return false;
                }

                // Establish a new connection for this request
                let conn = match establish_connection(&cli).await {
                    Ok(c) => c,
                    Err(e) => {
                        if !failed.swap(true, Ordering::Relaxed) {
                            let mut failure = first_failure.lock().await;
                            *failure = Some(format!(
                                "Connection failed at rep {}, request {}: {}",
                                rep + 1,
                                idx + 1,
                                e
                            ));
                        }
                        return false;
                    }
                };

                let session = match conn.create_session_optional_id(request.session_id()).await {
                    Ok(s) => s,
                    Err(e) => {
                        if !failed.swap(true, Ordering::Relaxed) {
                            let mut failure = first_failure.lock().await;
                            *failure = Some(format!(
                                "Session creation failed at rep {}, request {}: {}",
                                rep + 1,
                                idx + 1,
                                e
                            ));
                        }
                        return false;
                    }
                };

                let result = execute_single_request(&session, request).await;

                match result {
                    Ok(_) => {
                        completed.fetch_add(1, Ordering::Relaxed);
                        true
                    }
                    Err(e) => {
                        if !failed.swap(true, Ordering::Relaxed) {
                            let mut failure = first_failure.lock().await;
                            *failure = Some(format!(
                                "Request failed at rep {}, request {} ({}): {}",
                                rep + 1,
                                idx + 1,
                                request.type_name(),
                                e
                            ));
                        }
                        false
                    }
                }
            }
        })
        .buffer_unordered(config.max_parallel)
        .collect()
        .await;

    // Wait for progress display to finish
    let _ = progress_handle.await;

    let duration = start_time.elapsed();
    let successful_requests = results.iter().filter(|&&r| r).count();
    let failed_requests = if failed.load(Ordering::Relaxed) { 1 } else { 0 };
    let requests_per_second = if duration.as_secs_f64() > 0.0 {
        successful_requests as f64 / duration.as_secs_f64()
    } else {
        0.0
    };

    let failure_msg = first_failure.lock().await.clone();

    Ok(LoadTestResult {
        total_requests,
        successful_requests,
        failed_requests,
        duration,
        first_failure: failure_msg,
        requests_per_second,
    })
}

/// Prints a summary of load test results
fn print_load_test_summary(result: &LoadTestResult) {
    println!("\n=== Load Test Results ===");
    println!("Total requests planned: {}", result.total_requests);
    println!("Successful requests:    {}", result.successful_requests);
    println!("Failed requests:        {}", result.failed_requests);
    println!("Duration:               {:.2?}", result.duration);
    println!("Throughput:             {:.2} requests/second", result.requests_per_second);

    if let Some(failure) = &result.first_failure {
        println!("\nFirst failure: {failure}");
    } else {
        println!("\nStatus: SUCCESS - All requests completed successfully");
    }
}

/// Executes requests sequentially, one at a time
/// 
/// If the server doesn't support single connection mode, a new connection
/// is established for each subsequent request.
async fn execute_sequential(
    cli: &Cli,
    mut connection: Connection,
    requests: &[BatchRequest],
) -> anyhow::Result<Vec<RequestResult>> {
    let mut results = Vec::with_capacity(requests.len());

    for (index, request) in requests.iter().enumerate() {
        log::info!("Executing request {}/{}", index + 1, requests.len());

        // Check if we need a new connection (after first request, if single connection not supported)
        if index > 0 {
            match connection.single_connection_state().await {
                SingleConnectionState::NotSupported => {
                    log::info!("Server does not support single connection mode. Establishing new connection for request {}", index + 1);
                    connection = establish_connection(cli).await
                        .context("Failed to establish new connection for batch request")?;
                }
                SingleConnectionState::Supported => {
                    log::debug!("Reusing connection for request {} (single connection mode supported)", index + 1);
                }
                SingleConnectionState::Initial | SingleConnectionState::Negotiating => {
                    // This shouldn't happen in sequential mode after the first request
                    log::warn!("Unexpected connection state after first request: {:?}", 
                        connection.single_connection_state().await);
                }
            }
        }

        let custom_session_id = request.session_id();
        let session = connection
            .create_session_optional_id(custom_session_id)
            .await
            .context("Failed to create session for batch request")?;

        if let Some(sid) = custom_session_id {
            log::info!("Using custom session ID: {sid}");
        }

        let result = execute_single_request(&session, request).await;
        results.push(RequestResult {
            index,
            request_type: request.type_name(),
            result,
        });
    }

    Ok(results)
}

/// Executes all requests in parallel
/// 
/// First sends a single request to determine if the server supports single connection mode.
/// If supported, remaining requests are executed in parallel on the same connection.
/// If not supported, remaining requests are each executed on separate connections.
async fn execute_parallel(
    cli: &Cli,
    connection: Connection,
    requests: &[BatchRequest],
) -> anyhow::Result<Vec<RequestResult>> {
    if requests.is_empty() {
        return Ok(vec![]);
    }

    // Execute the first request to determine single connection mode support
    let first_request = &requests[0];
    log::info!("Executing first request to determine single connection mode support");
    
    let first_session = connection
        .create_session_optional_id(first_request.session_id())
        .await
        .context("Failed to create session for first batch request")?;

    let first_result = execute_single_request(&first_session, first_request).await;
    let mut results = vec![RequestResult {
        index: 0,
        request_type: first_request.type_name(),
        result: first_result,
    }];

    // If only one request, we're done
    if requests.len() == 1 {
        return Ok(results);
    }

    let remaining_requests = &requests[1..];

    // Check if single connection mode is supported
    let single_connection_supported = matches!(
        connection.single_connection_state().await,
        SingleConnectionState::Supported
    );

    if single_connection_supported {
        log::info!("Server supports single connection mode. Executing {} remaining requests in parallel on same connection", remaining_requests.len());
        
        // Create all sessions upfront on the same connection
        let mut session_futures = Vec::with_capacity(remaining_requests.len());
        for request in remaining_requests {
            session_futures.push(connection.create_session_optional_id(request.session_id()));
        }

        let sessions: Vec<Session> = join_all(session_futures)
            .await
            .into_iter()
            .enumerate()
            .map(|(i, r)| r.with_context(|| format!("Failed to create session for request {}", i + 2)))
            .collect::<anyhow::Result<Vec<_>>>()?;

        // Execute all requests in parallel
        let futures: Vec<_> = remaining_requests
            .iter()
            .zip(sessions.iter())
            .enumerate()
            .map(|(i, (request, session))| {
                let index = i + 1; // Offset by 1 since we already did index 0
                async move {
                    log::info!("Starting parallel request {}", index + 1);
                    let result = execute_single_request(session, request).await;
                    RequestResult {
                        index,
                        request_type: request.type_name(),
                        result,
                    }
                }
            })
            .collect();

        results.extend(join_all(futures).await);
    } else {
        log::info!("Server does not support single connection mode. Executing {} remaining requests with separate connections", remaining_requests.len());
        
        // Execute remaining requests in parallel, each with its own connection
        let futures: Vec<_> = remaining_requests
            .iter()
            .enumerate()
            .map(|(i, request)| {
                let index = i + 1; // Offset by 1 since we already did index 0
                let cli = cli.clone();
                async move {
                    log::info!("Establishing new connection for request {}", index + 1);
                    
                    let conn = match establish_connection(&cli).await {
                        Ok(c) => c,
                        Err(e) => {
                            return RequestResult {
                                index,
                                request_type: request.type_name(),
                                result: Err(format!("Failed to establish connection: {e}")),
                            };
                        }
                    };

                    let session = match conn.create_session_optional_id(request.session_id()).await {
                        Ok(s) => s,
                        Err(e) => {
                            return RequestResult {
                                index,
                                request_type: request.type_name(),
                                result: Err(format!("Failed to create session: {e}")),
                            };
                        }
                    };

                    let result = execute_single_request(&session, request).await;
                    RequestResult {
                        index,
                        request_type: request.type_name(),
                        result,
                    }
                }
            })
            .collect();

        results.extend(join_all(futures).await);
    }

    // Sort results by index to maintain order
    results.sort_by_key(|r| r.index);
    
    Ok(results)
}

/// Executes a single batch request
async fn execute_single_request(session: &Session, request: &BatchRequest) -> Result<String, String> {
    match request {
        BatchRequest::Accounting(req) => {
            let cmd_args = if req.cmd_args.is_empty() {
                None
            } else {
                Some(&req.cmd_args)
            };

            let custom_flags = req.custom_flags.to_tacacs_flags();

            match send_accounting_request(
                session,
                &req.user,
                &req.port,
                &req.rem_addr,
                &req.cmd,
                cmd_args,
                custom_flags,
            )
            .await
            {
                Ok(response) => Ok(format!("Accounting success: {response:?}")),
                Err(e) => Err(format!("Accounting failed: {e}")),
            }
        }

        BatchRequest::Authentication(req) => {
            // TODO: Implement authentication
            log::warn!(
                "Authentication not yet implemented for user: {}",
                req.user
            );
            Err(format!(
                "Authentication not yet implemented (user: {})",
                req.user
            ))
        }

        BatchRequest::Authorization(req) => {
            // TODO: Implement authorization
            log::warn!("Authorization not yet implemented for user: {}", req.user);
            Err(format!(
                "Authorization not yet implemented (user: {})",
                req.user
            ))
        }
    }
}

impl BatchRequest {
    /// Returns the type name of this request
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Accounting(_) => "accounting",
            Self::Authentication(_) => "authentication",
            Self::Authorization(_) => "authorization",
        }
    }

    /// Returns the optional custom session ID for this request
    pub fn session_id(&self) -> Option<u32> {
        match self {
            Self::Accounting(req) => req.session_id,
            Self::Authentication(req) => req.session_id,
            Self::Authorization(req) => req.session_id,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_batch_file_accounting() {
        let json = r#"{
            "metadata": {
                "parallel": false,
                "description": "Test batch"
            },
            "requests": [
                {
                    "type": "accounting",
                    "user": "admin",
                    "port": "tty0",
                    "rem_addr": "192.168.1.100",
                    "cmd": "show version"
                }
            ]
        }"#;

        let batch: BatchFile = serde_json::from_str(json).unwrap();

        assert!(!batch.metadata.parallel);
        assert_eq!(batch.metadata.description, Some("Test batch".to_owned()));
        assert_eq!(batch.requests.len(), 1);

        match &batch.requests[0] {
            BatchRequest::Accounting(req) => {
                assert_eq!(req.user, "admin");
                assert_eq!(req.cmd, "show version");
            }
            _ => panic!("Expected accounting request"),
        }
    }

    #[test]
    fn test_parse_batch_file_mixed_requests() {
        let json = r#"{
            "metadata": { "parallel": true },
            "requests": [
                {
                    "type": "accounting",
                    "user": "user1",
                    "port": "tty0",
                    "rem_addr": "10.0.0.1",
                    "cmd": "configure terminal",
                    "cmd_args": ["interface eth0", "shutdown"]
                },
                {
                    "type": "authentication",
                    "user": "user2",
                    "port": "tty1",
                    "rem_addr": "10.0.0.2",
                    "password": "secret"
                },
                {
                    "type": "authorization",
                    "user": "user3",
                    "port": "tty2",
                    "rem_addr": "10.0.0.3",
                    "cmd": "show running-config"
                }
            ]
        }"#;

        let batch: BatchFile = serde_json::from_str(json).unwrap();

        assert!(batch.metadata.parallel);
        assert_eq!(batch.requests.len(), 3);
        assert_eq!(batch.requests[0].type_name(), "accounting");
        assert_eq!(batch.requests[1].type_name(), "authentication");
        assert_eq!(batch.requests[2].type_name(), "authorization");
    }

    #[test]
    fn test_parse_batch_file_defaults() {
        let json = r#"{
            "requests": [
                {
                    "type": "authorization",
                    "user": "admin",
                    "port": "console",
                    "rem_addr": "local"
                }
            ]
        }"#;

        let batch: BatchFile = serde_json::from_str(json).unwrap();

        // Defaults should be applied
        assert!(!batch.metadata.parallel);
        assert!(batch.metadata.description.is_none());

        match &batch.requests[0] {
            BatchRequest::Authorization(req) => {
                assert_eq!(req.service, "shell"); // default
                assert!(req.cmd.is_none());
                assert!(req.cmd_args.is_empty());
            }
            _ => panic!("Expected authorization request"),
        }
    }

    #[test]
    fn test_parse_batch_file_load_test_config() {
        let json = r#"{
            "metadata": {
                "description": "Load test batch",
                "load_test": {
                    "repetitions": 100,
                    "max_parallel": 20
                }
            },
            "requests": [
                {
                    "type": "accounting",
                    "user": "user1",
                    "port": "tty0",
                    "rem_addr": "10.0.0.1",
                    "cmd": "show version"
                }
            ]
        }"#;

        let batch: BatchFile = serde_json::from_str(json).unwrap();

        assert!(batch.metadata.load_test.is_some());
        let load_config = batch.metadata.load_test.as_ref().unwrap();
        assert_eq!(load_config.repetitions, 100);
        assert_eq!(load_config.max_parallel, 20);
    }

    #[test]
    fn test_parse_batch_file_load_test_default_max_parallel() {
        let json = r#"{
            "metadata": {
                "load_test": {
                    "repetitions": 50
                }
            },
            "requests": [
                {
                    "type": "accounting",
                    "user": "user1",
                    "port": "tty0",
                    "rem_addr": "10.0.0.1",
                    "cmd": "show version"
                }
            ]
        }"#;

        let batch: BatchFile = serde_json::from_str(json).unwrap();

        let load_config = batch.metadata.load_test.as_ref().unwrap();
        assert_eq!(load_config.repetitions, 50);
        assert_eq!(load_config.max_parallel, 10); // default value
    }
}
