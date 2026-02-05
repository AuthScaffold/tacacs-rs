//! Batch mode processing for TACACS+ requests
//!
//! This module handles reading and executing multiple TACACS+ requests
//! from a JSON batch file, with support for parallel execution.

use anyhow::Context;
use futures::future::join_all;
use serde::Deserialize;
use std::path::Path;

use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_networking::session::Session;

use crate::commands::accounting::send_accounting_request;
use crate::Connection;

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

/// Executes all requests in a batch file
///
/// # Arguments
///
/// * `connection` - The active TACACS+ connection
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
    connection: &Connection,
    batch: &BatchFile,
) -> anyhow::Result<Vec<RequestResult>> {
    if let Some(desc) = &batch.metadata.description {
        log::info!("Executing batch: {desc}");
        println!("Batch: {desc}");
    }

    let request_count = batch.requests.len();
    log::info!(
        "Processing {request_count} requests (parallel: {})",
        batch.metadata.parallel
    );

    if batch.metadata.parallel {
        execute_parallel(connection, &batch.requests).await
    } else {
        execute_sequential(connection, &batch.requests).await
    }
}

/// Executes requests sequentially, one at a time
async fn execute_sequential(
    connection: &Connection,
    requests: &[BatchRequest],
) -> anyhow::Result<Vec<RequestResult>> {
    let mut results = Vec::with_capacity(requests.len());

    for (index, request) in requests.iter().enumerate() {
        log::info!("Executing request {}/{}", index + 1, requests.len());

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
async fn execute_parallel(
    connection: &Connection,
    requests: &[BatchRequest],
) -> anyhow::Result<Vec<RequestResult>> {
    // Create all sessions upfront
    let mut session_futures = Vec::with_capacity(requests.len());
    for request in requests {
        let custom_session_id = request.session_id();
        session_futures.push(connection.create_session_optional_id(custom_session_id));
    }

    let sessions: Vec<Session> = join_all(session_futures)
        .await
        .into_iter()
        .enumerate()
        .map(|(i, r)| r.with_context(|| format!("Failed to create session for request {i}")))
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Execute all requests in parallel
    let futures: Vec<_> = requests
        .iter()
        .zip(sessions.iter())
        .enumerate()
        .map(|(index, (request, session))| async move {
            log::info!("Starting parallel request {}", index + 1);
            let result = execute_single_request(session, request).await;
            RequestResult {
                index,
                request_type: request.type_name(),
                result,
            }
        })
        .collect();

    Ok(join_all(futures).await)
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
}
