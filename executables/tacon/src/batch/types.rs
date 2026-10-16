//! Batch mode data types and structures
//!
//! This module contains the data structures for batch file parsing
//! and request/result types.

use serde::Deserialize;
use std::time::Duration;
use tacacsrs_config::TacacsPlusServerType;

/// Batch file structure containing metadata and requests
#[derive(Debug, Deserialize)]
pub struct BatchFile {
    /// Metadata that controls the batch run
    #[serde(default)]
    pub metadata: BatchMetadata,

    /// List of requests to run
    pub requests: Vec<BatchRequest>,
}

impl BatchFile {
    /// Returns the combined TACACS+ server type required to run all requests.
    #[must_use]
    pub fn required_server_type(&self) -> Option<TacacsPlusServerType> {
        let required_type = self
            .requests
            .iter()
            .fold(TacacsPlusServerType::empty(), |acc, request| acc | request.server_type());

        (!required_type.is_empty()).then_some(required_type)
    }
}

/// Metadata that controls how the batch runs
#[derive(Debug, Deserialize, Default)]
pub struct BatchMetadata {
    /// If true, the batch sends all requests in parallel. If false, it sends them one at a time.
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

const fn default_max_parallel() -> usize {
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

impl BatchRequest {
    /// Returns the type name of this request
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Accounting(_) => "accounting",
            Self::Authentication(_) => "authentication",
            Self::Authorization(_) => "authorization",
        }
    }

    /// Returns the TACACS+ server type required to run this request.
    pub const fn server_type(&self) -> TacacsPlusServerType {
        match self {
            Self::Accounting(_) => TacacsPlusServerType::ACCOUNTING,
            Self::Authentication(_) => TacacsPlusServerType::AUTHENTICATION,
            Self::Authorization(_) => TacacsPlusServerType::AUTHORIZATION,
        }
    }
}

/// Arguments for an accounting request
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountingRequest {
    /// Username that runs the command
    pub user: String,

    /// Port identifier (for example, "tty0")
    pub port: String,

    /// Remote address of the client
    pub rem_addr: String,

    /// Command that the user runs
    pub cmd: String,

    /// Optional command arguments
    #[serde(default)]
    pub cmd_args: Vec<String>,
}

/// Arguments for an authentication request
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // Fields will be used when authentication is implemented
pub struct AuthenticationRequest {
    /// Username to authenticate
    pub user: String,

    /// Port identifier
    pub port: String,

    /// Remote address of the client
    pub rem_addr: String,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationAuthenticationContext {
    Ascii,
    Pap,
    Unauthenticated,
}

/// Arguments for an authorization request
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // Fields will be used when authorization is implemented
pub struct AuthorizationRequest {
    /// Username requesting authorization
    pub user: String,

    /// Port identifier
    pub port: String,

    /// Remote address of the client
    pub rem_addr: String,

    #[serde(default = "default_privilege_level")]
    pub privilege_level: u8,

    pub authentication_context: AuthorizationAuthenticationContext,

    /// Command to authorize
    #[serde(default)]
    pub cmd: Option<String>,

    /// Command arguments to authorize
    #[serde(default)]
    pub cmd_args: Vec<String>,
}

const fn default_privilege_level() -> u8 {
    15
}

/// Result of a single batch request
#[derive(Debug)]
pub struct RequestResult {
    /// Index of the request in the batch
    pub index: usize,

    /// Type of request that ran
    pub request_type: &'static str,

    /// Result of the request (Ok or error message)
    pub result: Result<String, String>,
}

/// Result of a load test
#[derive(Debug)]
pub struct LoadTestResult {
    /// Total number of requests that ran
    pub total_requests: usize,

    /// Number of successful requests
    pub successful_requests: usize,

    /// Number of failed requests. The value is 0 or 1 because the batch stops after the first failure.
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
    pub const fn is_success(&self) -> bool {
        self.first_failure.is_none()
    }
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
                    "rem_addr": "10.0.0.2"
                },
                {
                    "type": "authorization",
                    "user": "user3",
                    "port": "tty2",
                    "rem_addr": "10.0.0.3",
                    "authentication_context": "pap",
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
                    "rem_addr": "local",
                    "authentication_context": "pap"
                }
            ]
        }"#;

        let batch: BatchFile = serde_json::from_str(json).unwrap();

        // The parser applies the default values.
        assert!(!batch.metadata.parallel);
        assert!(batch.metadata.description.is_none());

        match &batch.requests[0] {
            BatchRequest::Authorization(req) => {
                assert_eq!(req.privilege_level, 15);
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

    #[test]
    fn test_parse_batch_file_rejects_session_id() {
        let json = r#"{
            "requests": [
                {
                    "type": "accounting",
                    "user": "user1",
                    "port": "tty0",
                    "rem_addr": "10.0.0.1",
                    "cmd": "show version",
                    "session_id": 7
                }
            ]
        }"#;

        let error = serde_json::from_str::<BatchFile>(json).unwrap_err();
        assert!(error.to_string().contains("unknown field `session_id`"));
    }
}
