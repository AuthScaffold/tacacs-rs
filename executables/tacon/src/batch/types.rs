//! Batch mode data types and structures
//!
//! This module contains the data structures for batch file parsing
//! and request/result types.

use serde::Deserialize;
use std::time::Duration;
use tacacsrs_messages::enumerations::TacacsFlags;

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

    #[test]
    fn test_custom_flags_to_tacacs_flags() {
        let flags = CustomFlags {
            custom_flag_1: true,
            custom_flag_2: false,
        };
        let tacacs_flags = flags.to_tacacs_flags();
        assert!(tacacs_flags.contains(TacacsFlags::TAC_PLUS_CUSTOM_FLAG_1));
        assert!(!tacacs_flags.contains(TacacsFlags::TAC_PLUS_CUSTOM_FLAG_2));

        let both_flags = CustomFlags {
            custom_flag_1: true,
            custom_flag_2: true,
        };
        let tacacs_flags = both_flags.to_tacacs_flags();
        assert!(tacacs_flags.contains(TacacsFlags::TAC_PLUS_CUSTOM_FLAG_1));
        assert!(tacacs_flags.contains(TacacsFlags::TAC_PLUS_CUSTOM_FLAG_2));
    }
}
