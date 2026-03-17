use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ServiceRequest {
    Accounting(AccountingOperation),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "result", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ServiceResponse {
    Accounting(AccountingOperationResponse),
    Error(ServiceError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountingOperation {
    pub user: String,
    pub port: String,
    pub remote_address: String,
    pub command: String,
    #[serde(default)]
    pub command_arguments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountingOperationResponse {
    pub server: String,
    pub status_code: u8,
    pub status_name: String,
    pub server_message: String,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceError {
    pub message: String,
    pub server: Option<String>,
    #[serde(default)]
    pub retriable: bool,
}

impl ServiceError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            server: None,
            retriable: false,
        }
    }

    #[must_use]
    pub fn with_server(mut self, server: impl Into<String>) -> Self {
        self.server = Some(server.into());
        self
    }

    #[must_use]
    pub const fn retriable(mut self, retriable: bool) -> Self {
        self.retriable = retriable;
        self
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use schemars::schema_for;
    use serde_json::json;

    use super::*;

    #[allow(dead_code)]
    #[derive(JsonSchema)]
    struct ServiceProtocolSchemaDocument {
        request: ServiceRequest,
        response: ServiceResponse,
    }

    fn protocol_schema_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ipc-protocol.schema.json")
    }

    fn generated_schema() -> serde_json::Value {
        schema_for!(ServiceProtocolSchemaDocument).to_value()
    }

    #[test]
    fn test_checked_in_schema_matches_protocol_types() {
        let expected: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(protocol_schema_path()).expect("schema file should exist"),
        )
        .expect("schema file should be valid json");

        assert_eq!(generated_schema(), expected);
    }

    #[test]
    fn test_accounting_operation_rejects_unknown_fields() {
        let invalid_request = json!({
            "operation": "accounting",
            "user": "admin",
            "port": "tty0",
            "remote_address": "127.0.0.1",
            "command": "show",
            "command_arguments": ["users"],
            "custom_flag_1": true,
            "session_id": 42
        });

        let error =
            serde_json::from_value::<ServiceRequest>(invalid_request).expect_err("must reject");
        assert!(error.to_string().contains("unknown field"));
    }
}
