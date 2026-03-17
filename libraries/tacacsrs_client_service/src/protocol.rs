use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ServiceRequest {
    Accounting(AccountingOperation),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ServiceResponse {
    Accounting(AccountingOperationResponse),
    Error(ServiceError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountingOperation {
    pub user: String,
    pub port: String,
    pub remote_address: String,
    pub command: String,
    #[serde(default)]
    pub command_arguments: Vec<String>,
    #[serde(default)]
    pub custom_flag_1: bool,
    #[serde(default)]
    pub custom_flag_2: bool,
    #[serde(default)]
    pub session_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountingOperationResponse {
    pub server: String,
    pub status_code: u8,
    pub status_name: String,
    pub server_message: String,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
