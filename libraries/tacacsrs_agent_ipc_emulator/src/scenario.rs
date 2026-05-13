use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::controller;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmulatorScenario {
    pub transactions: Vec<TransactionRule>,
}

impl EmulatorScenario {
    /// Reads and parses a JSON scenario file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read IPC emulator scenario {}", path.display()))?;
        serde_json::from_str(&data)
            .with_context(|| format!("Failed to parse IPC emulator scenario {}", path.display()))
    }

    /// Reads and parses a JSON scenario file without blocking the async runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub async fn from_file_async(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let data = tokio::fs::read_to_string(&path)
            .await
            .with_context(|| format!("Failed to read IPC emulator scenario {}", path.display()))?;
        serde_json::from_str(&data)
            .with_context(|| format!("Failed to parse IPC emulator scenario {}", path.display()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionRule {
    pub rpc: IpcRpc,
    #[serde(rename = "match")]
    pub match_fields: MatchFields,
    #[serde(default, rename = "match_any", skip_serializing_if = "Option::is_none")]
    pub match_any_fields: Option<MatchFields>,
    pub respond: EmulatorResponse,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MatchFields {
    #[serde(flatten)]
    pub fields: BTreeMap<String, Value>,
}

impl MatchFields {
    /// Returns true when every configured field equals the request field value.
    #[must_use]
    pub fn matches(&self, request_fields: &BTreeMap<String, Value>) -> bool {
        self.fields
            .iter()
            .all(|(key, value)| request_fields.get(key) == Some(value))
    }

    /// Returns true when every configured field has matching elements in the
    /// corresponding request array.
    ///
    /// - Scalar value: the request array must contain that value.
    /// - Array value: the request array must contain **all** of the values.
    #[must_use]
    pub fn matches_any(&self, request_fields: &BTreeMap<String, Value>) -> bool {
        self.fields.iter().all(|(key, value)| {
            let Some(request_array) = request_fields.get(key).and_then(Value::as_array) else {
                return false;
            };
            match value {
                Value::Array(required) => required.iter().all(|v| request_array.contains(v)),
                scalar => request_array.contains(scalar),
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IpcRpc {
    Accounting,
    Authorization,
}

impl fmt::Display for IpcRpc {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accounting => formatter.write_str("Accounting"),
            Self::Authorization => formatter.write_str("Authorization"),
        }
    }
}

impl std::str::FromStr for IpcRpc {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Accounting" => Ok(Self::Accounting),
            "Authorization" => Ok(Self::Authorization),
            _ => bail!("unsupported IPC RPC {value:?}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum EmulatorResponse {
    Response(ResponseBody),
    Error(ErrorBody),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseBody {
    pub server: String,
    pub status: String,
    #[serde(default)]
    pub server_message: String,
    #[serde(default)]
    pub data: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<ScenarioAuthorizationArg>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub message: String,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub retriable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioAuthorizationArg {
    pub name: String,
    pub mandatory: bool,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedIpcRequest {
    pub rpc: IpcRpc,
    pub fields: BTreeMap<String, Value>,
}

impl TryFrom<controller::CapturedIpcRequest> for CapturedIpcRequest {
    type Error = anyhow::Error;

    fn try_from(value: controller::CapturedIpcRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            rpc: value.rpc.parse()?,
            fields: serde_json::from_str(&value.request_json)
                .context("Failed to decode captured IPC request JSON")?,
        })
    }
}

impl TryFrom<&CapturedIpcRequest> for controller::CapturedIpcRequest {
    type Error = anyhow::Error;

    fn try_from(value: &CapturedIpcRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            rpc: value.rpc.to_string(),
            request_json: serde_json::to_string(&value.fields)
                .context("Failed to encode captured IPC request")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleHitCount {
    pub index: usize,
    pub rpc: IpcRpc,
    pub hits: u64,
}

impl TryFrom<controller::RuleHitCount> for RuleHitCount {
    type Error = anyhow::Error;

    fn try_from(value: controller::RuleHitCount) -> Result<Self, Self::Error> {
        Ok(Self {
            index: usize::try_from(value.index).context("Rule hit index is out of range")?,
            rpc: value.rpc.parse()?,
            hits: value.hits,
        })
    }
}

impl TryFrom<&RuleHitCount> for controller::RuleHitCount {
    type Error = anyhow::Error;

    fn try_from(value: &RuleHitCount) -> Result<Self, Self::Error> {
        Ok(Self {
            index: u32::try_from(value.index).context("Rule hit index is out of range")?,
            rpc: value.rpc.to_string(),
            hits: value.hits,
        })
    }
}
