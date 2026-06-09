use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use anyhow::{bail, Context};
use regorus::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::controller;

/// Rego query path evaluated for every captured IPC request.
///
/// The policy is expected to define a `decision` rule in the `tacacs.emulator`
/// package that returns the emulator response for the request supplied as Rego
/// `input`.
pub const DECISION_QUERY: &str = "data.tacacs.emulator.decision";

/// An Open Policy Agent policy that drives the emulator.
///
/// The policy is composed of Rego source and a fixed JSON data document. The
/// data is loaded once when the policy is compiled, and the captured TACACS+
/// request is supplied as Rego `input` at evaluation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmulatorPolicy {
    /// Rego policy source.
    pub rego: String,
    /// Fixed policy data document. Defaults to an empty object.
    #[serde(default = "empty_object")]
    pub data: Value,
}

fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

impl EmulatorPolicy {
    /// Creates a policy from Rego source with an empty data document.
    #[must_use]
    pub fn new(rego: impl Into<String>) -> Self {
        Self {
            rego: rego.into(),
            data: empty_object(),
        }
    }

    /// Attaches a fixed data document to the policy.
    #[must_use]
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = data;
        self
    }

    /// Reads a Rego policy file with an empty data document.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the policy cannot be
    /// compiled.
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let rego = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read IPC emulator policy {}", path.display()))?;
        let policy = Self::new(rego);
        policy.compile()?;
        Ok(policy)
    }

    /// Reads a Rego policy file without blocking the async runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the policy cannot be
    /// compiled.
    pub async fn from_file_async(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let rego = tokio::fs::read_to_string(&path)
            .await
            .with_context(|| format!("Failed to read IPC emulator policy {}", path.display()))?;
        let policy = Self::new(rego);
        policy.compile()?;
        Ok(policy)
    }

    /// Reads a Rego policy file together with a JSON data document file.
    ///
    /// # Errors
    ///
    /// Returns an error if either file cannot be read or parsed, or if the
    /// policy cannot be compiled.
    pub async fn from_files_async(
        policy_path: impl AsRef<Path>,
        data_path: impl AsRef<Path>,
    ) -> anyhow::Result<Self> {
        let policy = Self::from_file_async(policy_path).await?;
        let data_path = data_path.as_ref().to_path_buf();
        let data = tokio::fs::read_to_string(&data_path)
            .await
            .with_context(|| {
                format!("Failed to read IPC emulator policy data {}", data_path.display())
            })?;
        let data: Value = serde_json::from_str(&data).with_context(|| {
            format!("Failed to parse IPC emulator policy data {}", data_path.display())
        })?;
        let policy = policy.with_data(data);
        policy.compile()?;
        Ok(policy)
    }

    /// Compiles the policy into a ready-to-evaluate [`Engine`].
    ///
    /// The Rego source and fixed data are loaded once; only `input` changes
    /// between evaluations.
    ///
    /// # Errors
    ///
    /// Returns an error if the Rego source cannot be parsed or the data cannot
    /// be loaded.
    pub fn compile(&self) -> anyhow::Result<Engine> {
        let mut engine = Engine::new();
        engine
            .add_policy("policy.rego".to_owned(), self.rego.clone())
            .context("Failed to compile IPC emulator Rego policy")?;
        if !self.data.is_null() && self.data != empty_object() {
            let data = regorus::Value::from_json_str(&self.data.to_string())
                .context("Failed to encode IPC emulator policy data")?;
            engine
                .add_data(data)
                .context("Failed to load IPC emulator policy data")?;
        }
        Ok(engine)
    }
}

/// The decision produced by evaluating the policy for a single request.
///
/// `delay_ms` is flattened alongside the response so a Rego `decision` object
/// can specify a response and an optional artificial delay in one object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    #[serde(flatten)]
    pub response: EmulatorResponse,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum IpcRpc {
    Accounting,
    Authorization,
}

impl IpcRpc {
    /// Returns the canonical Rego `input.rpc` discriminator string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accounting => "Accounting",
            Self::Authorization => "Authorization",
        }
    }
}

impl fmt::Display for IpcRpc {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
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
    pub args: Vec<AuthorizationResponseArg>,
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
pub struct AuthorizationResponseArg {
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
