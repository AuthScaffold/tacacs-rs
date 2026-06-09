use std::collections::BTreeMap;

use regorus::Engine;
use serde_json::Value;
use tonic::Status;

use crate::policy::{
    CapturedIpcRequest, EmulatorPolicy, EmulatorResponse, IpcRpc, PolicyDecision, DECISION_QUERY,
};

/// Mutable emulator state shared by the emulated agent service and mock
/// controller.
///
/// Stores the compiled OPA/Rego policy engine and every captured IPC request.
/// The policy and its fixed data are compiled once; each request is evaluated
/// by supplying the captured fields as Rego `input`.
///
/// # Thread safety
///
/// [`regorus::Engine`] is **not** internally synchronized: `set_input` and
/// `eval_rule` take `&mut self` and share mutable engine state, so feeding one
/// request's `input` while another request is being evaluated would race. This
/// type therefore provides no interior synchronization of its own and instead
/// relies on callers holding it behind a single exclusive lock. All access goes
/// through `Arc<Mutex<EmulatorState>>` (see [`crate::service`]), and the lock is
/// held across the whole [`Self::record_and_evaluate`] call so that `set_input`
/// and `eval_rule` execute atomically for one request at a time.
pub(crate) struct EmulatorState {
    policy: EmulatorPolicy,
    engine: Engine,
    captured_requests: Vec<CapturedIpcRequest>,
}

impl EmulatorState {
    pub(crate) fn new(policy: EmulatorPolicy, engine: Engine) -> Self {
        Self {
            policy,
            engine,
            captured_requests: Vec::new(),
        }
    }

    pub(crate) fn captured_requests(&self) -> Vec<CapturedIpcRequest> {
        self.captured_requests.clone()
    }

    /// Replaces the active policy, recompiling its engine and clearing captured
    /// requests.
    pub(crate) fn replace_policy(&mut self, policy: EmulatorPolicy) -> anyhow::Result<()> {
        let engine = policy.compile()?;
        self.policy = policy;
        self.engine = engine;
        self.captured_requests.clear();
        Ok(())
    }

    pub(crate) fn reset(&mut self) {
        self.captured_requests.clear();
    }

    /// Records the request and evaluates the policy against it.
    ///
    /// Returns `Ok(None)` when the policy leaves `decision` undefined for the
    /// request, signalling that no rule applied.
    pub(crate) fn record_and_evaluate(
        &mut self,
        rpc: IpcRpc,
        fields: &BTreeMap<String, Value>,
    ) -> Result<Option<EvaluatedDecision>, Status> {
        self.captured_requests.push(CapturedIpcRequest {
            rpc,
            fields: fields.clone(),
        });
        self.evaluate(rpc, fields)
    }

    /// Sets the request as Rego `input` and evaluates the decision rule.
    ///
    /// `set_input` followed by `eval_rule` mutates shared engine state and must
    /// not be interleaved with another request's evaluation. Callers guarantee
    /// this by holding the surrounding `Mutex<EmulatorState>` for the entire
    /// call (see the type-level "Thread safety" note); `&mut self` makes that
    /// exclusivity explicit here.
    fn evaluate(
        &mut self,
        rpc: IpcRpc,
        fields: &BTreeMap<String, Value>,
    ) -> Result<Option<EvaluatedDecision>, Status> {
        let input = build_input(rpc, fields);
        let input = regorus::Value::from_json_str(&input.to_string()).map_err(|error| {
            Status::internal(format!("Failed to encode policy input for {rpc}: {error}"))
        })?;
        self.engine.set_input(input);
        let decision = self
            .engine
            .eval_rule(DECISION_QUERY.to_owned())
            .map_err(|error| {
                Status::internal(format!("Policy evaluation failed for {rpc}: {error}"))
            })?;
        if matches!(decision, regorus::Value::Undefined) {
            return Ok(None);
        }
        let decision = serde_json::to_value(&decision).map_err(|error| {
            Status::internal(format!("Failed to encode policy decision for {rpc}: {error}"))
        })?;
        let decision: PolicyDecision = serde_json::from_value(decision).map_err(|error| {
            Status::failed_precondition(format!(
                "Invalid policy decision for {rpc}: expected an object with type=\"response\" or \
                 type=\"error\": {error}"
            ))
        })?;
        Ok(Some(EvaluatedDecision {
            response: decision.response,
            delay_ms: decision.delay_ms,
        }))
    }
}

fn build_input(rpc: IpcRpc, fields: &BTreeMap<String, Value>) -> Value {
    let mut input = serde_json::Map::with_capacity(fields.len() + 1);
    input.insert("rpc".to_owned(), Value::String(rpc.as_str().to_owned()));
    for (key, value) in fields {
        input.insert(key.clone(), value.clone());
    }
    Value::Object(input)
}

/// A policy decision resolved for a single request.
///
/// Carries the configured response and optional delay outside the state lock so
/// RPC handlers can wait asynchronously without blocking controller operations.
#[derive(Clone)]
pub(crate) struct EvaluatedDecision {
    pub(crate) response: EmulatorResponse,
    pub(crate) delay_ms: Option<u64>,
}
