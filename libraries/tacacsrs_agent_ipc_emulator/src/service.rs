use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tacacsrs_agent_client::ipc;
use tacacsrs_agent_client::ipc::tacacs_agent_server::TacacsAgent;
use tacacsrs_agent_client::PapAuthenticationOperation;
use tokio::sync::{oneshot, Mutex};
use tonic::{Request, Response, Status};

use crate::controller;
use crate::controller::tacacs_agent_mock_controller_server::TacacsAgentMockController;
use crate::policy::{EmulatorPolicy, EmulatorResponse, IpcRpc, ResponseBody};
use crate::protocol::{
    accounting_fields, accounting_response, authorization_fields, authorization_response,
    service_error,
};
use crate::state::{EmulatorState, EvaluatedDecision};

#[derive(Clone)]
/// Emulated implementation of the TACACS+ agent gRPC service.
///
/// Each RPC captures the incoming request, evaluates the active OPA/Rego policy
/// with the request as `input`, and returns the configured response or gRPC
/// status error.
pub(crate) struct AgentService {
    pub(crate) state: Arc<Mutex<EmulatorState>>,
}

impl AgentService {
    async fn evaluate(
        &self,
        rpc: IpcRpc,
        fields: BTreeMap<String, Value>,
    ) -> Result<Option<EvaluatedDecision>, Status> {
        let decision = {
            let mut state = self.state.lock().await;
            state.record_and_evaluate(rpc, &fields)?
        };
        log_decision(rpc, fields.get("command"), decision.as_ref());
        if let Some(decision) = &decision {
            if let Some(delay_ms) = decision.delay_ms {
                log::info!("{rpc} delaying response by {delay_ms} ms");
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }
        Ok(decision)
    }
}

#[tonic::async_trait]
impl TacacsAgent for AgentService {
    async fn authenticate_pap(
        &self,
        request: Request<ipc::PapAuthenticationRequest>,
    ) -> Result<Response<ipc::PapAuthenticationReply>, Status> {
        let _request = PapAuthenticationOperation::try_from(request.into_inner())
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        Ok(Response::new(ipc::PapAuthenticationReply {
            result: Some(ipc::pap_authentication_reply::Result::Error(ipc::ServiceError {
                message: "PAP authentication is not supported by the policy emulator".to_owned(),
                server: "ipc-emulator".to_owned(),
                retriable: false,
            })),
        }))
    }

    async fn accounting(
        &self,
        request: Request<ipc::AccountingRequest>,
    ) -> Result<Response<ipc::AccountingReply>, Status> {
        let fields = accounting_fields(&request.into_inner());
        log_request(IpcRpc::Accounting, &fields);
        let Some(decision) = self.evaluate(IpcRpc::Accounting, fields).await? else {
            return Err(Status::not_found(
                "IPC emulator policy returned no Accounting decision for the request",
            ));
        };
        match decision.response {
            EmulatorResponse::Response(response) => {
                log_response(IpcRpc::Accounting, &response);
                Ok(Response::new(ipc::AccountingReply {
                    result: Some(ipc::accounting_reply::Result::Response(
                        accounting_response(response)?.into_proto(),
                    )),
                }))
            }
            EmulatorResponse::Error(error) => {
                log_error_response(IpcRpc::Accounting, &error);
                Ok(Response::new(ipc::AccountingReply {
                    result: Some(ipc::accounting_reply::Result::Error(
                        service_error(error).into_proto(),
                    )),
                }))
            }
        }
    }

    async fn authorization(
        &self,
        request: Request<ipc::AuthorizationRequest>,
    ) -> Result<Response<ipc::AuthorizationReply>, Status> {
        let fields = authorization_fields(&request.into_inner());
        log_request(IpcRpc::Authorization, &fields);
        let command_display = fields
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>")
            .to_owned();
        let response = match self.evaluate(IpcRpc::Authorization, fields).await? {
            Some(decision) => decision.response,
            None => EmulatorResponse::Response(ResponseBody {
                server: "ipc-emulator".to_owned(),
                status: "Fail".to_owned(),
                server_message: format!(
                    "policy returned no authorization decision (undefined) for command \
                     {command_display}"
                ),
                data: String::new(),
                args: Vec::new(),
            }),
        };
        match response {
            EmulatorResponse::Response(response) => {
                log_response(IpcRpc::Authorization, &response);
                Ok(Response::new(ipc::AuthorizationReply {
                    result: Some(ipc::authorization_reply::Result::Response(
                        authorization_response(response)?.into_proto(),
                    )),
                }))
            }
            EmulatorResponse::Error(error) => {
                log_error_response(IpcRpc::Authorization, &error);
                Ok(Response::new(ipc::AuthorizationReply {
                    result: Some(ipc::authorization_reply::Result::Error(
                        service_error(error).into_proto(),
                    )),
                }))
            }
        }
    }
}

fn log_request(rpc: IpcRpc, fields: &BTreeMap<String, Value>) {
    log::info!("{rpc} request {}", request_summary(fields));
    log::debug!("{rpc} request fields {}", json_object(fields));
}

fn log_decision(rpc: IpcRpc, command: Option<&Value>, decision: Option<&EvaluatedDecision>) {
    if let Some(decision) = decision {
        log::info!("{rpc} policy decided {}", response_summary(&decision.response));
    } else {
        let command = command.map_or_else(|| "<none>".to_owned(), json_value);
        log::warn!("{rpc} policy returned no decision for command={command}");
    }
}

fn log_response(rpc: IpcRpc, response: &ResponseBody) {
    log::info!(
        "{rpc} reply response status={} server={} message={}",
        response.status,
        display_text(&response.server),
        display_text(&response.server_message)
    );
    if !response.args.is_empty() {
        log::debug!("{rpc} reply authorization args {}", authorization_args_summary(response));
    }
}

fn log_error_response(rpc: IpcRpc, error: &crate::policy::ErrorBody) {
    log::warn!(
        "{rpc} reply service-error retriable={} server={} message={}",
        error.retriable,
        display_text(&error.server),
        display_text(&error.message)
    );
}

fn request_summary(fields: &BTreeMap<String, Value>) -> String {
    [
        "user",
        "port",
        "remote_address",
        "privilege_level",
        "command",
        "command_arguments",
    ]
    .into_iter()
    .filter_map(|key| {
        fields
            .get(key)
            .map(|value| format!("{key}={}", json_value(value)))
    })
    .collect::<Vec<_>>()
    .join(" ")
}

fn response_summary(response: &EmulatorResponse) -> String {
    match response {
        EmulatorResponse::Response(body) => {
            format!("response status={} server={}", body.status, display_text(&body.server))
        }
        EmulatorResponse::Error(body) => format!(
            "service-error retriable={} server={} message={}",
            body.retriable,
            display_text(&body.server),
            display_text(&body.message)
        ),
    }
}

fn authorization_args_summary(response: &ResponseBody) -> String {
    response
        .args
        .iter()
        .map(|arg| {
            format!(
                "{}{}={}",
                if arg.mandatory {
                    "!"
                } else {
                    ""
                },
                arg.name,
                display_text(&arg.value)
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn json_object(fields: &BTreeMap<String, Value>) -> String {
    serde_json::to_string(fields).unwrap_or_else(|error| format!("<json encode failed: {error}>"))
}

fn json_value(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|error| format!("<json encode failed: {error}>"))
}

fn display_text(value: &str) -> String {
    if value.is_empty() {
        "<empty>".to_owned()
    } else {
        json_value(&Value::String(value.to_owned()))
    }
}

#[derive(Clone)]
/// Mock-controller gRPC service used by external integration test runners.
///
/// Provides runtime policy replacement, state reset, request inspection, and
/// graceful shutdown for the same in-memory emulator state.
pub(crate) struct ControllerService {
    pub(crate) state: Arc<Mutex<EmulatorState>>,
    pub(crate) shutdown_sender: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

#[tonic::async_trait]
impl TacacsAgentMockController for ControllerService {
    async fn load_policy(
        &self,
        request: Request<controller::LoadPolicyRequest>,
    ) -> Result<Response<controller::LoadPolicyReply>, Status> {
        let request = request.into_inner();
        let data = if request.data_json.trim().is_empty() {
            Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_str(&request.data_json).map_err(|error| {
                Status::invalid_argument(format!("Invalid policy data JSON: {error}"))
            })?
        };
        let policy = EmulatorPolicy::new(request.policy_rego).with_data(data);
        self.state
            .lock()
            .await
            .replace_policy(policy)
            .map_err(|error| Status::invalid_argument(format!("Invalid policy: {error}")))?;
        log::info!("controller loaded new OPA/Rego policy");
        Ok(Response::new(controller::LoadPolicyReply {}))
    }

    async fn reset_state(
        &self,
        _request: Request<controller::ResetStateRequest>,
    ) -> Result<Response<controller::ResetStateReply>, Status> {
        log::info!("controller reset captured requests");
        self.state.lock().await.reset();
        Ok(Response::new(controller::ResetStateReply {}))
    }

    async fn get_captured_requests(
        &self,
        _request: Request<controller::GetCapturedRequestsRequest>,
    ) -> Result<Response<controller::GetCapturedRequestsReply>, Status> {
        let requests = self
            .state
            .lock()
            .await
            .captured_requests()
            .iter()
            .map(controller::CapturedIpcRequest::try_from)
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(|error| Status::internal(error.to_string()))?;
        log::debug!("controller returned {} captured request(s)", requests.len());
        Ok(Response::new(controller::GetCapturedRequestsReply { requests }))
    }

    async fn shutdown(
        &self,
        _request: Request<controller::ShutdownRequest>,
    ) -> Result<Response<controller::ShutdownReply>, Status> {
        log::info!("controller requested graceful shutdown");
        send_shutdown(&self.shutdown_sender).await;
        Ok(Response::new(controller::ShutdownReply {}))
    }
}

pub(crate) async fn shutdown_signal(shutdown_rx: oneshot::Receiver<()>) {
    let _ = shutdown_rx.await;
}

pub(crate) async fn send_shutdown(shutdown_sender: &Arc<Mutex<Option<oneshot::Sender<()>>>>) {
    let sender = shutdown_sender.lock().await.take();
    if let Some(sender) = sender {
        let _ = sender.send(());
    }
}
