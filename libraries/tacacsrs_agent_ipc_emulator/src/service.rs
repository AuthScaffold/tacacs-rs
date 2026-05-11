use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tacacsrs_agent_client::ipc;
use tacacsrs_agent_client::ipc::tacacs_agent_server::TacacsAgent;
use tokio::sync::oneshot;
use tonic::{Request, Response, Status};

use crate::controller;
use crate::controller::tacacs_agent_mock_controller_server::TacacsAgentMockController;
use crate::protocol::{
    accounting_fields, accounting_response, authorization_fields, authorization_response,
    service_error,
};
use crate::scenario::{EmulatorResponse, EmulatorScenario, IpcRpc};
use crate::state::{EmulatorState, MatchedRule};

#[derive(Clone)]
pub(crate) struct AgentService {
    pub(crate) state: Arc<Mutex<EmulatorState>>,
}

impl AgentService {
    async fn match_request(
        &self,
        rpc: IpcRpc,
        fields: BTreeMap<String, Value>,
    ) -> Result<MatchedRule, Status> {
        let matched = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| Status::internal("IPC emulator state lock is poisoned"))?;
            state.record_and_match(rpc, &fields)?
        };
        if let Some(delay_ms) = matched.delay_ms {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        Ok(matched)
    }
}

#[tonic::async_trait]
impl TacacsAgent for AgentService {
    async fn accounting(
        &self,
        request: Request<ipc::AccountingRequest>,
    ) -> Result<Response<ipc::AccountingReply>, Status> {
        let fields = accounting_fields(&request.into_inner());
        let matched = self.match_request(IpcRpc::Accounting, fields).await?;
        match matched.response {
            EmulatorResponse::Response(response) => Ok(Response::new(ipc::AccountingReply {
                result: Some(ipc::accounting_reply::Result::Response(
                    accounting_response(response)?.into_proto(),
                )),
            })),
            EmulatorResponse::Error(error) => Ok(Response::new(ipc::AccountingReply {
                result: Some(ipc::accounting_reply::Result::Error(
                    service_error(error).into_proto(),
                )),
            })),
        }
    }

    async fn authorization(
        &self,
        request: Request<ipc::AuthorizationRequest>,
    ) -> Result<Response<ipc::AuthorizationReply>, Status> {
        let fields = authorization_fields(&request.into_inner());
        let matched = self.match_request(IpcRpc::Authorization, fields).await?;
        match matched.response {
            EmulatorResponse::Response(response) => Ok(Response::new(ipc::AuthorizationReply {
                result: Some(ipc::authorization_reply::Result::Response(
                    authorization_response(response)?.into_proto(),
                )),
            })),
            EmulatorResponse::Error(error) => Ok(Response::new(ipc::AuthorizationReply {
                result: Some(ipc::authorization_reply::Result::Error(
                    service_error(error).into_proto(),
                )),
            })),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ControllerService {
    pub(crate) state: Arc<Mutex<EmulatorState>>,
    pub(crate) shutdown_sender: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

#[tonic::async_trait]
impl TacacsAgentMockController for ControllerService {
    async fn load_scenario(
        &self,
        request: Request<controller::LoadScenarioRequest>,
    ) -> Result<Response<controller::LoadScenarioReply>, Status> {
        let scenario: EmulatorScenario = serde_json::from_str(&request.into_inner().scenario_json)
            .map_err(|error| Status::invalid_argument(format!("Invalid scenario JSON: {error}")))?;
        self.state
            .lock()
            .map_err(|_| Status::internal("IPC emulator state lock is poisoned"))?
            .replace_scenario(scenario);
        Ok(Response::new(controller::LoadScenarioReply {}))
    }

    async fn reset_state(
        &self,
        _request: Request<controller::ResetStateRequest>,
    ) -> Result<Response<controller::ResetStateReply>, Status> {
        self.state
            .lock()
            .map_err(|_| Status::internal("IPC emulator state lock is poisoned"))?
            .reset();
        Ok(Response::new(controller::ResetStateReply {}))
    }

    async fn get_captured_requests(
        &self,
        _request: Request<controller::GetCapturedRequestsRequest>,
    ) -> Result<Response<controller::GetCapturedRequestsReply>, Status> {
        let requests = self
            .state
            .lock()
            .map_err(|_| Status::internal("IPC emulator state lock is poisoned"))?
            .captured_requests()
            .iter()
            .map(controller::CapturedIpcRequest::try_from)
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(controller::GetCapturedRequestsReply { requests }))
    }

    async fn get_rule_hit_counts(
        &self,
        _request: Request<controller::GetRuleHitCountsRequest>,
    ) -> Result<Response<controller::GetRuleHitCountsReply>, Status> {
        let hit_counts = self
            .state
            .lock()
            .map_err(|_| Status::internal("IPC emulator state lock is poisoned"))?
            .rule_hit_counts()
            .iter()
            .map(controller::RuleHitCount::try_from)
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(|error| Status::internal(error.to_string()))?;
        Ok(Response::new(controller::GetRuleHitCountsReply { hit_counts }))
    }

    async fn shutdown(
        &self,
        _request: Request<controller::ShutdownRequest>,
    ) -> Result<Response<controller::ShutdownReply>, Status> {
        send_shutdown(&self.shutdown_sender);
        Ok(Response::new(controller::ShutdownReply {}))
    }
}

pub(crate) async fn shutdown_signal(shutdown_rx: oneshot::Receiver<()>) {
    let _ = shutdown_rx.await;
}

pub(crate) fn send_shutdown(shutdown_sender: &Arc<Mutex<Option<oneshot::Sender<()>>>>) {
    if let Ok(mut sender) = shutdown_sender.lock() {
        if let Some(sender) = sender.take() {
            let _ = sender.send(());
        }
    }
}
