use std::collections::BTreeMap;

use serde_json::{json, Value};
use tacacsrs_ipc::proto;
use tacacsrs_protocol::failure::{DeliveryState, FailureCategory, FailureFacts, FailurePhase};
use tacacsrs_protocol::operations::{
    AccountingOperationResponse, AccountingResponseStatus, AuthorizationArg,
    AuthorizationOperationResponse, AuthorizationResponseStatus,
};
use tacacsrs_protocol::failure::ServiceError;
use tonic::Status;

use crate::policy::{ErrorBody, ResponseBody};

pub(crate) fn accounting_fields(request: &proto::AccountingRequest) -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("user".to_owned(), json!(request.user)),
        ("port".to_owned(), json!(request.port)),
        ("remote_address".to_owned(), json!(request.remote_address)),
        ("command".to_owned(), json!(request.command)),
        ("command_arguments".to_owned(), json!(request.command_arguments)),
    ])
}

pub(crate) fn authorization_fields(
    request: &proto::AuthorizationRequest,
) -> BTreeMap<String, Value> {
    let command = request
        .args
        .iter()
        .find(|arg| arg.name == "cmd")
        .map(|arg| arg.value.as_str());
    let command_arguments = request
        .args
        .iter()
        .filter(|arg| arg.name == "cmd-arg")
        .map(|arg| arg.value.clone())
        .collect::<Vec<_>>();
    BTreeMap::from([
        ("user".to_owned(), json!(request.user)),
        ("port".to_owned(), json!(request.port)),
        ("remote_address".to_owned(), json!(request.remote_address)),
        ("privilege_level".to_owned(), json!(request.privilege_level)),
        ("command".to_owned(), command.map_or(Value::Null, |value| json!(value))),
        ("command_arguments".to_owned(), json!(command_arguments)),
        (
            "args".to_owned(),
            Value::Array(
                request
                    .args
                    .iter()
                    .map(|arg| {
                        json!({
                            "name": arg.name,
                            "mandatory": arg.mandatory,
                            "value": arg.value,
                        })
                    })
                    .collect(),
            ),
        ),
    ])
}

pub(crate) fn accounting_response(
    response: ResponseBody,
) -> Result<AccountingOperationResponse, Status> {
    let status = match response.status.as_str() {
        "Success" => AccountingResponseStatus::Success,
        "Error" => AccountingResponseStatus::Error,
        "Follow" => AccountingResponseStatus::Follow,
        status => {
            return Err(Status::failed_precondition(format!(
                "Invalid Accounting response status: {status:?}"
            )));
        }
    };
    Ok(AccountingOperationResponse {
        server: response.server,
        status,
        server_message: response.server_message,
        data: response.data,
    })
}

pub(crate) fn authorization_response(
    response: ResponseBody,
) -> Result<AuthorizationOperationResponse, Status> {
    let status = match response.status.as_str() {
        "PassAdd" => AuthorizationResponseStatus::PassAdd,
        "PassRepl" => AuthorizationResponseStatus::PassRepl,
        "Fail" => AuthorizationResponseStatus::Fail,
        "Error" => AuthorizationResponseStatus::Error,
        "Follow" => AuthorizationResponseStatus::Follow,
        status => {
            return Err(Status::failed_precondition(format!(
                "Invalid Authorization response status: {status:?}"
            )));
        }
    };
    Ok(AuthorizationOperationResponse {
        server: response.server,
        status,
        server_message: response.server_message,
        args: response
            .args
            .into_iter()
            .map(|arg| AuthorizationArg::new(arg.name, arg.mandatory, arg.value))
            .collect(),
        data: response.data,
    })
}

pub(crate) fn service_error(error: ErrorBody) -> ServiceError {
    // The emulator performs no upstream I/O, so every failure is NotSent at the
    // IPC phase. The Rego `retriable` field is a simulation input, not an
    // authoritative retry decision: it only selects a recoverable or terminal
    // category. The domain type derives the retry advice from the facts.
    let category = if error.retriable {
        FailureCategory::Unavailable
    } else {
        FailureCategory::Internal
    };
    let facts = FailureFacts::new(category, FailurePhase::Ipc, DeliveryState::NotSent);
    let mut service_error = ServiceError::new(error.message, facts);
    if !error.server.is_empty() {
        service_error = service_error.with_server(error.server);
    }
    service_error
}

/// Builds the error returned for the unsupported PAP authentication RPC.
///
/// The emulator rejects the local request before any upstream I/O, so the
/// delivery state is `NotSent` and the derived advice is never to replay.
pub(crate) fn pap_unsupported_error() -> ServiceError {
    ServiceError::new(
        "PAP authentication is not supported by the policy emulator",
        FailureFacts::new(
            FailureCategory::InvalidRequest,
            FailurePhase::Ipc,
            DeliveryState::NotSent,
        ),
    )
    .with_server("ipc-emulator")
}
