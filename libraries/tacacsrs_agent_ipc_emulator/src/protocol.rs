use std::collections::BTreeMap;

use serde_json::{json, Value};
use tacacsrs_agent_client::ipc;
use tacacsrs_agent_client::{
    AccountingOperationResponse, AccountingResponseStatus, AuthorizationArg,
    AuthorizationOperationResponse, AuthorizationResponseStatus, ServiceError,
};
use tonic::Status;

use crate::policy::{ErrorBody, ResponseBody};

pub(crate) fn accounting_fields(request: &ipc::AccountingRequest) -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("user".to_owned(), json!(request.user)),
        ("port".to_owned(), json!(request.port)),
        ("remote_address".to_owned(), json!(request.remote_address)),
        ("command".to_owned(), json!(request.command)),
        ("command_arguments".to_owned(), json!(request.command_arguments)),
    ])
}

pub(crate) fn authorization_fields(request: &ipc::AuthorizationRequest) -> BTreeMap<String, Value> {
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
    let mut service_error = ServiceError::new(error.message).retriable(error.retriable);
    if !error.server.is_empty() {
        service_error = service_error.with_server(error.server);
    }
    service_error
}
