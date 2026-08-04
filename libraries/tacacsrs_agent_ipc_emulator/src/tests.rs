use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::json;
use tacacsrs_agent_client::{
    AccountingOperation, AuthorizationKey, AuthorizationOperation, AuthorizationResponseStatus,
    ServiceClient,
};
use tonic::Code;

use crate::policy::EmulatorResponse;
use crate::state::EmulatorState;
use crate::{EmulatorPolicy, IpcEmulator, IpcRpc, MockControllerClient};

const ACCOUNTING_POLICY: &str = r#"
package tacacs.emulator
import rego.v1

decision := {
    "type": "response",
    "server": "primary",
    "status": "Success",
    "server_message": "",
    "data": "",
} if {
    input.rpc == "Accounting"
    input.user == "admin"
}
"#;

const AUTHORIZATION_POLICY: &str = r#"
package tacacs.emulator
import rego.v1

decision := {
    "type": "response",
    "server": "primary",
    "status": status,
    "server_message": message,
    "data": "",
    "args": [],
} if {
    input.rpc == "Authorization"
    input.command == "show"
}

status := "Error" if {
    data.error_mode
} else := "PassAdd"

message := "authorization policy evaluation failed" if {
    data.error_mode
} else := ""
"#;

fn accounting_request(user: &str, command: &str) -> AccountingOperation {
    AccountingOperation {
        user: user.to_owned(),
        port: "tty0".to_owned(),
        remote_address: "127.0.0.1".to_owned(),
        command: command.to_owned(),
        command_arguments: vec!["brief".to_owned()],
    }
}

fn authorization_request(command: &str) -> AuthorizationOperation {
    AuthorizationOperation::builder(
        "admin",
        15,
        tacacsrs_agent_client::AuthorizationAuthenticationContext::TacacsAscii,
    )
    .port("tty0")
    .remote_address("127.0.0.1")
    .key_value(AuthorizationKey::Service, true, "shell")
    .key_value(AuthorizationKey::Cmd, true, command)
    .build()
    .expect("authorization operation should build")
}

fn state_from(rego: &str) -> EmulatorState {
    let policy = EmulatorPolicy::new(rego);
    let engine = policy.compile().expect("policy should compile");
    EmulatorState::new(policy, engine)
}

#[test]
fn compiles_valid_policy() {
    EmulatorPolicy::new(ACCOUNTING_POLICY)
        .compile()
        .expect("valid policy should compile");
}

#[test]
fn rejects_invalid_policy() {
    let error = EmulatorPolicy::new("this is not rego")
        .compile()
        .expect_err("invalid policy should fail to compile");
    assert!(error.to_string().contains("Rego policy"));
}

#[test]
fn evaluates_request_fields_as_input() {
    let mut state = state_from(ACCOUNTING_POLICY);
    let fields = BTreeMap::from([
        ("user".to_owned(), json!("admin")),
        ("command".to_owned(), json!("show")),
    ]);

    let decision = state
        .record_and_evaluate(IpcRpc::Accounting, &fields)
        .expect("evaluation should succeed")
        .expect("policy should produce a decision");

    match decision.response {
        EmulatorResponse::Response(response) => assert_eq!(response.server, "primary"),
        EmulatorResponse::Error(_) => panic!("expected response"),
    }
    assert_eq!(state.captured_requests().len(), 1);
}

#[test]
fn undefined_decision_returns_none() {
    let mut state = state_from(ACCOUNTING_POLICY);
    let fields = BTreeMap::from([("user".to_owned(), json!("guest"))]);

    let decision = state
        .record_and_evaluate(IpcRpc::Accounting, &fields)
        .expect("evaluation should succeed");

    assert!(decision.is_none());
    assert_eq!(state.captured_requests().len(), 1);
}

#[tokio::test]
async fn delay_is_applied_before_response() {
    let policy = EmulatorPolicy::new(
        r#"
package tacacs.emulator
import rego.v1
decision := {
    "type": "response",
    "server": "primary",
    "status": "Success",
    "server_message": "",
    "data": "",
    "delay_ms": 25,
} if input.rpc == "Accounting"
"#,
    );
    let (emulator, endpoint) = IpcEmulator::from_policy(policy)
        .await
        .expect("emulator should start");
    let client = ServiceClient::connect(endpoint)
        .await
        .expect("client should connect");

    let start = Instant::now();
    client
        .send_accounting(accounting_request("admin", "show"))
        .await
        .expect("request should succeed");

    assert!(start.elapsed() >= Duration::from_millis(25));
    emulator.shutdown().await;
}

#[tokio::test]
async fn captures_requests() {
    let (emulator, endpoint) = IpcEmulator::from_policy(EmulatorPolicy::new(ACCOUNTING_POLICY))
        .await
        .expect("emulator should start");
    let client = ServiceClient::connect(endpoint)
        .await
        .expect("client should connect");

    client
        .send_accounting(accounting_request("admin", "show"))
        .await
        .expect("request should succeed");

    let captured = emulator.captured_requests().await;
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].rpc, IpcRpc::Accounting);
    assert_eq!(captured[0].fields["user"], json!("admin"));
    emulator.shutdown().await;
}

#[tokio::test]
async fn undefined_accounting_decision_returns_grpc_error() {
    let (emulator, endpoint) = IpcEmulator::from_policy(EmulatorPolicy::new(ACCOUNTING_POLICY))
        .await
        .expect("emulator should start");
    let client = ServiceClient::connect(endpoint)
        .await
        .expect("client should connect");

    let error = client
        .send_accounting(accounting_request("guest", "show"))
        .await
        .expect_err("undefined accounting decision should fail");

    let grpc_status = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<tonic::Status>())
        .expect("error should include tonic status");
    assert_eq!(grpc_status.code(), Code::NotFound);
    assert!(grpc_status
        .message()
        .contains("policy returned no Accounting decision"));
    assert_eq!(emulator.captured_requests().await.len(), 1);
    emulator.shutdown().await;
}

#[tokio::test]
async fn authorization_response_works_with_service_client() {
    let (emulator, endpoint) = IpcEmulator::from_policy(EmulatorPolicy::new(AUTHORIZATION_POLICY))
        .await
        .expect("emulator should start");
    let client = ServiceClient::connect(endpoint)
        .await
        .expect("client should connect");

    let response = client
        .send_authorization(authorization_request("show"))
        .await
        .expect("authorization request should succeed");

    assert_eq!(response.status, AuthorizationResponseStatus::PassAdd);
    emulator.shutdown().await;
}

#[tokio::test]
async fn undefined_authorization_decision_returns_fail_response() {
    let (emulator, endpoint) = IpcEmulator::from_policy(EmulatorPolicy::new(AUTHORIZATION_POLICY))
        .await
        .expect("emulator should start");
    let client = ServiceClient::connect(endpoint)
        .await
        .expect("client should connect");

    let response = client
        .send_authorization(authorization_request("/usr/bin/htop"))
        .await
        .expect("authorization no-decision should be a TACACS+ response");

    assert_eq!(response.status, AuthorizationResponseStatus::Fail);
    assert_eq!(response.server, "ipc-emulator");
    assert!(response
        .server_message
        .contains("policy returned no authorization decision"));
    assert!(response.server_message.contains("/usr/bin/htop"));
    assert_eq!(emulator.captured_requests().await.len(), 1);
    emulator.shutdown().await;
}

#[tokio::test]
async fn authorization_error_status_returns_response() {
    let policy = EmulatorPolicy::new(AUTHORIZATION_POLICY).with_data(json!({ "error_mode": true }));
    let (emulator, endpoint) = IpcEmulator::from_policy(policy)
        .await
        .expect("emulator should start");
    let client = ServiceClient::connect(endpoint)
        .await
        .expect("client should connect");

    let response = client
        .send_authorization(authorization_request("show"))
        .await
        .expect("authorization Error status should be a TACACS+ response");

    assert_eq!(response.status, AuthorizationResponseStatus::Error);
    assert_eq!(response.server_message, "authorization policy evaluation failed");
    emulator.shutdown().await;
}

#[tokio::test]
async fn policy_data_drives_authorization_denylist() {
    let policy = EmulatorPolicy::from_file("examples/policy.rego")
        .expect("example policy should compile")
        .with_data(
            serde_json::from_str(
                &std::fs::read_to_string("examples/policy_data.json")
                    .expect("example data should load"),
            )
            .expect("example data should parse"),
        );
    let (emulator, endpoint) = IpcEmulator::from_policy(policy)
        .await
        .expect("emulator should start");
    let client = ServiceClient::connect(endpoint)
        .await
        .expect("client should connect");

    let denied = client
        .send_authorization(
            AuthorizationOperation::builder(
                "admin",
                15,
                tacacsrs_agent_client::AuthorizationAuthenticationContext::TacacsAscii,
            )
            .port("tty0")
            .remote_address("127.0.0.1")
            .key_value(AuthorizationKey::Service, true, "shell")
            .key_value(AuthorizationKey::Cmd, true, "/usr/bin/git")
            .key_value(AuthorizationKey::CmdArg, false, "--force")
            .build()
            .expect("authorization operation should build"),
        )
        .await
        .expect("denied request should still return a response");
    assert_eq!(denied.status, AuthorizationResponseStatus::Fail);
    assert!(denied.server_message.contains("--force"));

    let allowed = client
        .send_authorization(authorization_request("/usr/bin/git"))
        .await
        .expect("allowed request should succeed");
    assert_eq!(allowed.status, AuthorizationResponseStatus::PassAdd);
    emulator.shutdown().await;
}

#[tokio::test]
async fn controller_can_reset_and_replace_policy() {
    let (emulator, endpoint) = IpcEmulator::from_policy(EmulatorPolicy::new(ACCOUNTING_POLICY))
        .await
        .expect("emulator should start");
    let client = ServiceClient::connect(endpoint.clone())
        .await
        .expect("client should connect");
    let mut controller = MockControllerClient::connect(endpoint)
        .await
        .expect("controller should connect");

    client
        .send_accounting(accounting_request("admin", "show"))
        .await
        .expect("request should succeed");
    assert_eq!(
        controller
            .captured_requests()
            .await
            .expect("captures should load")
            .len(),
        1
    );

    controller
        .reset_state()
        .await
        .expect("reset should succeed");
    assert!(controller
        .captured_requests()
        .await
        .expect("captures should load")
        .is_empty());

    controller
        .load_policy(&EmulatorPolicy::new(
            r#"
package tacacs.emulator
import rego.v1
decision := {
    "type": "response",
    "server": "secondary",
    "status": "Success",
    "server_message": "",
    "data": "",
} if {
    input.rpc == "Accounting"
    input.user == "guest"
}
"#,
        ))
        .await
        .expect("load should succeed");
    client
        .send_accounting(accounting_request("guest", "show"))
        .await
        .expect("new policy should match");
    let captured = controller
        .captured_requests()
        .await
        .expect("captures should load");
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].fields["user"], json!("guest"));
    emulator.shutdown().await;
}
