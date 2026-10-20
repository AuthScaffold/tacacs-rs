use std::time::Duration;

use serde_json::json;

use tacacsrs_ipc::{IpcEndpoint, ServiceClient};
use tacacsrs_ipc::proto;
use tacacsrs_ipc::proto::tacacs_agent_client::TacacsAgentClient;
use tacacsrs_protocol::failure::{DeliveryState, FailurePhase, RetryAdvice};

use super::{ACCOUNTING_POLICY, accounting_request};
use crate::{EmulatorPolicy, IpcEmulator, MockControllerClient};

#[tokio::test]
async fn source_loading_defers_rego_validation() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let source = directory.path().join("policy.rego");
    std::fs::write(&source, "this is not rego").unwrap();
    for policy in [
        EmulatorPolicy::from_file(&source).unwrap(),
        EmulatorPolicy::from_file_async(&source).await.unwrap(),
    ] {
        assert_eq!(policy.rego, "this is not rego");
        assert!(policy.compile().is_err());
    }
    assert!(EmulatorPolicy::from_file(directory.path().join("missing")).is_err());
    assert!(EmulatorPolicy::from_file_async(directory.path().join("missing"))
        .await
        .is_err());
}

#[tokio::test]
async fn data_loading_decodes_json_before_explicit_compilation() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let source = directory.path().join("policy.rego");
    let data = directory.path().join("data.json");
    std::fs::write(&source, ACCOUNTING_POLICY).unwrap();
    std::fs::write(&data, "[]").unwrap();
    let policy = EmulatorPolicy::from_files_async(&source, &data)
        .await
        .unwrap();
    assert_eq!(policy.data, json!([]));
    assert!(policy
        .compile()
        .unwrap_err()
        .to_string()
        .contains("policy data"));

    std::fs::write(&data, "{").unwrap();
    let error = EmulatorPolicy::from_files_async(&source, &data)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Failed to parse"));
    assert!(error.to_string().contains(&data.display().to_string()));
}

#[tokio::test]
async fn invalid_startup_policy_does_not_touch_the_endpoint() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let path = directory.path().join("untouched");
    std::fs::write(&path, "existing endpoint path").unwrap();
    for policy in [
        EmulatorPolicy::new("this is not rego"),
        EmulatorPolicy::new(ACCOUNTING_POLICY).with_data(json!([])),
    ] {
        let result =
            IpcEmulator::from_policy_at_endpoint(policy, IpcEndpoint::Unix(path.clone())).await;
        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "existing endpoint path");
    }
}

#[tokio::test]
async fn rejected_replacements_retain_policy_and_captured_requests() {
    let (emulator, endpoint) = IpcEmulator::from_policy(EmulatorPolicy::new(ACCOUNTING_POLICY))
        .await
        .unwrap();
    let client = ServiceClient::connect(endpoint.clone()).await.unwrap();
    let mut controller = MockControllerClient::connect(endpoint).await.unwrap();
    client
        .send_accounting(accounting_request("admin", "show"))
        .await
        .unwrap();
    for (index, (rego, data)) in [
        ("this is not rego", "{}"),
        (ACCOUNTING_POLICY, "{"),
        (ACCOUNTING_POLICY, "[]"),
    ]
    .into_iter()
    .enumerate()
    {
        let error = controller
            .load_policy_rego(rego.to_owned(), data.to_owned())
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<tonic::Status>().unwrap().code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(controller.captured_requests().await.unwrap().len(), index + 1);
        let response = client
            .send_accounting(accounting_request("admin", "show"))
            .await
            .unwrap();
        assert_eq!(response.server, "primary");
    }
    assert_eq!(emulator.captured_requests().await.len(), 4);
    drop(controller);
    drop(client);
    emulator.shutdown().await;
}

#[tokio::test]
async fn malformed_policy_decisions_preserve_deliberate_grpc_statuses() {
    for (decision, expected) in [
        (r#"{"unexpected": true}"#, "Invalid policy decision"),
        (
            r#"{"type": "response", "server": "primary", "status": "invalid"}"#,
            "Invalid Accounting response status",
        ),
    ] {
        let policy = EmulatorPolicy::new(format!(
            "package tacacs.emulator\nimport rego.v1\ndecision := {decision}"
        ));
        let (emulator, endpoint) = IpcEmulator::from_policy(policy).await.unwrap();
        let mut raw = TacacsAgentClient::new(endpoint.connect_channel().await.unwrap());
        let error = raw
            .accounting(proto::AccountingRequest::default())
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains(expected));
        let client = ServiceClient::connect(endpoint).await.unwrap();
        let error = client
            .send_accounting(accounting_request("admin", "show"))
            .await
            .unwrap_err();
        assert_eq!(error.facts.phase(), FailurePhase::Ipc);
        assert_eq!(error.facts.delivery(), DeliveryState::OutcomeUnknown);
        assert_eq!(error.facts.retry_advice(), RetryAdvice::Never);
        drop(raw);
        drop(client);
        emulator.shutdown().await;
    }
}

#[tokio::test]
async fn raw_authorization_projection_is_not_domain_validation() {
    let policy = EmulatorPolicy::new(
        r#"package tacacs.emulator
import rego.v1
decision := {"type": "response", "server": "primary", "status": "PassAdd"}
"#,
    );
    let (emulator, endpoint) = IpcEmulator::from_policy(policy).await.unwrap();
    let mut raw = TacacsAgentClient::new(endpoint.connect_channel().await.unwrap());
    raw.authorization(proto::AuthorizationRequest {
        privilege_level: 256,
        args: vec![proto::AuthorizationArg {
            name: "invalid=name".to_owned(),
            mandatory: true,
            value: "value".to_owned(),
        }],
        ..Default::default()
    })
    .await
    .unwrap();
    let captured = emulator.captured_requests().await;
    assert_eq!(captured[0].fields["privilege_level"], json!(256));
    assert_eq!(captured[0].fields["args"][0]["name"], json!("invalid=name"));
    drop(raw);
    emulator.shutdown().await;
}

#[tokio::test]
async fn shutdown_preserves_transport_faults_for_connected_clients() {
    let (emulator, endpoint) = IpcEmulator::from_policy(EmulatorPolicy::new(ACCOUNTING_POLICY))
        .await
        .unwrap();
    let client = ServiceClient::connect(endpoint.clone()).await.unwrap();
    let mut controller = MockControllerClient::connect(endpoint).await.unwrap();
    emulator.shutdown().await;

    let error = tokio::time::timeout(
        Duration::from_secs(2),
        client.send_accounting(accounting_request("admin", "show")),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.facts.phase(), FailurePhase::Ipc);
    assert_eq!(error.facts.delivery(), DeliveryState::OutcomeUnknown);
    assert_eq!(error.facts.retry_advice(), RetryAdvice::Never);
    tokio::time::timeout(Duration::from_secs(2), controller.reset_state())
        .await
        .unwrap()
        .expect_err("a stopped controller must return a transport error");
}
