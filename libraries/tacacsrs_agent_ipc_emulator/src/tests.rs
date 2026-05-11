use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::json;
use tacacsrs_agent_client::{
    AccountingOperation, AuthorizationKey, AuthorizationOperation, AuthorizationResponseStatus,
    ServiceClient,
};

use crate::state::EmulatorState;
use crate::{
    EmulatorResponse, EmulatorScenario, IpcEmulator, IpcRpc, MatchFields, MockControllerClient,
    ResponseBody, TransactionRule,
};

fn accounting_request(user: &str, command: &str) -> AccountingOperation {
    AccountingOperation {
        user: user.to_owned(),
        port: "tty0".to_owned(),
        remote_address: "127.0.0.1".to_owned(),
        command: command.to_owned(),
        command_arguments: vec!["brief".to_owned()],
    }
}

fn accounting_success_rule(user: &str, server: &str) -> TransactionRule {
    TransactionRule {
        rpc: IpcRpc::Accounting,
        match_fields: MatchFields {
            fields: BTreeMap::from([("user".to_owned(), json!(user))]),
        },
        respond: EmulatorResponse::Response(ResponseBody {
            server: server.to_owned(),
            status: "Success".to_owned(),
            server_message: String::new(),
            data: String::new(),
            args: Vec::new(),
        }),
        delay_ms: None,
    }
}

#[test]
fn parses_json_scenario() {
    let scenario: EmulatorScenario = serde_json::from_str(
        r#"{
            "transactions": [{
                "rpc": "Accounting",
                "match": { "user": "admin", "command": "show" },
                "respond": {
                    "type": "response",
                    "server": "tacacs-primary:49",
                    "status": "Success",
                    "server_message": "ok",
                    "data": ""
                },
                "delay_ms": 5
            }]
        }"#,
    )
    .expect("scenario should parse");

    assert_eq!(scenario.transactions.len(), 1);
    assert_eq!(scenario.transactions[0].rpc, IpcRpc::Accounting);
    assert_eq!(scenario.transactions[0].delay_ms, Some(5));
}

#[test]
fn partial_matching_uses_only_present_fields() {
    let match_fields = MatchFields {
        fields: BTreeMap::from([("user".to_owned(), json!("admin"))]),
    };
    let request_fields = BTreeMap::from([
        ("user".to_owned(), json!("admin")),
        ("command".to_owned(), json!("show")),
    ]);

    assert!(match_fields.matches(&request_fields));
}

#[test]
fn rules_are_evaluated_in_order() {
    let mut state = EmulatorState::new(EmulatorScenario {
        transactions: vec![
            accounting_success_rule("admin", "first"),
            accounting_success_rule("admin", "second"),
        ],
    });

    let fields = BTreeMap::from([("user".to_owned(), json!("admin"))]);
    let matched = state
        .record_and_match(IpcRpc::Accounting, &fields)
        .expect("rule should match");

    match matched.response {
        EmulatorResponse::Response(response) => assert_eq!(response.server, "first"),
        EmulatorResponse::Error(_) => panic!("expected response"),
    }
    assert_eq!(state.rule_hit_counts()[0].hits, 1);
    assert_eq!(state.rule_hit_counts()[1].hits, 0);
}

#[tokio::test]
async fn delay_is_applied_before_response() {
    let scenario = EmulatorScenario {
        transactions: vec![TransactionRule {
            delay_ms: Some(25),
            ..accounting_success_rule("admin", "primary")
        }],
    };
    let (emulator, endpoint) = IpcEmulator::from_scenario(scenario)
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
async fn captures_requests_and_hit_counts() {
    let scenario = EmulatorScenario {
        transactions: vec![accounting_success_rule("admin", "primary")],
    };
    let (emulator, endpoint) = IpcEmulator::from_scenario(scenario)
        .await
        .expect("emulator should start");
    let client = ServiceClient::connect(endpoint)
        .await
        .expect("client should connect");

    client
        .send_accounting(accounting_request("admin", "show"))
        .await
        .expect("request should succeed");

    let captured = emulator.captured_requests();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].rpc, IpcRpc::Accounting);
    assert_eq!(captured[0].fields["user"], json!("admin"));
    assert_eq!(emulator.rule_hits()[0].hits, 1);
    emulator.shutdown().await;
}

#[tokio::test]
async fn unmatched_request_returns_grpc_error() {
    let scenario = EmulatorScenario {
        transactions: vec![accounting_success_rule("admin", "primary")],
    };
    let (emulator, endpoint) = IpcEmulator::from_scenario(scenario)
        .await
        .expect("emulator should start");
    let client = ServiceClient::connect(endpoint)
        .await
        .expect("client should connect");

    let error = client
        .send_accounting(accounting_request("guest", "show"))
        .await
        .expect_err("unmatched request should fail");

    assert!(error
        .to_string()
        .contains("Failed to execute accounting RPC"));
    assert_eq!(emulator.captured_requests().len(), 1);
    assert_eq!(emulator.rule_hits()[0].hits, 0);
    emulator.shutdown().await;
}

#[tokio::test]
async fn authorization_response_works_with_service_client() {
    let scenario = EmulatorScenario {
        transactions: vec![TransactionRule {
            rpc: IpcRpc::Authorization,
            match_fields: MatchFields {
                fields: BTreeMap::from([("command".to_owned(), json!("show"))]),
            },
            respond: EmulatorResponse::Response(ResponseBody {
                server: "primary".to_owned(),
                status: "PassAdd".to_owned(),
                server_message: String::new(),
                data: String::new(),
                args: Vec::new(),
            }),
            delay_ms: None,
        }],
    };
    let (emulator, endpoint) = IpcEmulator::from_scenario(scenario)
        .await
        .expect("emulator should start");
    let client = ServiceClient::connect(endpoint)
        .await
        .expect("client should connect");
    let request = AuthorizationOperation::builder("admin", 15)
        .port("tty0")
        .remote_address("127.0.0.1")
        .key_value(AuthorizationKey::Service, true, "shell")
        .key_value(AuthorizationKey::Cmd, true, "show")
        .build()
        .expect("authorization operation should build");

    let response = client
        .send_authorization(request)
        .await
        .expect("authorization request should succeed");

    assert_eq!(response.status, AuthorizationResponseStatus::PassAdd);
    assert_eq!(emulator.rule_hits()[0].hits, 1);
    emulator.shutdown().await;
}

#[tokio::test]
async fn controller_can_reset_and_replace_state() {
    let scenario = EmulatorScenario {
        transactions: vec![accounting_success_rule("admin", "primary")],
    };
    let (emulator, endpoint) = IpcEmulator::from_scenario(scenario)
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
    assert_eq!(controller.rule_hits().await.expect("hits should load")[0].hits, 1);

    controller
        .reset_state()
        .await
        .expect("reset should succeed");
    assert!(controller
        .captured_requests()
        .await
        .expect("captures should load")
        .is_empty());
    assert_eq!(controller.rule_hits().await.expect("hits should load")[0].hits, 0);

    controller
        .load_scenario(&EmulatorScenario {
            transactions: vec![accounting_success_rule("guest", "secondary")],
        })
        .await
        .expect("load should succeed");
    client
        .send_accounting(accounting_request("guest", "show"))
        .await
        .expect("new scenario should match");
    assert_eq!(controller.rule_hits().await.expect("hits should load")[0].hits, 1);
    emulator.shutdown().await;
}
