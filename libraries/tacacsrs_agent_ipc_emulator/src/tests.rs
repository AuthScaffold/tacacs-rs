use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::json;
use tacacsrs_agent_client::{
    AccountingOperation, AuthorizationKey, AuthorizationOperation, AuthorizationResponseStatus,
    ServiceClient,
};
use tonic::Code;

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
        match_any_fields: None,
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

    let captured = emulator.captured_requests().await;
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].rpc, IpcRpc::Accounting);
    assert_eq!(captured[0].fields["user"], json!("admin"));
    assert_eq!(emulator.rule_hits().await[0].hits, 1);
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

    let grpc_status = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<tonic::Status>())
        .expect("error should include tonic status");
    assert_eq!(grpc_status.code(), Code::NotFound);
    assert!(grpc_status
        .message()
        .contains("IPC emulator has no Accounting transaction rule matching"));
    assert_eq!(emulator.captured_requests().await.len(), 1);
    assert_eq!(emulator.rule_hits().await[0].hits, 0);
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
            match_any_fields: None,
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
    assert_eq!(emulator.rule_hits().await[0].hits, 1);
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

#[test]
fn match_any_matches_when_array_contains_value() {
    let match_any = MatchFields {
        fields: BTreeMap::from([("command_arguments".to_owned(), json!("--force"))]),
    };
    let request_fields = BTreeMap::from([
        ("command".to_owned(), json!("/usr/bin/git")),
        ("command_arguments".to_owned(), json!(["push", "--force", "origin"])),
    ]);

    assert!(match_any.matches_any(&request_fields));
}

#[test]
fn match_any_rejects_when_array_does_not_contain_value() {
    let match_any = MatchFields {
        fields: BTreeMap::from([("command_arguments".to_owned(), json!("--force"))]),
    };
    let request_fields = BTreeMap::from([
        ("command".to_owned(), json!("/usr/bin/git")),
        ("command_arguments".to_owned(), json!(["push", "origin", "main"])),
    ]);

    assert!(!match_any.matches_any(&request_fields));
}

#[test]
fn match_any_requires_all_values_when_array() {
    let match_any = MatchFields {
        fields: BTreeMap::from([("command_arguments".to_owned(), json!(["push", "--force"]))]),
    };

    // Contains both "push" and "--force" → matches.
    let with_both =
        BTreeMap::from([("command_arguments".to_owned(), json!(["push", "--force", "origin"]))]);
    assert!(match_any.matches_any(&with_both));

    // Contains "push" but not "--force" → no match.
    let missing_force =
        BTreeMap::from([("command_arguments".to_owned(), json!(["push", "origin"]))]);
    assert!(!match_any.matches_any(&missing_force));

    // Contains "--force" but not "push" → no match.
    let missing_push =
        BTreeMap::from([("command_arguments".to_owned(), json!(["commit", "--force"]))]);
    assert!(!match_any.matches_any(&missing_push));
}

#[test]
fn match_any_rejects_when_field_is_not_array() {
    let match_any = MatchFields {
        fields: BTreeMap::from([("command".to_owned(), json!("git"))]),
    };
    let request_fields = BTreeMap::from([("command".to_owned(), json!("/usr/bin/git"))]);

    assert!(!match_any.matches_any(&request_fields));
}

#[test]
fn match_any_combined_with_match_fields() {
    let mut state = EmulatorState::new(EmulatorScenario {
        transactions: vec![TransactionRule {
            rpc: IpcRpc::Authorization,
            match_fields: MatchFields {
                fields: BTreeMap::from([("command".to_owned(), json!("/usr/bin/git"))]),
            },
            match_any_fields: Some(MatchFields {
                fields: BTreeMap::from([("command_arguments".to_owned(), json!("--force"))]),
            }),
            respond: EmulatorResponse::Response(ResponseBody {
                server: "primary".to_owned(),
                status: "Fail".to_owned(),
                server_message: String::new(),
                data: String::new(),
                args: Vec::new(),
            }),
            delay_ms: None,
        }],
    });

    // Should match: command matches and --force is in args.
    let fields_with_force = BTreeMap::from([
        ("command".to_owned(), json!("/usr/bin/git")),
        ("command_arguments".to_owned(), json!(["push", "--force", "origin"])),
    ]);
    assert!(state
        .record_and_match(IpcRpc::Authorization, &fields_with_force)
        .is_ok());

    // Should not match: command matches but --force is absent.
    let fields_without_force = BTreeMap::from([
        ("command".to_owned(), json!("/usr/bin/git")),
        ("command_arguments".to_owned(), json!(["push", "origin", "main"])),
    ]);
    assert!(state
        .record_and_match(IpcRpc::Authorization, &fields_without_force)
        .is_err());
}

#[test]
fn match_any_round_trips_through_json() {
    let rule_json = r#"{
        "rpc": "Authorization",
        "match": { "command": "/usr/bin/git" },
        "match_any": { "command_arguments": "--force" },
        "respond": {
            "type": "response",
            "server": "primary",
            "status": "Fail",
            "server_message": "",
            "args": [],
            "data": ""
        }
    }"#;
    let rule: TransactionRule =
        serde_json::from_str(rule_json).expect("rule with match_any should parse");
    assert!(rule.match_any_fields.is_some());
    assert_eq!(
        rule.match_any_fields.as_ref().unwrap().fields["command_arguments"],
        json!("--force")
    );

    let serialized = serde_json::to_string(&rule).expect("should serialize");
    let deserialized: TransactionRule =
        serde_json::from_str(&serialized).expect("should round-trip");
    assert_eq!(rule, deserialized);
}
