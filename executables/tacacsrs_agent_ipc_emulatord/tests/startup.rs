use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

use tacacsrs_agent_ipc_emulator::MockControllerClient;
use tacacsrs_ipc::IpcEndpoint;

fn daemon() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tacacsrs-agent-ipc-emulatord"));
    command.arg("--quiet").kill_on_drop(true);
    command
}

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../libraries/tacacsrs_agent_ipc_emulator/examples")
        .join(name)
}

#[tokio::test]
async fn startup_errors_print_no_endpoint_and_leave_no_socket() {
    for (policy, data, message) in [
        (PathBuf::from("tests/fixtures/invalid.rego"), None, "Failed to start"),
        (example("policy.rego"), Some("tests/fixtures/invalid.json"), "Failed to load"),
        (example("policy.rego"), Some("tests/fixtures/array.json"), "Failed to start"),
    ] {
        let socket = format!("./emulatord-invalid-{}.sock", std::process::id());
        let mut command = daemon();
        command
            .arg("--policy")
            .arg(policy)
            .arg("--listen-endpoint")
            .arg(&socket);
        if let Some(data) = data {
            command.arg("--data").arg(data);
        }
        let output = timeout(Duration::from_secs(5), command.output())
            .await
            .unwrap()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr).unwrap().contains(message));
        assert!(!std::path::Path::new(&socket).exists());
    }
}

#[tokio::test]
async fn daemon_reports_bound_endpoints_and_accepts_controller_shutdown() {
    let socket = format!("./emulatord-valid-{}.sock", std::process::id());
    for listen in ["127.0.0.1:0", socket.as_str()] {
        let mut child = daemon()
            .arg("--policy")
            .arg(example("policy.rego"))
            .arg("--data")
            .arg(example("policy_data.json"))
            .arg("--listen-endpoint")
            .arg(listen)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();
        let bound = timeout(Duration::from_secs(5), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .expect("the daemon must print its bound endpoint");
        let endpoint = bound.parse::<IpcEndpoint>().unwrap();
        if let IpcEndpoint::Tcp(address) = &endpoint {
            assert_ne!(address.port(), 0);
            assert!(address.ip().is_loopback());
        } else {
            assert_eq!(bound, socket);
        }
        let mut controller = MockControllerClient::connect(endpoint).await.unwrap();
        assert!(controller.captured_requests().await.unwrap().is_empty());
        controller.shutdown().await.unwrap();
        drop(controller);
        assert!(timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success());
    }
    assert!(!std::path::Path::new(&socket).exists());
}
