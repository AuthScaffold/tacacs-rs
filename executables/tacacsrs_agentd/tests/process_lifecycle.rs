//! Native host-signal and startup-cancellation regressions.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

struct ProcessDirectory(PathBuf);

impl ProcessDirectory {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("tacacsrs-process-{}-{unique}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for ProcessDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn agent() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tacacsrs-agentd"));
    command
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
}

async fn wait_for_signal_registration(child: &mut Child) {
    let process = child.id().unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                let mut error = String::new();
                child
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut error)
                    .await
                    .unwrap();
                panic!("agent exited before signal registration ({status}): {error}");
            }
            let status = tokio::fs::read_to_string(format!("/proc/{process}/status"))
                .await
                .unwrap();
            let caught = status
                .lines()
                .find_map(|line| line.strip_prefix("SigCgt:"))
                .map(|value| u64::from_str_radix(value.trim(), 16).unwrap())
                .unwrap();
            if caught & ((1 << 1) | (1 << 14)) == ((1 << 1) | (1 << 14)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("daemon must register host signals before bootstrap");
}

async fn stop(child: Child, signal: &str) {
    let status = Command::new("kill")
        .arg(signal)
        .arg(child.id().unwrap().to_string())
        .status()
        .await
        .unwrap();
    assert!(status.success());
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .expect("host signal must stop and join the daemon")
        .unwrap();
    assert!(
        output.status.success(),
        "daemon exited with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn host_signals_cancel_blocked_bootstrap_without_binding() {
    for signal in ["-TERM", "-INT"] {
        let directory = ProcessDirectory::new();
        let endpoint = directory.0.join("agent.sock");
        let mut child = agent()
            .args([
                "--sonic",
                "--sonic-redis-url",
                "redis://127.0.0.1:9",
                "--service-mode",
                "both",
                "--host-integration",
                "none",
                "--listen-endpoint",
            ])
            .arg(&endpoint)
            .spawn()
            .unwrap();
        wait_for_signal_registration(&mut child).await;
        stop(child, signal).await;
        assert!(!endpoint.exists());
    }
}

#[tokio::test]
async fn host_signal_drains_a_serving_agent_and_closes_idle_ipc_connection() {
    let directory = ProcessDirectory::new();
    let endpoint = directory.0.join("agent.sock");
    let policy = directory.0.join("policy.json");
    tokio::fs::write(&policy, br#"{"tacacsrs:runtime-policy":{"authentication":{"request-timeout-seconds":1},"authorization":{"request-timeout-seconds":1},"accounting":{"request-timeout-seconds":1}}}"#).await.unwrap();
    let mut child = agent()
        .args([
            "--server-addr",
            "192.0.2.10:49",
            "--shared-secret",
            "test-secret",
            "--host-integration",
            "none",
            "--listen-endpoint",
        ])
        .arg(&endpoint)
        .arg("--runtime-policy")
        .arg(policy)
        .spawn()
        .unwrap();
    wait_for_signal_registration(&mut child).await;
    let mut connection = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(child.try_wait().unwrap().is_none(), "agent exited before listening");
            if let Ok(connection) = tokio::net::UnixStream::connect(&endpoint).await {
                return connection;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("agent must bind its endpoint");
    stop(child, "-TERM").await;
    let mut buffer = [0; 1024];
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match connection.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await
    .expect("shutdown must close the held IPC transport");
    assert!(!endpoint.exists());
}
