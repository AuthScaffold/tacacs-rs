//! Native host-signal and startup-cancellation regressions.

use std::path::PathBuf;
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
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
        Self::with_timestamp(unique)
    }

    fn with_timestamp(timestamp: u128) -> Self {
        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
        loop {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("tacacsrs-process-{}-{timestamp}-{sequence}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("could not create process test directory: {error}"),
            }
        }
    }
}

impl Drop for ProcessDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

#[test]
fn process_directories_are_unique_when_clock_timestamps_match() {
    let first = ProcessDirectory::with_timestamp(0);
    let second = ProcessDirectory::with_timestamp(0);
    assert_ne!(first.0, second.0);
    assert!(first.0.is_dir());
    assert!(second.0.is_dir());
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
async fn statistics_export_is_read_only_private_and_generation_bound() {
    let directory = ProcessDirectory::new();
    let endpoint = directory.0.join("agent.sock");
    let output = directory.0.join("statistics.json");
    let mut child = agent()
        .args([
            "--server-addr",
            "192.0.2.10:49",
            "--shared-secret",
            "private-test-key",
            "--host-integration",
            "none",
            "--listen-endpoint",
        ])
        .arg(&endpoint)
        .arg("--statistics-file")
        .arg(&output)
        .spawn()
        .unwrap();
    wait_for_signal_registration(&mut child).await;
    let data = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(child.try_wait().unwrap().is_none());
            if let Ok(data) = tokio::fs::read_to_string(&output).await {
                break data;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&data).unwrap();
    let root = &json["ietf-system-tacacs-plus:tacacs-plus"];
    assert!(root["tacacsrs:runtime-generation"].is_string());
    assert!(root["server"][0]["tacacsrs:counter-epoch"].is_string());
    assert_eq!(root["server"][0]["statistics"]["connection-opens"], "0");
    assert!(root["server"][0]["statistics"]["discontinuity-time"].is_string());
    assert!(!data.contains("private-test-key") && !data.contains("shared-secret"));
    assert_eq!(
        tokio::fs::metadata(&output)
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    stop(child, "-TERM").await;
    assert!(!endpoint.exists());
    assert!(output.exists());
    assert!(!std::fs::read_dir(&directory.0).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .ends_with(".tmp")));
}

#[tokio::test]
async fn diagnostics_rpc_is_read_only_and_generation_bound() {
    use tacacsrs_ipc::diagnostics::DiagnosticsClient;
    use tacacsrs_ipc::IpcEndpoint;

    let directory = ProcessDirectory::new();
    let endpoint = directory.0.join("agent.sock");
    let mut child = agent()
        .args([
            "--server-addr",
            "192.0.2.10:49",
            "--shared-secret",
            "private-test-key",
            "--host-integration",
            "none",
            "--listen-endpoint",
        ])
        .arg(&endpoint)
        .spawn()
        .unwrap();
    let client = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(child.try_wait().unwrap().is_none());
            if let Ok(client) =
                DiagnosticsClient::connect(IpcEndpoint::Unix(endpoint.clone())).await
            {
                break client;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let first = client.statistics_json(None).await.unwrap();
    let first: serde_json::Value = serde_json::from_str(&first).unwrap();
    let root = &first["ietf-system-tacacs-plus:tacacs-plus"];
    let server = root["server"][0]["name"].as_str().unwrap();
    for selection in [None, Some(server)] {
        let data = client.statistics_json(selection).await.unwrap();
        assert!(!data.contains("private-test-key") && !data.contains("shared-secret"));
        let json: serde_json::Value = serde_json::from_str(&data).unwrap();
        let snapshot = &json["ietf-system-tacacs-plus:tacacs-plus"];
        assert_eq!(snapshot["server"].as_array().unwrap().len(), 1);
        assert_eq!(snapshot["tacacsrs:runtime-generation"], root["tacacsrs:runtime-generation"]);
        assert_eq!(
            snapshot["server"][0]["tacacsrs:counter-epoch"],
            root["server"][0]["tacacsrs:counter-epoch"]
        );
        assert_eq!(snapshot["server"][0]["statistics"]["connection-opens"], "0");
        assert_eq!(snapshot["server"][0]["statistics"]["messages-sent"], "0");
    }
    drop(client);
    stop(child, "-TERM").await;
    assert!(!endpoint.exists());
}

#[tokio::test]
async fn statistics_export_failure_stops_the_supervised_daemon() {
    let directory = ProcessDirectory::new();
    let endpoint = directory.0.join("agent.sock");
    let report = directory.0.join("statistics.json");
    let mut child = agent()
        .args([
            "--server-addr",
            "192.0.2.10:49",
            "--shared-secret",
            "secret",
            "--host-integration",
            "none",
            "--listen-endpoint",
        ])
        .arg(&endpoint)
        .arg("--statistics-file")
        .arg(&report)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !report.exists() {
            assert!(child.try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    tokio::fs::remove_file(&report).await.unwrap();
    tokio::fs::create_dir(&report).await.unwrap();
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("operational statistics"));
    assert!(!endpoint.exists());
}

#[tokio::test]
async fn statistics_export_cannot_replace_inputs_or_listener() {
    let directory = ProcessDirectory::new();
    let config = directory.0.join("config.json");
    let original = b"operator configuration remains unchanged";
    tokio::fs::write(&config, original).await.unwrap();
    let output = agent()
        .arg("--config")
        .arg(&config)
        .arg("--statistics-file")
        .arg(&config)
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot overwrite"));
    assert_eq!(tokio::fs::read(&config).await.unwrap(), original);
    let socket = directory.0.join("agent.sock");
    let output = agent()
        .args([
            "--server-addr",
            "192.0.2.10:49",
            "--shared-secret",
            "secret",
            "--host-integration",
            "none",
            "--listen-endpoint",
        ])
        .arg(&socket)
        .arg("--statistics-file")
        .arg(&socket)
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot replace a listener"));
    assert!(!socket.exists());
}

#[tokio::test]
async fn host_signals_cancel_blocked_bootstrap_without_binding() {
    for signal in ["-TERM", "-INT"] {
        let directory = ProcessDirectory::new();
        let endpoint = directory.0.join("agent.sock");
        let redis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redis_url = format!("redis://{}", redis.local_addr().unwrap());
        let child = agent()
            .args([
                "--sonic",
                "--sonic-redis-url",
                &redis_url,
                "--service-mode",
                "both",
                "--host-integration",
                "none",
                "--listen-endpoint",
            ])
            .arg(&endpoint)
            .spawn()
            .unwrap();
        // QEMU catches host signals before the guest installs its handlers.
        // Observe guest bootstrap IO instead, and leave its Redis request blocked.
        let (mut connection, _) = tokio::time::timeout(Duration::from_secs(5), redis.accept())
            .await
            .expect("daemon must start Redis bootstrap")
            .unwrap();
        let mut request = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), connection.read(&mut request))
                .await
                .expect("daemon must send a Redis request")
                .unwrap(),
            1
        );
        stop(child, signal).await;
        assert!(!endpoint.exists());
    }
}

#[tokio::test]
async fn invalid_http_registration_fails_before_sonic_bootstrap() {
    let directory = ProcessDirectory::new();
    let endpoint = directory.0.join("agent.sock");
    let url = "https://example.test/crl?token=private-value";
    let child = agent()
        .args([
            "--sonic",
            "--sonic-redis-url",
            "redis://127.0.0.1:9",
            "--host-integration",
            "none",
            "--http-crl-source",
            "private-reference",
            url,
            "--listen-endpoint",
        ])
        .arg(&endpoint)
        .spawn()
        .unwrap();
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("CRL locations cannot contain"));
    assert!(
        !error.contains(url)
            && !error.contains("private-reference")
            && !error.contains("private-value")
    );
    assert!(!endpoint.exists());
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

#[tokio::test]
async fn shutdown_budget_terminates_a_stalled_systemd_helper() {
    let directory = ProcessDirectory::new();
    let endpoint = directory.0.join("agent.sock");
    let policy = directory.0.join("policy.json");
    let helper = directory.0.join("systemd-notify");
    let helper_pid = directory.0.join("helper.pid");
    tokio::fs::write(&policy, br#"{"tacacsrs:runtime-policy":{"shutdown-timeout-seconds":1}}"#)
        .await
        .unwrap();
    tokio::fs::write(
        &helper,
        b"#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$TACACSRS_HELPER_PID\"\nexec /bin/sleep 60\n",
    )
    .await
    .unwrap();
    tokio::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    let paths = std::env::join_paths(
        std::iter::once(directory.0.clone())
            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let mut child = agent()
        .args([
            "--server-addr",
            "192.0.2.10:49",
            "--shared-secret",
            "test-secret",
            "--host-integration",
            "systemd",
            "--listen-endpoint",
        ])
        .arg(&endpoint)
        .arg("--runtime-policy")
        .arg(&policy)
        .env("PATH", paths)
        .env("NOTIFY_SOCKET", directory.0.join("notify.sock"))
        .env("TACACSRS_HELPER_PID", &helper_pid)
        .spawn()
        .unwrap();
    wait_for_signal_registration(&mut child).await;
    let helper_process = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(pid) = tokio::fs::read_to_string(&helper_pid).await {
                if let Ok(pid) = pid.trim().parse::<u32>() {
                    return pid;
                }
            }
            assert!(child.try_wait().unwrap().is_none(), "daemon exited before helper start");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("systemd helper must start");
    assert!(Command::new("kill")
        .arg("-TERM")
        .arg(child.id().unwrap().to_string())
        .status()
        .await
        .unwrap()
        .success());
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .expect("stalled helper must not hold process shutdown open")
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Shutdown deadline elapsed"));
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match tokio::fs::read_to_string(format!("/proc/{helper_process}/status")).await {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Ok(status)
                    if status
                        .lines()
                        .any(|line| line.starts_with("State:") && line.contains('Z')) =>
                {
                    break
                }
                Ok(_) => tokio::time::sleep(Duration::from_millis(5)).await,
                Err(error) => panic!("read helper state: {error}"),
            }
        }
    })
    .await
    .expect("owned helper must be terminated on timeout");
    assert!(!endpoint.exists());
}
