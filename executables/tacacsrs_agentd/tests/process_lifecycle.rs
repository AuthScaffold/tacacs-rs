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
