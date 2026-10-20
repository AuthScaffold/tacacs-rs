use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::AsyncReadExt;

use super::*;

mod pinned;
mod multipath;

struct LabLogger(Mutex<Vec<String>>);

static LAB_LOGGER: LabLogger = LabLogger(Mutex::new(Vec::new()));

impl log::Log for LabLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            eprintln!("{}", record.args());
            self.0.lock().unwrap().push(record.args().to_string());
        }
    }

    fn flush(&self) {}
}

fn warning_count() -> usize {
    LAB_LOGGER.0.lock().unwrap().len()
}

fn ip(args: &[&str]) {
    assert!(
        std::process::Command::new("ip")
            .args(args)
            .status()
            .unwrap()
            .success(),
        "{args:?}"
    );
}

async fn receive(destination: SocketAddr, binding: &LocalBinding) -> anyhow::Result<String> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut stream = connect(destination, binding).await?;
        let mut response = String::new();
        stream.read_to_string(&mut response).await?;
        Ok(response)
    })
    .await?
}

#[tokio::test]
async fn missing_device_and_source_obey_policy() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = listener.local_addr().unwrap();
    for (source, device) in [
        (None, Some("trs-missing")),
        (Some(SourceBinding::Ip("192.0.2.249".parse().unwrap())), Some("lo")),
        (Some(SourceBinding::Interface("trs-missing".to_owned())), None),
    ] {
        let strict =
            LocalBinding::new(source.clone(), device, None, BindingPolicy::Strict).unwrap();
        assert!(connect(destination, &strict).await.is_err());
        let best_effort =
            LocalBinding::new(source, device, None, BindingPolicy::BestEffort).unwrap();
        let stream = connect(destination, &best_effort).await.unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert_eq!(peer, stream.local_addr().unwrap());
    }
}

#[tokio::test]
async fn interface_source_uses_destination_family_and_non_vrf_is_invalid() {
    for host in ["127.0.0.1", "::1"] {
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(host.parse().unwrap(), 0))
            .await
            .unwrap();
        let binding = LocalBinding::new(
            Some(SourceBinding::Interface("lo".to_owned())),
            None,
            None,
            BindingPolicy::Strict,
        )
        .unwrap();
        let stream = connect(listener.local_addr().unwrap(), &binding)
            .await
            .unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert_eq!(peer.ip(), host.parse::<IpAddr>().unwrap());
        assert_eq!(peer, stream.local_addr().unwrap());

        let invalid = LocalBinding::new(None, None, Some("lo"), BindingPolicy::BestEffort).unwrap();
        let error = connect(listener.local_addr().unwrap(), &invalid)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not a VRF"));
    }
}

#[tokio::test]
async fn unavailable_routing_discovery_keeps_explicit_source() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let binding = LocalBinding::new(
        Some(SourceBinding::Ip("127.0.0.2".parse().unwrap())),
        Some("trs-missing"),
        None,
        BindingPolicy::BestEffort,
    )
    .unwrap();
    let stream = connect(listener.local_addr().unwrap(), &binding)
        .await
        .unwrap();
    let (_, peer) = listener.accept().await.unwrap();
    assert_eq!(peer.ip(), "127.0.0.2".parse::<IpAddr>().unwrap());
    assert_eq!(peer, stream.local_addr().unwrap());
}

#[tokio::test]
#[ignore = "Run through tests/linux_binding_lab.py in disposable network namespaces"]
async fn namespace_client() {
    assert_eq!(std::env::var("TACACSRS_BINDING_LAB").as_deref(), Ok("1"));
    for (kind, key) in [
        ("net", "TACACSRS_BINDING_ORIGINAL_NETNS"),
        ("user", "TACACSRS_BINDING_ORIGINAL_USERNS"),
    ] {
        let original =
            std::env::var(key).expect("the namespace harness must supply its original namespace");
        let current = std::fs::metadata(format!("/proc/self/ns/{kind}"))
            .unwrap()
            .ino()
            .to_string();
        assert_ne!(original, current, "the lab must not change the original {kind} namespace");
    }
    if std::env::var_os("TACACSRS_BINDING_LAB_READONLY").is_some() {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        assert!(status
            .lines()
            .any(|line| line == "CapEff:\t0000000000000000"));
    }
    log::set_logger(&LAB_LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Warn);
    for destination in ["198.51.100.49:49490", "[2001:db8:ffff::49]:49490"] {
        let destination: SocketAddr = destination.parse().unwrap();
        let mgmt_source = if destination.is_ipv4() {
            "192.0.2.1"
        } else {
            "2001:db8:1::1"
        };
        let data_source = if destination.is_ipv4() {
            "203.0.113.1"
        } else {
            "2001:db8:2::1"
        };
        for source in [
            SourceBinding::Ip(if destination.is_ipv4() {
                "192.0.2.249".parse().unwrap()
            } else {
                "2001:db8:1::249".parse().unwrap()
            }),
            SourceBinding::Interface("missing0".to_owned()),
        ] {
            let binding = LocalBinding::new(
                Some(source),
                Some("mgmt0"),
                Some("mgmt-vrf"),
                BindingPolicy::BestEffort,
            )
            .unwrap();
            assert_eq!(
                receive(destination, &binding).await.unwrap(),
                format!("{mgmt_source} mgmt-peer\n")
            );
        }
        let missing_vrf =
            LocalBinding::new(None, Some("mgmt0"), Some("missing-vrf"), BindingPolicy::BestEffort)
                .unwrap();
        assert_eq!(
            receive(destination, &missing_vrf).await.unwrap(),
            format!("{data_source} data-peer\n")
        );
        for (source, egress, vrf) in [
            (None, Some("mgmt0"), None),
            (None, None, Some("mgmt-vrf")),
            (None, Some("mgmt0"), Some("mgmt-vrf")),
            (
                Some(SourceBinding::Ip(mgmt_source.parse().unwrap())),
                Some("mgmt0"),
                Some("mgmt-vrf"),
            ),
            (Some(SourceBinding::Interface("mgmt0".to_owned())), None, Some("mgmt-vrf")),
        ] {
            let binding = LocalBinding::new(source, egress, vrf, BindingPolicy::Strict).unwrap();
            assert_eq!(
                receive(destination, &binding).await.unwrap(),
                format!("{mgmt_source} mgmt-peer\n")
            );
        }
        // RFC source-interface selects the loopback address, not the egress device.
        let loop_source = if destination.is_ipv4() {
            "198.18.0.1"
        } else {
            "2001:db8:3::1"
        };
        let binding = LocalBinding::new(
            Some(SourceBinding::Interface("source0".to_owned())),
            None,
            None,
            BindingPolicy::Strict,
        )
        .unwrap();
        assert_eq!(
            receive(destination, &binding).await.unwrap(),
            format!("{loop_source} data-peer\n")
        );

        // A present but unrelated interface is invalid, not a fallback opportunity.
        let invalid =
            LocalBinding::new(None, Some("data0"), Some("mgmt-vrf"), BindingPolicy::BestEffort)
                .unwrap();
        assert!(receive(destination, &invalid)
            .await
            .unwrap_err()
            .to_string()
            .contains("does not belong"));
        for policy in [BindingPolicy::BestEffort, BindingPolicy::Strict] {
            for device in ["missing0", "down0"] {
                let missing =
                    LocalBinding::new(None, Some(device), Some("mgmt-vrf"), policy).unwrap();
                let result = receive(destination, &missing).await;
                if policy == BindingPolicy::Strict {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result.unwrap(), format!("{mgmt_source} mgmt-peer\n"));
                }
            }
        }
        // Connection refusal does not remove a valid management binding.
        let refused = SocketAddr::new(destination.ip(), 49491);
        let binding =
            LocalBinding::new(None, Some("mgmt0"), None, BindingPolicy::BestEffort).unwrap();
        let error = connect(refused, &binding).await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::ConnectionRefused
        );
        // The peer rejects management SYNs with ICMP, while the local route remains valid.
        // A mistaken fallback would reach the data-only listener and succeed.
        {
            let rejected = SocketAddr::new(destination.ip(), 49492);
            let binding =
                LocalBinding::new(None, Some("standalone0"), None, BindingPolicy::BestEffort)
                    .unwrap();
            let warnings = warning_count();
            let error = receive(rejected, &binding).await.unwrap_err();
            assert!(error.downcast_ref::<Unavailable>().is_none(), "{error:#}");
            assert!(matches!(
                error
                    .downcast_ref::<io::Error>()
                    .unwrap_or_else(|| panic!("{error:#}"))
                    .kind(),
                io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable
            ));
            assert_eq!(warning_count(), warnings, "remote ICMP must not relax local constraints");
            let data = LocalBinding::new(None, Some("data0"), None, BindingPolicy::Strict).unwrap();
            assert_eq!(
                receive(rejected, &data).await.unwrap(),
                format!("{data_source} data-peer\n")
            );
        }
        let stalled = SocketAddr::new(destination.ip(), 49493);
        let binding =
            LocalBinding::new(None, Some("standalone0"), None, BindingPolicy::BestEffort).unwrap();
        let warnings = warning_count();
        assert!(tokio::time::timeout(Duration::from_millis(100), receive(stalled, &binding))
            .await
            .is_err());
        assert_eq!(warning_count(), warnings, "the shared deadline must not authorize fallback");
        println!(
            "PASS {destination}: IPv4/IPv6 binding, VRF, scoped fallback, and remote ICMP capture"
        );
    }

    if std::env::var_os("TACACSRS_BINDING_LAB_READONLY").is_some() {
        return;
    }
    pinned::run().await;

    // The usable VRF must survive an independent missing or down egress request.
    for (family, destination, prefix, gateway, source) in [
        ("-4", "198.51.100.49:49490", "198.51.100.49/32", "203.0.113.2", "192.0.2.1"),
        (
            "-6",
            "[2001:db8:ffff::49]:49490",
            "2001:db8:ffff::49/128",
            "2001:db8:2::2",
            "2001:db8:1::1",
        ),
    ] {
        ip(&[family, "route", "del", prefix, "dev", "data0"]);
        ip(&[
            family,
            "route",
            "del",
            prefix,
            "dev",
            "standalone0",
            "metric",
            "100",
        ]);
        for egress in ["missing0", "down0"] {
            for source in [None, Some(SourceBinding::Ip(source.parse().unwrap()))] {
                let binding = LocalBinding::new(
                    source,
                    Some(egress),
                    Some("mgmt-vrf"),
                    BindingPolicy::BestEffort,
                )
                .unwrap();
                assert_eq!(
                    receive(destination.parse().unwrap(), &binding)
                        .await
                        .unwrap(),
                    format!(
                        "{} mgmt-peer\n",
                        if family == "-4" {
                            "192.0.2.1"
                        } else {
                            "2001:db8:1::1"
                        }
                    )
                );
            }
        }
        ip(&[
            family, "route", "add", prefix, "via", gateway, "dev", "data0", "metric", "10",
        ]);
        ip(&[
            family,
            "route",
            "add",
            prefix,
            "via",
            if family == "-4" {
                "198.18.1.2"
            } else {
                "2001:db8:4::2"
            },
            "dev",
            "standalone0",
            "metric",
            "100",
        ]);
        println!(
            "PASS {destination}: missing/down egress retained VRF and source without a main route"
        );
    }

    for command in [
        &["-4", "route", "del", "table", "100", "198.51.100.49/32"][..],
        &[
            "-6",
            "route",
            "del",
            "table",
            "100",
            "2001:db8:ffff::49/128",
        ][..],
    ] {
        assert!(std::process::Command::new("ip")
            .args(command)
            .status()
            .unwrap()
            .success());
    }
    for destination in ["198.51.100.49:49490", "[2001:db8:ffff::49]:49490"] {
        let destination: SocketAddr = destination.parse().unwrap();
        // There is deliberately no VRF unreachable default. Linux can fall through to main.
        for source in [
            None,
            Some(SourceBinding::Ip(if destination.is_ipv4() {
                "192.0.2.1".parse().unwrap()
            } else {
                "2001:db8:1::1".parse().unwrap()
            })),
        ] {
            let binding =
                LocalBinding::new(source, None, Some("mgmt-vrf"), BindingPolicy::Strict).unwrap();
            let warnings = warning_count();
            let error = receive(destination, &binding).await.unwrap_err();
            assert!(error.downcast_ref::<Unavailable>().is_some(), "{error:#}");
            assert_eq!(warning_count(), warnings, "strict mode must not relax VRF routing");
        }
        let warnings = warning_count();
        let binding =
            LocalBinding::new(None, None, Some("mgmt-vrf"), BindingPolicy::BestEffort).unwrap();
        let data_source = if destination.is_ipv4() {
            "203.0.113.1"
        } else {
            "2001:db8:2::1"
        };
        assert_eq!(
            receive(destination, &binding).await.unwrap(),
            format!("{data_source} data-peer\n")
        );
        assert!(warning_count() > warnings, "VRF route fallback must warn");
        let unavailable_source = if destination.is_ipv4() {
            "192.0.2.249"
        } else {
            "2001:db8:1::249"
        };
        let binding = LocalBinding::new(
            Some(SourceBinding::Ip(unavailable_source.parse().unwrap())),
            Some("missing0"),
            Some("mgmt-vrf"),
            BindingPolicy::BestEffort,
        )
        .unwrap();
        let warnings = warning_count();
        assert_eq!(
            receive(destination, &binding).await.unwrap(),
            format!("{data_source} data-peer\n")
        );
        assert_eq!(
            warning_count() - warnings,
            3,
            "three independent constraints permit at most four attempts"
        );
        println!("PASS {destination}: strict VRF rejected main-table fall-through without an unreachable default");
    }
    assert!(std::process::Command::new("ip")
        .args(["link", "set", "mgmt0", "down"])
        .status()
        .unwrap()
        .success());
    for policy in [BindingPolicy::BestEffort, BindingPolicy::Strict] {
        let binding = LocalBinding::new(None, Some("mgmt0"), None, policy).unwrap();
        let result = receive("198.51.100.49:49490".parse().unwrap(), &binding).await;
        if policy == BindingPolicy::Strict {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), "203.0.113.1 data-peer\n");
        }
    }
    // An address change is visible to the same prepared native binding.
    let bindings = [
        LocalBinding::new(None, Some("data0"), None, BindingPolicy::Strict).unwrap(),
        LocalBinding::new(
            Some(SourceBinding::Interface("data0".to_owned())),
            None,
            None,
            BindingPolicy::Strict,
        )
        .unwrap(),
    ];
    for binding in &bindings {
        assert_eq!(
            receive("198.51.100.49:49490".parse().unwrap(), binding)
                .await
                .unwrap(),
            "203.0.113.1 data-peer\n"
        );
    }
    for command in [
        &["address", "del", "203.0.113.1/24", "dev", "data0"][..],
        &["address", "add", "203.0.113.10/24", "dev", "data0"][..],
        // Removing the last address can remove routes through that prefix.
        &[
            "route",
            "replace",
            "198.51.100.49/32",
            "via",
            "203.0.113.2",
            "dev",
            "data0",
        ][..],
    ] {
        assert!(std::process::Command::new("ip")
            .args(command)
            .status()
            .unwrap()
            .success());
    }
    for binding in &bindings {
        assert_eq!(
            receive("198.51.100.49:49490".parse().unwrap(), binding)
                .await
                .unwrap(),
            "203.0.113.10 data-peer\n"
        );
    }
}
