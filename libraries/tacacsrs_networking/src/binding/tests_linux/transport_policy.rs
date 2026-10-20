use super::*;

pub(super) async fn run() {
    if std::env::var_os("TACACSRS_BINDING_LAB_READONLY").is_some() {
        return;
    }
    let range = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").unwrap();
    let ports = range.split_whitespace().collect::<Vec<_>>().join("-");
    for (family, destination, prefix, source, gateway) in [
        ("-4", "198.51.100.49:49490", "198.51.100.49/32", "198.18.1.1", "198.18.1.2"),
        (
            "-6",
            "[2001:db8:ffff::49]:49490",
            "2001:db8:ffff::49/128",
            "2001:db8:4::1",
            "2001:db8:4::2",
        ),
    ] {
        // No general route through standalone0 remains. Only the TCP rule
        // with the real source/destination ports can select its usable route.
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
        ip(&[
            family,
            "route",
            "add",
            "unreachable",
            prefix,
            "table",
            "210",
        ]);
        ip(&[
            family,
            "route",
            "add",
            prefix,
            "via",
            gateway,
            "dev",
            "standalone0",
            "table",
            "211",
        ]);
        ip(&[
            family, "rule", "add", "priority", "30", "ipproto", "udp", "dport", "49490", "lookup",
            "210",
        ]);
        ip(&[
            family,
            "rule",
            "add",
            "priority",
            "31",
            "oif",
            "standalone0",
            "ipproto",
            "tcp",
            "sport",
            &ports,
            "dport",
            "49490",
            "lookup",
            "211",
        ]);
        let destination: SocketAddr = destination.parse().unwrap();
        let udp = tokio::net::UdpSocket::bind(SocketAddr::new(source.parse().unwrap(), 0))
            .await
            .unwrap();
        assert!(
            udp.connect(destination).await.is_err(),
            "UDP route probing must disagree with TCP in this fixture"
        );
        for choice in [
            None,
            Some(SourceBinding::Ip(source.parse().unwrap())),
            Some(SourceBinding::Interface("standalone0".to_owned())),
        ] {
            for policy in [BindingPolicy::Strict, BindingPolicy::BestEffort] {
                let binding =
                    LocalBinding::new(choice.clone(), Some("standalone0"), None, policy).unwrap();
                let warnings = warning_count();
                assert_eq!(
                    receive(destination, &binding).await.unwrap(),
                    format!("{source} stand-peer\n")
                );
                assert_eq!(
                    warning_count(),
                    warnings,
                    "TCP-specific policy must not cause egress relaxation"
                );
            }
        }
        println!("PASS {family}: TCP protocol and real port-range rules honored while no-send UDP probe rejects");
        // IPv4 can attempt direct neighbor delivery when a bound device has no
        // route. Only IPv6 guarantees a local no-route error for this fixture.
        if family == "-4" {
            continue;
        }
        ip(&[
            family,
            "route",
            "del",
            "unreachable",
            prefix,
            "table",
            "210",
        ]);
        ip(&[
            family,
            "route",
            "add",
            prefix,
            "via",
            gateway,
            "dev",
            "standalone0",
            "table",
            "210",
        ]);
        ip(&[family, "route", "del", prefix, "table", "211"]);
        ip(&[
            family,
            "route",
            "add",
            "unreachable",
            prefix,
            "table",
            "211",
        ]);
        let udp = tokio::net::UdpSocket::bind(SocketAddr::new(source.parse().unwrap(), 0))
            .await
            .unwrap();
        udp.connect(destination).await.unwrap();
        let control = tokio::net::TcpSocket::new_v6().unwrap();
        control.bind_device(Some(b"standalone0")).unwrap();
        control
            .bind(SocketAddr::new(source.parse().unwrap(), 0))
            .unwrap();
        let error = tokio::time::timeout(Duration::from_secs(3), control.connect(destination))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NetworkUnreachable);
        for (choice, expected_source) in [
            (
                None,
                if family == "-4" {
                    "203.0.113.1"
                } else {
                    "2001:db8:2::1"
                },
            ),
            (Some(SourceBinding::Ip(source.parse().unwrap())), source),
            (Some(SourceBinding::Interface("standalone0".to_owned())), source),
        ] {
            let strict =
                LocalBinding::new(choice.clone(), Some("standalone0"), None, BindingPolicy::Strict)
                    .unwrap();
            let error = receive(destination, &strict).await.unwrap_err();
            assert!(error.downcast_ref::<Unavailable>().is_some(), "{error:#}");
            let best =
                LocalBinding::new(choice, Some("standalone0"), None, BindingPolicy::BestEffort)
                    .unwrap();
            let warnings = warning_count();
            assert_eq!(
                receive(destination, &best).await.unwrap(),
                format!("{expected_source} data-peer\n")
            );
            assert_eq!(warning_count() - warnings, 1);
        }
        println!("PASS {family}: actual TCP-only no-route failure permits egress-only fallback even when UDP connects");
    }
}
