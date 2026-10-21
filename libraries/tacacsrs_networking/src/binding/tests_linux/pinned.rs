use super::*;

fn main_backend_routes(family: &str, add: bool) {
    let (prefix, data, standalone) = if family == "-4" {
        ("198.51.100.49/32", "203.0.113.2", "198.18.1.2")
    } else {
        ("2001:db8:ffff::49/128", "2001:db8:2::2", "2001:db8:4::2")
    };
    for (device, gateway, metric) in [("data0", data, "10"), ("standalone0", standalone, "100")] {
        if add {
            ip(&[
                family, "route", "add", prefix, "via", gateway, "dev", device, "metric", metric,
            ]);
        } else {
            ip(&[
                family, "route", "del", prefix, "dev", device, "metric", metric,
            ]);
        }
    }
}

pub(super) async fn run() {
    let range = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").unwrap();
    let ports = range.split_whitespace().collect::<Vec<_>>().join("-");
    for (family, destination, source, source_prefix, data_source) in [
        ("-4", "198.51.100.49:49490", "192.0.2.1", "192.0.2.1/32", "203.0.113.1"),
        ("-6", "[2001:db8:ffff::49]:49490", "2001:db8:1::1", "2001:db8:1::1/128", "2001:db8:2::1"),
    ] {
        let destination: SocketAddr = destination.parse().unwrap();
        // Only the real ephemeral TCP source port permits this VRF lookup.
        ip(&[
            family, "rule", "add", "priority", "100", "oif", "mgmt-vrf", "ipproto", "tcp", "sport",
            &ports, "dport", "49490", "lookup", "100",
        ]);
        ip(&[
            family,
            "rule",
            "add",
            "priority",
            "101",
            "oif",
            "mgmt-vrf",
            "unreachable",
        ]);
        let warnings = warning_count();
        for policy in [BindingPolicy::Strict, BindingPolicy::BestEffort] {
            let binding = LocalBinding::new(None, None, Some("mgmt-vrf"), policy).unwrap();
            assert_eq!(
                receive(destination, &binding).await.unwrap(),
                format!("{source} mgmt-peer\n"),
            );
        }
        assert_eq!(warning_count(), warnings);
        ip(&[family, "rule", "del", "priority", "101"]);
        ip(&[family, "rule", "del", "priority", "100"]);
        println!("PASS {family}: VRF automatic source selection retains the reserved TCP port");
        // The source-free query sees table 100. TCP must not choose this source
        // later and silently use the higher-priority source rule for main.
        ip(&[
            family,
            "rule",
            "add",
            "priority",
            "100",
            "from",
            source_prefix,
            "ipproto",
            "tcp",
            "sport",
            &ports,
            "dport",
            "49490",
            "lookup",
            "main",
        ]);
        let warnings = warning_count();
        for choice in [
            None,
            Some(SourceBinding::Ip(source.parse().unwrap())),
            Some(SourceBinding::Interface("mgmt0".to_owned())),
        ] {
            for egress in [None, Some("mgmt0")] {
                let binding = LocalBinding::new(
                    choice.clone(),
                    egress,
                    Some("mgmt-vrf"),
                    BindingPolicy::Strict,
                )
                .unwrap();
                match receive(destination, &binding).await {
                    Ok(observation) => {
                        // A strict member lookup can exclude main's different
                        // output device and retain the management route.
                        assert_eq!(egress, Some("mgmt0"));
                        assert_eq!(observation, format!("{source} mgmt-peer\n"));
                    }
                    Err(error) => {
                        assert!(error.downcast_ref::<Unavailable>().is_some(), "{error:#}");
                    }
                }
            }
        }
        assert_eq!(warning_count(), warnings);
        let binding =
            LocalBinding::new(None, None, Some("mgmt-vrf"), BindingPolicy::BestEffort).unwrap();
        assert_eq!(
            receive(destination, &binding).await.unwrap(),
            format!("{data_source} data-peer\n")
        );
        assert_eq!(warning_count() - warnings, 1);
        ip(&[family, "rule", "del", "priority", "100"]);
        println!(
            "PASS {family}: all source choices and TCP tuple rules retain VRF table isolation"
        );

        // Match the actual socket member, not the VRF master. The main route
        // uses the same member but a different gateway, so egress alone is not proof.
        let gateway = if family == "-4" {
            "192.0.2.2"
        } else {
            "2001:db8:1::2"
        };
        let prefix = if family == "-4" {
            "198.51.100.49/32"
        } else {
            "2001:db8:ffff::49/128"
        };
        ip(&[
            family, "route", "add", prefix, "via", gateway, "dev", "mgmt0", "metric", "5",
        ]);
        // The pinned source selects the VRF. The source-free flow selects main.
        for main_present in [true, false] {
            ip(&[
                family,
                "rule",
                "add",
                "priority",
                "98",
                "from",
                source_prefix,
                "oif",
                "mgmt0",
                "lookup",
                "100",
            ]);
            ip(&[
                family, "rule", "add", "priority", "99", "oif", "mgmt0", "lookup", "main",
            ]);
            ip(&[
                family,
                "rule",
                "add",
                "priority",
                "100",
                "oif",
                "mgmt0",
                "unreachable",
            ]);
            if !main_present {
                ip(&[
                    family, "route", "del", prefix, "dev", "mgmt0", "metric", "5",
                ]);
            }
            let warnings = warning_count();
            for choice in [
                SourceBinding::Ip(source.parse().unwrap()),
                SourceBinding::Interface("mgmt0".to_owned()),
            ] {
                for policy in [BindingPolicy::Strict, BindingPolicy::BestEffort] {
                    let binding = LocalBinding::new(
                        Some(choice.clone()),
                        Some("mgmt0"),
                        Some("mgmt-vrf"),
                        policy,
                    )
                    .unwrap();
                    assert_eq!(
                        receive(destination, &binding).await.unwrap(),
                        format!("{source} mgmt-peer\n")
                    );
                }
            }
            assert_eq!(warning_count(), warnings);
            ip(&[family, "rule", "del", "priority", "100"]);
            ip(&[family, "rule", "del", "priority", "99"]);
            ip(&[family, "rule", "del", "priority", "98"]);
            if !main_present {
                ip(&[
                    family, "route", "add", prefix, "via", gateway, "dev", "mgmt0", "metric", "5",
                ]);
            }
        }
        println!("PASS {family}: explicit and interface sources retain from-plus-oif policy without fallback");
        ip(&[
            family,
            "rule",
            "add",
            "priority",
            "100",
            "from",
            source_prefix,
            "oif",
            "mgmt0",
            "ipproto",
            "tcp",
            "sport",
            &ports,
            "dport",
            "49490",
            "lookup",
            "main",
        ]);
        let warnings = warning_count();
        for choice in [
            None,
            Some(SourceBinding::Ip(source.parse().unwrap())),
            Some(SourceBinding::Interface("mgmt0".to_owned())),
        ] {
            for vrf in [None, Some("mgmt-vrf")] {
                let binding =
                    LocalBinding::new(choice.clone(), Some("mgmt0"), vrf, BindingPolicy::Strict)
                        .unwrap();
                let error = receive(destination, &binding).await.unwrap_err();
                assert!(error.downcast_ref::<Unavailable>().is_some(), "{error:#}");
                assert!(error.to_string().contains("fell through"), "{error:#}");
            }
        }
        assert_eq!(warning_count(), warnings);
        ip(&[family, "rule", "del", "priority", "100"]);
        ip(&[
            family, "route", "del", prefix, "dev", "mgmt0", "metric", "5",
        ]);
        println!("PASS {family}: actual-member source and TCP tuple rules cannot escape the VRF");

        for main_present in [true, false] {
            if !main_present {
                main_backend_routes(family, false);
            }
            let binding =
                LocalBinding::new(None, Some("unused0"), Some("mgmt-vrf"), BindingPolicy::Strict)
                    .unwrap();
            assert!(receive(destination, &binding).await.is_err());
            let binding = LocalBinding::new(
                None,
                Some("unused0"),
                Some("mgmt-vrf"),
                BindingPolicy::BestEffort,
            )
            .unwrap();
            let warnings = warning_count();
            assert_eq!(
                receive(destination, &binding).await.unwrap(),
                format!("{source} mgmt-peer\n")
            );
            assert_eq!(warning_count() - warnings, 1, "only the unused egress must be removed");
            if !main_present {
                main_backend_routes(family, true);
            }
        }
        println!(
            "PASS {family}: UP unused VRF egress removed before VRF with and without main route"
        );

        // Local delivery does not have a physical egress device.
        let local: IpAddr = data_source.parse().unwrap();
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(local, 0))
            .await
            .unwrap();
        let binding = LocalBinding::new(None, Some("data0"), None, BindingPolicy::Strict).unwrap();
        let stream = connect(listener.local_addr().unwrap(), &binding)
            .await
            .unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert_eq!(peer.ip(), local);
        assert_eq!(stream.local_addr().unwrap(), peer);
        println!("PASS {family}: ordinary local-address path preserved");
    }

    let destination: SocketAddr = "[2001:db8:ffff::49]:49490".parse().unwrap();
    ip(&[
        "-6",
        "route",
        "add",
        "table",
        "100",
        "2001:db8:ffff::49/128",
        "from",
        "2001:db8:1::/64",
        "via",
        "2001:db8:6::2",
        "dev",
        "vrf-alt0",
    ]);
    for choice in [
        SourceBinding::Ip("2001:db8:1::1".parse().unwrap()),
        SourceBinding::Interface("mgmt0".to_owned()),
    ] {
        for policy in [BindingPolicy::Strict, BindingPolicy::BestEffort] {
            let binding =
                LocalBinding::new(Some(choice.clone()), Some("mgmt0"), Some("mgmt-vrf"), policy)
                    .unwrap();
            let warnings = warning_count();
            let error = receive(destination, &binding).await.unwrap_err();
            assert!(error.to_string().contains("source-specific route"), "{error:#}");
            assert!(error.downcast_ref::<Unavailable>().is_none(), "{error:#}");
            assert_eq!(warning_count(), warnings);
        }
    }
    ip(&[
        "-6",
        "route",
        "del",
        "table",
        "100",
        "2001:db8:ffff::49/128",
        "from",
        "2001:db8:1::/64",
    ]);
    println!("PASS IPv6: source-specific alternate member never escapes or permits fallback");
    // A source-bearing IPv6 route query can return data0 despite RTA_OIF.
    main_backend_routes("-6", false);
    ip(&[
        "-6",
        "route",
        "add",
        "default",
        "via",
        "2001:db8:2::2",
        "dev",
        "data0",
        "metric",
        "10",
    ]);
    for source in [
        SourceBinding::Ip("2001:db8:4::1".parse().unwrap()),
        SourceBinding::Interface("standalone0".to_owned()),
    ] {
        let binding = LocalBinding::new(
            Some(source.clone()),
            Some("standalone0"),
            None,
            BindingPolicy::Strict,
        )
        .unwrap();
        assert!(receive(destination, &binding)
            .await
            .unwrap_err()
            .downcast_ref::<Unavailable>()
            .is_some());
        let binding =
            LocalBinding::new(Some(source), Some("standalone0"), None, BindingPolicy::BestEffort)
                .unwrap();
        let warnings = warning_count();
        assert_eq!(receive(destination, &binding).await.unwrap(), "2001:db8:4::1 data-peer\n");
        assert_eq!(warning_count() - warnings, 1);
    }
    ip(&["-6", "route", "del", "default", "dev", "data0"]);
    main_backend_routes("-6", true);
    println!("PASS IPv6: explicit and interface-derived sources reject wrong physical output");

    // The VRF route is valid, but it uses a different member from the request.
    ip(&[
        "-6",
        "route",
        "replace",
        "table",
        "100",
        "2001:db8:ffff::49/128",
        "via",
        "2001:db8:6::2",
        "dev",
        "vrf-alt0",
    ]);
    for main_present in [true, false] {
        if !main_present {
            main_backend_routes("-6", false);
        }
        for source in [
            None,
            Some(SourceBinding::Ip("2001:db8:1::1".parse().unwrap())),
            Some(SourceBinding::Interface("mgmt0".to_owned())),
        ] {
            let binding = LocalBinding::new(
                source.clone(),
                Some("mgmt0"),
                Some("mgmt-vrf"),
                BindingPolicy::Strict,
            )
            .unwrap();
            assert!(receive(destination, &binding)
                .await
                .unwrap_err()
                .downcast_ref::<Unavailable>()
                .is_some());
            let binding = LocalBinding::new(
                source.clone(),
                Some("mgmt0"),
                Some("mgmt-vrf"),
                BindingPolicy::BestEffort,
            )
            .unwrap();
            let warnings = warning_count();
            let expected_source = if source.is_none() {
                "2001:db8:6::1"
            } else {
                "2001:db8:1::1"
            };
            assert_eq!(
                receive(destination, &binding).await.unwrap(),
                format!("{expected_source} vrf-peer\n")
            );
            assert_eq!(warning_count() - warnings, 1, "the VRF and compatible source must remain");
        }
        if !main_present {
            main_backend_routes("-6", true);
        }
    }
    ip(&[
        "-6",
        "route",
        "replace",
        "table",
        "100",
        "2001:db8:ffff::49/128",
        "via",
        "2001:db8:1::2",
        "dev",
        "mgmt0",
    ]);
    println!(
        "PASS IPv6: wrong VRF member relaxed egress only and retained VRF for all source choices"
    );
    super::multipath::run().await;
}
