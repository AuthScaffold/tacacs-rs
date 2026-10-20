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
                let error = receive(destination, &binding).await.unwrap_err();
                assert!(error.downcast_ref::<Unavailable>().is_some(), "{error:#}");
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
            SourceBinding::Ip("2001:db8:1::1".parse().unwrap()),
            SourceBinding::Interface("mgmt0".to_owned()),
        ] {
            let binding = LocalBinding::new(
                Some(source.clone()),
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
                Some(source),
                Some("mgmt0"),
                Some("mgmt-vrf"),
                BindingPolicy::BestEffort,
            )
            .unwrap();
            let warnings = warning_count();
            assert_eq!(receive(destination, &binding).await.unwrap(), "2001:db8:1::1 vrf-peer\n");
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
        "PASS IPv6: wrong VRF member relaxed egress only and retained VRF and both source choices"
    );
    super::multipath::run().await;
}
