use super::*;

pub(super) async fn run() {
    for (family, destination, prefix, source, mgmt_gateway, alternate_gateway) in [
        ("-4", "198.51.100.49:49490", "198.51.100.49/32", "192.0.2.1", "192.0.2.2", "192.0.5.2"),
        (
            "-6",
            "[2001:db8:ffff::49]:49490",
            "2001:db8:ffff::49/128",
            "2001:db8:1::1",
            "2001:db8:1::2",
            "2001:db8:6::2",
        ),
    ] {
        ip(&[
            family,
            "route",
            "replace",
            "table",
            "100",
            prefix,
            "nexthop",
            "via",
            mgmt_gateway,
            "dev",
            "mgmt0",
            "weight",
            "1",
            "nexthop",
            "via",
            alternate_gateway,
            "dev",
            "vrf-alt0",
            "weight",
            "1",
        ]);
        let mut forced_successes = 0;
        let mut constrained_rejections = 0;
        let mut ambiguous_rejections = 0;
        for _ in 0..16 {
            let destination: SocketAddr = destination.parse().unwrap();
            let binding = LocalBinding::new(
                Some(SourceBinding::Ip(source.parse().unwrap())),
                Some("mgmt0"),
                Some("mgmt-vrf"),
                BindingPolicy::Strict,
            )
            .unwrap();
            let warnings = warning_count();
            match receive(destination, &binding).await {
                Ok(observation) => {
                    assert_eq!(observation, format!("{source} mgmt-peer\n"));
                    forced_successes += 1;
                }
                Err(error) => {
                    if error.downcast_ref::<Unavailable>().is_none() {
                        ambiguous_rejections += 1;
                    }
                    assert!(
                        error.downcast_ref::<Unavailable>().is_some()
                            || error.to_string().contains("mixed-device multipath"),
                        "an unknown TCP-selected hop must not pass validation: {error:#}"
                    );
                    constrained_rejections += 1;
                }
            }
            assert_eq!(warning_count(), warnings);

            // A VRF-only request permits either member. Its pinned source and
            // selected table must stay unchanged for every ECMP connection.
            let binding = LocalBinding::new(
                Some(SourceBinding::Ip(source.parse().unwrap())),
                None,
                Some("mgmt-vrf"),
                BindingPolicy::Strict,
            )
            .unwrap();
            let observation = receive(destination, &binding).await.unwrap();
            assert!(
                observation == format!("{source} mgmt-peer\n")
                    || observation == format!("{source} vrf-peer\n"),
                "{observation}"
            );
        }
        ip(&[
            family,
            "route",
            "replace",
            "table",
            "100",
            prefix,
            "via",
            mgmt_gateway,
            "dev",
            "mgmt0",
        ]);
        println!("PASS {family}: live ECMP forced_successes={forced_successes}, constrained_rejections={constrained_rejections}, ambiguous_rejections={ambiguous_rejections}, vrf_connections=16");
    }
}
