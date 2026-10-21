use super::*;

async fn control(destination: SocketAddr, device: &str, source: IpAddr) -> anyhow::Result<String> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let socket = tokio::net::TcpSocket::new_v6()?;
        socket.bind_device(Some(device.as_bytes()))?;
        socket.bind(SocketAddr::new(source, 0))?;
        let mut stream = socket.connect(destination).await?;
        let mut response = String::new();
        stream.read_to_string(&mut response).await?;
        Ok(response)
    })
    .await?
}

pub(super) async fn run() {
    let layout = std::env::var("TACACSRS_NONPREFERRED_LAYOUT").unwrap();
    let destination: SocketAddr = "[2001:db8:ffff::49]:49490".parse().unwrap();
    let mut failures = Vec::new();
    for (device, source, vrf, peer) in [
        ("standalone0", "2001:db8:4::1", None, "stand-peer"),
        ("mgmt0", "2001:db8:1::1", Some("mgmt-vrf"), "mgmt-peer"),
    ] {
        let expected = format!("{source} {peer}\n");
        for (name, choice) in [
            ("automatic", None),
            ("explicit", Some(SourceBinding::Ip(source.parse().unwrap()))),
            ("interface", Some(SourceBinding::Interface(device.to_owned()))),
        ] {
            for policy in [BindingPolicy::Strict, BindingPolicy::BestEffort] {
                // This independent Rust socket bypasses product route verification.
                // Its source is the sole global address of the fixture's interface.
                let observation = control(destination, device, source.parse().unwrap())
                    .await
                    .unwrap();
                assert_eq!(observation, expected, "the requested real TCP route must work");
                let binding = LocalBinding::new(choice.clone(), Some(device), vrf, policy).unwrap();
                let warnings = warning_count();
                let product = receive(destination, &binding).await;
                let correct = product.as_ref().is_ok_and(|observed| observed == &expected)
                    && warning_count() == warnings;
                println!("COMPARE {layout} device={device} source={name} policy={policy:?} control={observation:?} product={product:?} warnings={}", warning_count() - warnings);
                if !correct {
                    failures.push(format!("{layout}/{device}/{name}/{policy:?}"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "valid bound TCP paths were rejected or relaxed: {failures:?}");
    println!("PASS {layout}: all 12 actual Rust product paths matched bound TCP controls without fallback");
}
