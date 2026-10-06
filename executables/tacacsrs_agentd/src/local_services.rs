//! Startup adapters for the canonical local-services resource.

use anyhow::{Context, ensure};

use tacacsrs_config::local_services::{parse_local_services, prepare_local_services};
use tacacsrs_config::tacacsrs::LocalServices;
use tacacsrs_sonic::SonicForwarderSettings;

use crate::cli::{Cli, ServiceMode};

pub(crate) async fn load(
    cli: &Cli,
    forwarder: Option<SonicForwarderSettings>,
) -> anyhow::Result<LocalServices> {
    if let Some(path) = &cli.local_services {
        let bytes = tokio::fs::read(path)
            .await
            .with_context(|| format!("read local-services resource {}", path.display()))?;
        return parse_local_services(&bytes);
    }
    from_cli(cli, forwarder)
}

pub(crate) fn from_cli(
    cli: &Cli,
    forwarder: Option<SonicForwarderSettings>,
) -> anyhow::Result<LocalServices> {
    let mut source = LocalServices::default();
    if let Some(endpoint) = &cli.listen_endpoint {
        source.client_api_endpoint.clone_from(endpoint);
    }
    source.tacacs_proxy_endpoint.clone_from(&cli.proxy_endpoint);
    if let Some(mode) = &cli.socket_mode {
        source.unix_socket_mode = u16::from_str_radix(mode, 8)
            .context("socket mode must be an octal permission value")?;
    }
    if let Some(forwarder) = forwarder {
        let endpoint = forwarder.socket_address().to_string();
        if let Some(configured) = &source.tacacs_proxy_endpoint {
            ensure!(
                configured.parse::<std::net::SocketAddr>().ok() == Some(forwarder.socket_address()),
                "CLI proxy endpoint conflicts with TACPLUS_FORWARDER|global"
            );
        }
        source.tacacs_proxy_endpoint = Some(endpoint);
    }
    if cli.sonic {
        ensure!(
            cli.service_mode
                .is_none_or(|mode| mode == ServiceMode::Both),
            "SONiC central-agent mode requires --service-mode both"
        );
        source.client_api_enabled = true;
        source.tacacs_proxy_enabled = true;
    } else if let Some(mode) = cli.service_mode {
        source.client_api_enabled = mode != ServiceMode::TacacsProxy;
        source.tacacs_proxy_enabled = mode != ServiceMode::ClientApi;
    } else if source.tacacs_proxy_endpoint.is_some() {
        source.tacacs_proxy_enabled = true;
    }
    prepare_local_services(&source)?;
    Ok(source)
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use super::*;

    #[test]
    fn cli_and_yang_have_equal_canonical_and_prepared_values() {
        let cli = Cli::parse_from([
            "agentd",
            "--server-addr",
            "192.0.2.1:49",
            "--listen-endpoint",
            "/tmp/api.sock",
            "--proxy-endpoint",
            "[::1]:9049",
            "--socket-mode",
            "600",
        ]);
        let cli_source = from_cli(&cli, None).unwrap();
        let yang_source = parse_local_services(
            br#"{"tacacsrs:local-services":{
            "client-api-endpoint":"/tmp/api.sock", "tacacs-proxy-enabled":true,
            "tacacs-proxy-endpoint":"[::1]:9049", "unix-socket-mode":384
        }}"#,
        )
        .unwrap();
        assert_eq!(cli_source, yang_source);
        assert_eq!(
            prepare_local_services(&cli_source).unwrap(),
            prepare_local_services(&yang_source).unwrap()
        );
        let defaults = Cli::parse_from(["agentd", "--server-addr", "192.0.2.1:49"]);
        assert_eq!(from_cli(&defaults, None).unwrap(), LocalServices::default());
    }

    #[test]
    fn invalid_cli_controls_fail_before_service_construction() {
        for flags in [
            vec!["--socket-mode", "1000"],
            vec!["--socket-mode", "999"],
            vec!["--service-mode", "tacacs-proxy"],
            vec!["--listen-endpoint", "relative/socket"],
            vec!["--proxy-endpoint", "/run/tacacs/tacacs.sock"],
            vec![
                "--service-mode",
                "client-api",
                "--proxy-endpoint",
                "127.0.0.1:49",
            ],
        ] {
            let cli = Cli::parse_from(
                ["agentd", "--server-addr", "192.0.2.1:49"]
                    .into_iter()
                    .chain(flags),
            );
            assert!(from_cli(&cli, None).is_err());
        }
    }

    #[test]
    fn resource_file_conflicts_with_parallel_listener_inputs() {
        for flags in [
            vec!["--listen-endpoint", "/tmp/api.sock"],
            vec!["--proxy-endpoint", "127.0.0.1:49"],
            vec!["--socket-mode", "660"],
            vec!["--service-mode", "both"],
            vec!["--sonic"],
        ] {
            let args = [
                "agentd",
                "--server-addr",
                "192.0.2.1:49",
                "--local-services",
                "listeners.json",
            ];
            assert!(Cli::try_parse_from(args.into_iter().chain(flags)).is_err());
        }
    }

    #[tokio::test]
    async fn file_adapter_loads_canonical_resource_and_rejects_replacement() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir()
            .join(format!("local-services-{}-{unique}.json", std::process::id()));
        let cli = Cli::parse_from([
            "agentd",
            "--server-addr",
            "192.0.2.1:49",
            "--local-services",
            path.to_str().unwrap(),
        ]);
        let document = br#"{"tacacsrs:local-services":{"client-api-endpoint":"/tmp/file-api.sock","unix-socket-mode":384}}"#;
        tokio::fs::write(&path, document).await.unwrap();
        let source = load(&cli, None).await.unwrap();
        assert_eq!(source, parse_local_services(document).unwrap());
        tokio::fs::write(&path, br#"{"tacacsrs:local-services":{"unix-socket-mode":512}}"#)
            .await
            .unwrap();
        let invalid = load(&cli, None).await;
        tokio::fs::remove_file(&path).await.unwrap();
        assert!(invalid.is_err());
        assert_eq!(source.unix_socket_mode, 0o600);
    }

    #[test]
    fn sonic_forwarder_enters_canonical_preparation() {
        let cli = Cli::parse_from(["agentd", "--sonic"]);
        let hash = [
            ("local_listen_address".to_owned(), "127.0.0.1".to_owned()),
            ("local_listen_port".to_owned(), "49".to_owned()),
        ]
        .into_iter()
        .collect();
        let forwarder = SonicForwarderSettings::from_hash(&hash).unwrap();
        let source = from_cli(&cli, forwarder).unwrap();
        assert!(source.client_api_enabled);
        assert!(source.tacacs_proxy_enabled);
        assert_eq!(source.tacacs_proxy_endpoint.as_deref(), Some("127.0.0.1:49"));
    }
}
