//! Startup adapters for the canonical local-services resource.

use anyhow::{Context, ensure};

use tacacsrs_config::local_services::{parse_local_services, prepare_local_services};
use tacacsrs_config::tacacsrs::{LocalServices, ProxyCredentialSource};
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
    let mut source =
        forwarder.map_or_else(LocalServices::default, SonicForwarderSettings::local_services);
    if let Some(endpoint) = &cli.listen_endpoint {
        source.client_api_endpoint.clone_from(endpoint);
    }
    if let Some(endpoint) = &cli.proxy_endpoint {
        source.tacacs_proxy_endpoint = Some(endpoint.clone());
    }
    if let Some(secret) = &cli.proxy_shared_secret {
        source.proxy_credential_source = ProxyCredentialSource::Inline;
        source.proxy_shared_secret = Some(secret.clone());
    }
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
        ensure!(forwarder.is_some(), "SONiC listener configuration requires a forwarder row");
    } else if let Some(mode) = cli.service_mode {
        source.client_api_enabled = mode != ServiceMode::TacacsProxy;
        source.tacacs_proxy_enabled = mode != ServiceMode::ClientApi;
    } else if source.tacacs_proxy_endpoint.is_some() {
        source.tacacs_proxy_enabled = true;
    }
    if let Some(selection) = cli.proxy_credential_source {
        source.proxy_credential_source = selection;
    }
    prepare_local_services(&source)?;
    Ok(source)
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use super::*;

    #[test]
    fn inline_cli_and_file_credentials_match_without_debug_disclosure() {
        let cli = Cli::parse_from([
            "agentd",
            "--server-addr",
            "192.0.2.1:49",
            "--proxy-endpoint",
            "127.0.0.1:49",
            "--proxy-shared-secret",
            "private-downstream-key",
        ]);
        let source = from_cli(&cli, None).unwrap();
        let file = parse_local_services(
            br#"{"tacacsrs:local-services":{
            "tacacs-proxy-enabled":true, "tacacs-proxy-endpoint":"127.0.0.1:49",
            "proxy-credential-source":"inline", "proxy-shared-secret":"private-downstream-key"
        }}"#,
        )
        .unwrap();
        assert_eq!(source, file);
        assert!(!format!("{cli:?} {source:?}").contains("private-downstream-key"));
        for document in [
            br#"{"tacacsrs:local-services":{"proxy-shared-secret":"private-downstream-key"}}"#.as_slice(),
            br#"{"tacacsrs:local-services":{"tacacs-proxy-enabled":true,"tacacs-proxy-endpoint":"127.0.0.1:49","proxy-credential-source":"inline","proxy-shared-secret":""}}"#.as_slice(),
        ] {
            let error = parse_local_services(document).unwrap_err();
            assert!(!format!("{error:#}").contains("private-downstream-key"));
        }
    }

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
        assert_eq!(source.proxy_credential_source, ProxyCredentialSource::LocalProxyRow);
        let plain = Cli::parse_from([
            "agentd",
            "--sonic",
            "--proxy-credential-source",
            "unobfuscated",
        ]);
        let source = from_cli(&plain, forwarder).unwrap();
        assert_eq!(source.proxy_credential_source, ProxyCredentialSource::Unobfuscated);
    }

    #[test]
    fn sonic_cli_and_yang_share_local_service_defaults_and_prepared_behavior() {
        for address in ["127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1"] {
            let hash = tacacsrs_sonic::SonicHash::from([(
                "local_listen_address".to_owned(),
                address.to_owned(),
            )]);
            let forwarder = SonicForwarderSettings::from_hash(&hash).unwrap().unwrap();
            let socket = forwarder.socket_address().to_string();
            let sonic = Cli::parse_from(["agentd", "--sonic"]);
            let inline = Cli::parse_from([
                "agentd",
                "--server-addr",
                "192.0.2.20:49",
                "--proxy-endpoint",
                &socket,
                "--proxy-credential-source",
                "local-proxy-row",
            ]);
            let document = serde_json::json!({"tacacsrs:local-services": {
                "tacacs-proxy-enabled": true, "tacacs-proxy-endpoint": socket,
                "proxy-credential-source": "local-proxy-row"
            }});
            let sources = [
                from_cli(&sonic, Some(forwarder)).unwrap(),
                from_cli(&inline, None).unwrap(),
                parse_local_services(&serde_json::to_vec(&document).unwrap()).unwrap(),
            ];
            assert_eq!(sources[0], forwarder.local_services());
            assert_eq!(sources[0], sources[1]);
            assert_eq!(sources[1], sources[2]);
            for source in &sources {
                assert_eq!(
                    prepare_local_services(source).unwrap(),
                    prepare_local_services(&sources[0]).unwrap()
                );
            }
        }
    }

    #[test]
    fn sonic_listener_conflicts_fail_before_binding() {
        let hash = tacacsrs_sonic::SonicHash::from([(
            "local_listen_address".to_owned(),
            "127.0.0.1".to_owned(),
        )]);
        let forwarder = SonicForwarderSettings::from_hash(&hash).unwrap();
        for flags in [
            vec!["--proxy-endpoint", "127.0.0.2:49"],
            vec!["--service-mode", "client-api"],
            vec!["--socket-mode", "1000"],
        ] {
            let cli = Cli::parse_from(["agentd", "--sonic"].into_iter().chain(flags));
            assert!(from_cli(&cli, forwarder).is_err());
        }
    }
}
