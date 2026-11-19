//! Maps the listener flags to the local-services input of the library.

use anyhow::Context;

use tacacsrs_agent::components::LocalServicesInput;
use tacacsrs_config::local_services::{LocalServicesPatch, ServiceSelection};
use tacacsrs_config::tacacsrs::LocalServices;

use crate::cli::{Cli, ServiceMode};

/// Returns the listener flags as a patch.
///
/// # Errors
/// Returns an error when the socket mode is not an octal value.
pub(crate) fn patch(cli: &Cli) -> anyhow::Result<LocalServicesPatch> {
    Ok(LocalServicesPatch {
        client_api_endpoint: cli.listen_endpoint.clone(),
        tacacs_proxy_endpoint: cli.proxy_endpoint.clone(),
        proxy_shared_secret: cli.proxy_shared_secret.clone(),
        unix_socket_mode: cli
            .socket_mode
            .as_deref()
            .map(|mode| u16::from_str_radix(mode, 8))
            .transpose()
            .context("socket mode must be an octal permission value")?,
        services: cli.service_mode.map(|mode| match mode {
            ServiceMode::ClientApi => ServiceSelection::ClientApi,
            ServiceMode::TacacsProxy => ServiceSelection::TacacsProxy,
            ServiceMode::Both => ServiceSelection::Both,
        }),
        proxy_credential_source: cli.proxy_credential_source,
    })
}

/// Returns the local-services input of a command-line profile.
///
/// A command-line profile has no source that can supply a proxy endpoint
/// later. An enabled proxy must therefore have `--proxy-endpoint`.
///
/// # Errors
/// Returns the error of [`patch`], or an error when the flags enable the
/// proxy without an endpoint.
pub(crate) fn input(cli: &Cli) -> anyhow::Result<LocalServicesInput> {
    Ok(match &cli.local_services {
        Some(path) => LocalServicesInput::File(path.clone()),
        None => {
            let patch = patch(cli)?;
            let services = patch.apply(LocalServices::default())?;
            anyhow::ensure!(
                !services.tacacs_proxy_enabled || services.tacacs_proxy_endpoint.is_some(),
                "The TACACS+ proxy service needs --proxy-endpoint"
            );
            LocalServicesInput::Patch(patch)
        }
    })
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use tacacsrs_config::local_services::{parse_local_services, prepare_local_services};
    use tacacsrs_config::tacacsrs::ProxyCredentialSource;
    use tacacsrs_sonic::SonicForwarderSettings;

    use super::*;

    fn from_cli(cli: &Cli, source: LocalServices) -> anyhow::Result<LocalServices> {
        patch(cli)?.apply(source)
    }

    fn sonic(cli: &Cli, forwarder: SonicForwarderSettings) -> anyhow::Result<LocalServices> {
        forwarder.local_services_with(&patch(cli)?)
    }

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
        let source = from_cli(&cli, LocalServices::default()).unwrap();
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
        let cli_source = from_cli(&cli, LocalServices::default()).unwrap();
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
        assert_eq!(
            from_cli(&defaults, LocalServices::default()).unwrap(),
            LocalServices::default()
        );
    }

    #[test]
    fn invalid_cli_controls_fail_before_service_construction() {
        for flags in [
            vec!["--socket-mode", "1000"],
            vec!["--socket-mode", "999"],
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
            assert!(from_cli(&cli, LocalServices::default()).is_err());
        }
    }

    #[test]
    fn a_command_line_proxy_needs_an_endpoint() {
        let cli = Cli::parse_from([
            "agentd",
            "--server-addr",
            "192.0.2.1:49",
            "--service-mode",
            "tacacs-proxy",
        ]);
        assert!(from_cli(&cli, LocalServices::default()).is_ok());
        let error = input(&cli).expect_err("the proxy needs an endpoint");
        assert!(error.to_string().contains("--proxy-endpoint"), "{error:#}");
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

    #[test]
    fn sonic_forwarder_enters_canonical_preparation() {
        let cli = Cli::parse_from(["agentd", "--sonic"]);
        let hash = [
            ("local_listen_address".to_owned(), "127.0.0.1".to_owned()),
            ("local_listen_port".to_owned(), "49".to_owned()),
        ]
        .into_iter()
        .collect();
        let forwarder = SonicForwarderSettings::from_hash(&hash).unwrap().unwrap();
        let source = sonic(&cli, forwarder).unwrap();
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
        let source = sonic(&plain, forwarder).unwrap();
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
            let sonic_cli = Cli::parse_from(["agentd", "--sonic"]);
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
                sonic(&sonic_cli, forwarder).unwrap(),
                from_cli(&inline, LocalServices::default()).unwrap(),
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
        let forwarder = SonicForwarderSettings::from_hash(&hash).unwrap().unwrap();
        for flags in [
            vec!["--proxy-endpoint", "127.0.0.2:49"],
            vec!["--service-mode", "client-api"],
            vec!["--socket-mode", "1000"],
        ] {
            let cli = Cli::parse_from(["agentd", "--sonic"].into_iter().chain(flags));
            assert!(sonic(&cli, forwarder).is_err());
        }
    }
}
