//! SONiC ConfigDB source selection.

use tacacsrs_sonic::{SonicConnection, SonicSource};

use super::SelectedProfile;
use crate::cli::Cli;
use crate::local_services;

fn connection(cli: &Cli) -> SonicConnection {
    let mut settings = SonicConnection::default();
    if let Some(url) = cli.matches.get_one::<String>("sonic_redis_url") {
        settings.url.clone_from(url);
    }
    if let Some(db) = cli.matches.get_one::<i64>("sonic_redis_db") {
        settings.db_index = *db;
    }
    settings
}

pub(crate) fn parse(cli: Cli) -> anyhow::Result<SelectedProfile> {
    SelectedProfile::from_cli(cli, |cli| {
        Ok(vec![Box::new(
            SonicSource::new(connection(cli)).with_listener_patch(local_services::patch(cli)?)?,
        )])
    })
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::cli::Cli;

    #[test]
    fn sonic_rejects_inline_upstream_and_forwarder_cli_flags_at_parse_time() {
        for flags in [
            vec!["--use-tls"],
            vec!["--shared-secret", "secret"],
            vec![
                "--use-tls",
                "--client-certificate",
                "client.pem",
                "--client-key",
                "client.key",
            ],
            vec![
                "--use-tls",
                "--psk-identity",
                "client",
                "--psk-key",
                "secret",
            ],
            vec!["--connect-timeout-seconds", "10"],
            vec!["--dedicated"],
            vec!["--service-mode", "client-api"],
            vec!["--service-mode", "both"],
            vec!["--proxy-endpoint", "127.0.0.1:49"],
            vec!["--proxy-credential-source", "unobfuscated"],
            vec!["--local-services", "listeners.json"],
        ] {
            assert!(
                Cli::try_parse_from(["agentd", "--sonic"].into_iter().chain(flags.clone()))
                    .is_err(),
                "SONiC profile accepted unsupported CLI flags: {flags:?}",
            );
        }
        assert!(Cli::try_parse_from([
            "agentd",
            "--sonic",
            "--sonic-redis-url",
            "redis://127.0.0.1:1",
            "--sonic-redis-db",
            "4",
            "--listen-endpoint",
            "/tmp/tacacs.sock",
            "--socket-mode",
            "660",
        ])
        .is_ok());
    }
}
