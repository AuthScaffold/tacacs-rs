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

    use super::parse;
    use crate::cli::Cli;

    #[test]
    fn service_mode_conflict_fails_before_configdb_access() {
        let cli = Cli::parse_from([
            "agentd",
            "--sonic",
            "--sonic-redis-url",
            "redis://127.0.0.1:1",
            "--service-mode",
            "client-api",
        ]);
        let error = parse(cli).err().unwrap();
        assert!(
            format!("{error:#}").contains("requires both local services"),
            "{error:#}"
        );
    }
}
