//! Canonical YANG file source registration.

use std::sync::Arc;

use tacacsrs_config::input::{CliConfigSource, CliDatastoreInput};
use tacacsrs_config::source::CliFileDatastore;
use tacacsrs_config::tacacsrs::LocalServices;

use crate::cli::Cli;
use crate::{credential_provider, local_services};
use super::{SelectedProfile, SourceComponents};

pub(crate) fn parse(cli: Cli) -> anyhow::Result<SelectedProfile> {
    Ok(SelectedProfile::from_cli(cli, |cli| async move {
        let path = cli.config.clone().ok_or_else(|| anyhow::anyhow!("File source requires a configuration path"))?;
        let datastore = Arc::new(CliFileDatastore::new(CliDatastoreInput::new(
            CliConfigSource::YangFile { path }, "file",
        )));
        Ok(SourceComponents {
            datastore,
            credentials: credential_provider::build(&cli, (None, None)).await?,
            local_services: local_services::load(&cli, LocalServices::default()).await?,
            host_services: Vec::new(),
        })
    }))
}
