//! Canonical YANG file source registration.

use std::sync::Arc;

use tacacsrs_agent::components::DatastoreSourceComponent;

use tacacsrs_config::input::{CliConfigSource, CliDatastoreInput};
use tacacsrs_config::source::CliFileDatastore;

use super::SelectedProfile;
use crate::cli::Cli;
use crate::local_services;

pub(crate) fn parse(cli: Cli) -> anyhow::Result<SelectedProfile> {
    SelectedProfile::from_cli(cli, |cli| {
        let path = cli
            .config
            .clone()
            .ok_or_else(|| anyhow::anyhow!("File source requires a configuration path"))?;
        let datastore = Arc::new(CliFileDatastore::new(CliDatastoreInput::new(
            CliConfigSource::YangFile { path },
            "file",
        )));
        Ok(vec![Box::new(DatastoreSourceComponent::from_file_datastore(
            "YANG file source",
            datastore,
            local_services::input(cli)?,
        ))])
    })
}
