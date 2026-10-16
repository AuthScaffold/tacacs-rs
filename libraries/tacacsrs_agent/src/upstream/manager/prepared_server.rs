//! Source metadata paired with a reusable prepared endpoint identity.

use std::sync::Arc;

use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt, TacacsPlusServerType};
use tacacsrs_config::prepare::PrepareOptions;
use tacacsrs_networking::routed::{Endpoint, OperationKind};

pub(super) struct PreparedServer {
    pub(super) server: Arc<TacacsPlusServer>,
    pub(super) endpoint: Endpoint,
}

impl PreparedServer {
    pub(super) fn new(
        server: Arc<TacacsPlusServer>,
        options: PrepareOptions,
    ) -> anyhow::Result<Self> {
        let prepared = tacacsrs_config::prepare::prepare_endpoint(&server, options)?;
        let operations = [
            (OperationKind::Authentication, TacacsPlusServerType::AUTHENTICATION),
            (OperationKind::Authorization, TacacsPlusServerType::AUTHORIZATION),
            (OperationKind::Accounting, TacacsPlusServerType::ACCOUNTING),
        ]
        .into_iter()
        .filter_map(|(operation, capability)| {
            server.supports_server_type(capability).then_some(operation)
        });
        let endpoint = Endpoint::new(&server.name, prepared, operations);
        Ok(Self { server, endpoint })
    }

    pub(super) fn config(&self) -> &TacacsPlusServer {
        &self.server
    }
}
