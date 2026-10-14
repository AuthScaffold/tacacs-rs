//! Source metadata paired with a reusable prepared endpoint identity.

use std::sync::Arc;

use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt, TacacsPlusServerType};
use tacacsrs_config::prepare::PrepareOptions;
use tacacsrs_networking::routed::{Endpoint, OperationKind};

pub(super) struct PreparedServer {
    pub(super) server: Arc<TacacsPlusServer>,
    pub(super) endpoint: Endpoint,
    pub(super) certificate_lifetime: crate::runtime::CredentialLifetime,
    pub(super) counters: tacacsrs_networking::ServerCounters,
}

impl PreparedServer {
    pub(super) fn new(
        server: Arc<TacacsPlusServer>,
        options: PrepareOptions,
    ) -> anyhow::Result<Self> {
        let prepared = tacacsrs_config::prepare::prepare_endpoint(&server, options)?;
        let counters = prepared.counters();
        let certificate_lifetime = match prepared.prepared_credential_validity() {
            Some(validity) => crate::runtime::CredentialLifetime::new(
                tacacsrs_credential_resolution::CredentialValidity::new(
                    Some(validity.valid_from()),
                    Some(validity.valid_until()),
                )?,
            )?,
            None => crate::runtime::CredentialLifetime::unbounded(),
        };
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
        Ok(Self {
            server,
            endpoint,
            certificate_lifetime,
            counters,
        })
    }

    pub(super) fn config(&self) -> &TacacsPlusServer {
        &self.server
    }
}
