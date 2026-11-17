//! Assembly of KubeSONiC source capabilities.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use tacacsrs_provider::{Companion, CredentialProvider, SourceBundle};

use crate::credentials::MountedCredentials;
use crate::datastore::KubeSonicConfigDb;
use crate::environment::Environment;
use crate::registration::{LoopbackRegistration, Registrar};

/// Builds an inert source bundle from validated environment inputs.
///
/// # Errors
/// Returns an error when the datastore or registration endpoint is invalid.
pub fn prepare(input: Environment) -> anyhow::Result<SourceBundle> {
    let companions: Vec<Box<dyn Companion>> = if input.loopback.enabled {
        let endpoint: SocketAddr = input
            .local_services
            .tacacs_proxy_endpoint
            .as_deref()
            .context("Registration requires a proxy endpoint")?
            .parse()?;
        vec![Box::new(Registrar::new(
            LoopbackRegistration::new(
                input.source.clone(),
                input.loopback.priority,
                endpoint.port(),
            ),
            input.loopback.retry_interval,
        ))]
    } else {
        Vec::new()
    };
    let datastore = Arc::new(KubeSonicConfigDb::new(input.source)?);
    let provider = Arc::new(MountedCredentials::new(input.credentials));
    Ok(SourceBundle {
        datastore,
        credentials: CredentialProvider::observed(provider.clone(), provider),
        local_services: input.local_services,
        companions,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn disabled_registration_has_no_companion() {
        let input = Environment::parse(BTreeMap::new()).unwrap();
        let bundle = prepare(input).unwrap();
        assert!(bundle.companions.is_empty());
        let (resolver, changes) = bundle.credentials.into_parts();
        assert!(resolver.is_some() && changes.is_some());
    }

    #[test]
    fn registration_requires_a_proxy_endpoint() {
        let mut input = Environment::parse(BTreeMap::new()).unwrap();
        input.loopback.enabled = true;
        input.local_services.tacacs_proxy_endpoint = None;
        assert!(prepare(input).is_err());
    }
}
