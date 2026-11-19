//! SONiC credential assembly.

use std::sync::Arc;

use tacacsrs_provider::CredentialProvider;

use crate::{
    SonicConnection, SonicCredentialChangeSource, SonicCredentialPolicy, SonicCredentialResolver,
    SonicCredentialRoots,
};

/// Creates the SONiC credential provider for this connection.
#[must_use]
pub fn credentials(settings: &SonicConnection) -> CredentialProvider {
    let resolver = Arc::new(SonicCredentialResolver::reloadable(
        SonicCredentialRoots::default(),
        SonicCredentialPolicy::production_from_root_group(),
    ));
    match &settings.credential_watch_root {
        Some(root) => CredentialProvider::observed(
            resolver,
            Arc::new(SonicCredentialChangeSource::new(root.clone(), settings.debounce)),
        ),
        None => CredentialProvider::resolver(resolver),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_notifications_follow_connection_settings() {
        let mut settings = SonicConnection::default();
        let (resolver, changes) = credentials(&settings).into_parts();
        assert!(resolver.is_some() && changes.is_some());
        settings.credential_watch_root = None;
        let (resolver, changes) = credentials(&settings).into_parts();
        assert!(resolver.is_some() && changes.is_none());
    }
}
