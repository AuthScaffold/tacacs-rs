//! Credential capabilities supplied by a source.

use std::fmt;
use std::sync::Arc;

use tacacsrs_credential_resolution::{CredentialChangeSource, CredentialResolver};

/// A resolver and its optional notifications, or no external credentials.
#[derive(Clone, Default)]
pub struct CredentialProvider {
    resolver: Option<Arc<dyn CredentialResolver>>,
    changes: Option<Arc<dyn CredentialChangeSource>>,
}

impl CredentialProvider {
    /// Creates a provider without external credentials.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Creates a provider without notifications.
    #[must_use]
    pub fn resolver(resolver: Arc<dyn CredentialResolver>) -> Self {
        Self {
            resolver: Some(resolver),
            changes: None,
        }
    }

    /// Creates a resolver with its change source.
    #[must_use]
    pub fn observed(
        resolver: Arc<dyn CredentialResolver>,
        changes: Arc<dyn CredentialChangeSource>,
    ) -> Self {
        Self {
            resolver: Some(resolver),
            changes: Some(changes),
        }
    }

    /// Wraps the resolver and preserves its notifications.
    ///
    /// # Errors
    /// Returns the error of `outer`.
    pub fn layer(
        self,
        outer: impl FnOnce(
            Option<Arc<dyn CredentialResolver>>,
        ) -> anyhow::Result<Arc<dyn CredentialResolver>>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            resolver: Some(outer(self.resolver)?),
            changes: self.changes,
        })
    }

    /// Transfers the resolver and notifications to the runtime.
    #[must_use]
    #[allow(
        clippy::type_complexity,
        reason = "The tuple transfers the paired optional capabilities without another public type."
    )]
    pub fn into_parts(
        self,
    ) -> (Option<Arc<dyn CredentialResolver>>, Option<Arc<dyn CredentialChangeSource>>) {
        (self.resolver, self.changes)
    }
}

impl fmt::Debug for CredentialProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialProvider")
            .field("resolver", &self.resolver.is_some())
            .field("changes", &self.changes.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacacsrs_credential_resolution::{
        CredentialChangeError, CredentialChangeStream, FakeCredentialResolver,
    };

    struct Changes;

    impl fmt::Debug for Changes {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("credential-secret-sentinel")
        }
    }

    #[async_trait::async_trait]
    impl CredentialChangeSource for Changes {
        async fn subscribe(&self) -> Result<CredentialChangeStream, CredentialChangeError> {
            Err(CredentialChangeError)
        }
    }

    #[test]
    fn layering_preserves_the_source_resolver_and_notifications() {
        let resolver: Arc<dyn CredentialResolver> = Arc::new(FakeCredentialResolver::new());
        let changes: Arc<dyn CredentialChangeSource> = Arc::new(Changes);
        let provider = CredentialProvider::observed(resolver.clone(), changes.clone())
            .layer(|base| {
                assert!(Arc::ptr_eq(base.as_ref().unwrap(), &resolver));
                Ok(base.unwrap())
            })
            .unwrap();
        let (retained_resolver, retained_changes) = provider.into_parts();
        assert!(Arc::ptr_eq(&retained_resolver.unwrap(), &resolver));
        assert!(Arc::ptr_eq(&retained_changes.unwrap(), &changes));
        let created = CredentialProvider::none()
            .layer(|base| {
                assert!(base.is_none());
                Ok(resolver)
            })
            .unwrap();
        assert!(created.into_parts().0.is_some());
    }

    #[test]
    fn debug_does_not_format_credential_sources() {
        let provider = CredentialProvider::observed(
            Arc::new(FakeCredentialResolver::new()),
            Arc::new(Changes),
        );
        assert!(format!("{:?}", Changes).contains("credential-secret-sentinel"));
        assert!(!format!("{provider:#?}").contains("credential-secret-sentinel"));
    }
}
