//! Host-supplied filtering of canonical source snapshots before preparation.
//!
//! Filters receive a working copy. The supervisor retains the authoritative
//! source separately for credential refresh and generation checks.

use futures_util::future::{BoxFuture, FutureExt};
use tacacsrs_config::TacacsPlus;
use tacacsrs_config::proxy_policy::{prepare_proxy_policy, PreparedProxyPolicy};
use tacacsrs_config::tacacsrs::LocalServices;

/// Filtered upstream configuration and its derived downstream proxy policy.
pub struct FilteredTacacsPlus {
    /// Canonical configuration selected for runtime preparation.
    pub tacacs_plus: TacacsPlus,
    /// Derived obfuscation policy for downstream proxy connections.
    pub proxy_downstream_obfuscation: PreparedProxyPolicy,
}

/// Applies host-specific filtering before a candidate enters preparation.
pub trait TacacsPlusFilter: Send + Sync {
    /// Returns a filtered candidate without changing the authoritative source.
    ///
    /// # Errors
    /// Returns an error when the candidate violates host policy.
    fn filter(&self, tacacs_plus: TacacsPlus) -> BoxFuture<'_, anyhow::Result<FilteredTacacsPlus>>;
}

/// Preserves every server and derives proxy policy from local service configuration.
#[derive(Debug, Default)]
pub struct NoopTacacsPlusFilter {
    source: LocalServices,
}

impl NoopTacacsPlusFilter {
    /// Captures the canonical local service configuration.
    #[must_use]
    pub fn new(source: LocalServices) -> Self {
        Self { source }
    }
}

impl TacacsPlusFilter for NoopTacacsPlusFilter {
    fn filter(&self, tacacs_plus: TacacsPlus) -> BoxFuture<'_, anyhow::Result<FilteredTacacsPlus>> {
        async move {
            let proxy_downstream_obfuscation = prepare_proxy_policy(&self.source, None)?;
            Ok(FilteredTacacsPlus {
                tacacs_plus,
                proxy_downstream_obfuscation,
            })
        }
        .boxed()
    }
}
