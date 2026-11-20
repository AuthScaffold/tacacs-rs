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
///
/// The runtime passes the active local services of each candidate. A filter
/// keeps no listener state, so a local services change takes effect with the
/// next candidate.
pub trait TacacsPlusFilter: Send + Sync {
    /// Returns an upper bound for known payload copies beyond the supplied working copy.
    ///
    /// The supervisor reserves this amount before filter entry. Unknown opaque
    /// output is checked at handoff, which cannot prevent its earlier allocation.
    /// # Errors
    /// Returns an error if the known byte count exceeds `u64`.
    fn known_payload_copies(
        &self,
        _source: &TacacsPlus,
        _local_services: &LocalServices,
    ) -> anyhow::Result<u64> {
        Ok(0)
    }

    /// Returns a filtered candidate without changing the authoritative source.
    ///
    /// # Errors
    /// Returns an error when the candidate violates host policy.
    fn filter<'a>(
        &'a self,
        tacacs_plus: TacacsPlus,
        local_services: &'a LocalServices,
    ) -> BoxFuture<'a, anyhow::Result<FilteredTacacsPlus>>;
}

/// Preserves every server and derives proxy policy from the local services.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopTacacsPlusFilter;

impl TacacsPlusFilter for NoopTacacsPlusFilter {
    fn known_payload_copies(
        &self,
        _source: &TacacsPlus,
        local_services: &LocalServices,
    ) -> anyhow::Result<u64> {
        Ok(u64::try_from(
            local_services
                .proxy_shared_secret
                .as_ref()
                .map_or(0, |secret| secret.expose_secret().len()),
        )?)
    }

    fn filter<'a>(
        &'a self,
        tacacs_plus: TacacsPlus,
        local_services: &'a LocalServices,
    ) -> BoxFuture<'a, anyhow::Result<FilteredTacacsPlus>> {
        async move {
            let proxy_downstream_obfuscation = prepare_proxy_policy(local_services, None)?;
            Ok(FilteredTacacsPlus {
                tacacs_plus,
                proxy_downstream_obfuscation,
            })
        }
        .boxed()
    }
}
