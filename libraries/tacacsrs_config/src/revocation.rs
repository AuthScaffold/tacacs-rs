//! Converts the global `certificate-revocation` container into runtime settings.
//!
//! The YANG container is the canonical policy. [`revocation_settings`] derives
//! the [`RevocationSettings`] value that a host gives to its revocation
//! verifier. The settings contain no certificate or CRL material.

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};

use tacacsrs_networking::{
    DistributionPointPattern, DistributionPointUrl, RevocationEnforcement, RevocationSettings,
};

use crate::{TacacsPlus, tacacsrs::CertificateRevocation, tacacsrs::Enforcement};

/// Returns the validated revocation settings of a configuration.
///
/// A configuration without a `certificate-revocation` container gives the
/// default settings, with enforcement `disabled`.
///
/// # Errors
///
/// Returns an error when a distribution-point pattern or URL is invalid, or
/// when [`RevocationSettings::validate`] rejects the combined settings.
pub fn revocation_settings(config: &TacacsPlus) -> Result<RevocationSettings> {
    config
        .certificate_revocation
        .as_ref()
        .map_or_else(|| Ok(RevocationSettings::default()), settings_from_container)
}

fn settings_from_container(container: &CertificateRevocation) -> Result<RevocationSettings> {
    let mut settings = RevocationSettings::default();
    settings.enforcement = match container.enforcement {
        Enforcement::Disabled => RevocationEnforcement::Disabled,
        Enforcement::HardFail => RevocationEnforcement::HardFail,
        Enforcement::SoftFail => RevocationEnforcement::SoftFail,
        Enforcement::WarnOnly => RevocationEnforcement::WarnOnly,
    };
    settings.soft_fail_grace = Duration::from_secs(u64::from(container.soft_fail_grace_seconds));
    settings.allowed_distribution_points = container
        .allowed_distribution_point
        .iter()
        .map(|pattern| {
            DistributionPointPattern::parse(pattern).with_context(|| {
                format!("certificate-revocation/allowed-distribution-point '{pattern}' is invalid")
            })
        })
        .collect::<Result<_>>()?;
    settings.prefetch_distribution_points = container
        .prefetch_distribution_point
        .iter()
        .map(|url| {
            DistributionPointUrl::parse(url).with_context(|| {
                format!("certificate-revocation/prefetch-distribution-point '{url}' is invalid")
            })
        })
        .collect::<Result<_>>()?;
    settings.allow_private_addresses = container.allow_private_addresses;
    settings.fetch_timeout = Duration::from_secs(u64::from(container.fetch_timeout_seconds));
    settings.max_crl_bytes = u64::from(container.max_crl_bytes);
    settings.cache_directory = container.cache_directory.as_ref().map(PathBuf::from);
    settings
        .validate()
        .context("certificate-revocation is invalid")?;
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_yang_json;

    const SERVER: &str = r#""server":[{"name":"a","server-type":"accounting","address":"192.0.2.1","port":49,"shared-secret":"s"}]"#;

    fn parse(revocation: &str) -> Result<TacacsPlus> {
        let json = format!(r#"{{"ietf-system-tacacs-plus:tacacs-plus":{{{SERVER}{revocation}}}}}"#);
        parse_yang_json(&json)
    }

    #[test]
    fn missing_container_disables_enforcement() {
        let settings = revocation_settings(&parse("").unwrap()).unwrap();
        assert_eq!(settings.enforcement, RevocationEnforcement::Disabled);
    }

    #[test]
    fn container_maps_units_and_patterns() {
        let cache_directory = if cfg!(windows) {
            "C:/var/cache/tacacsrs"
        } else {
            "/var/cache/tacacsrs"
        };
        let config = parse(&format!(
            r#","tacacsrs:certificate-revocation":{{
                "enforcement":"soft-fail",
                "soft-fail-grace-seconds":60,
                "allowed-distribution-point":["http://**.pki.core.windows.net/**/*.crl"],
                "prefetch-distribution-point":["http://primary-cdn.pki.core.windows.net/eastus2/crls/x/current.crl"],
                "allow-private-addresses":false,
                "fetch-timeout-seconds":2,
                "max-crl-bytes":1024,
                "cache-directory":"{cache_directory}"}}"#
        ))
        .unwrap();
        let settings = revocation_settings(&config).unwrap();
        assert_eq!(settings.enforcement, RevocationEnforcement::SoftFail);
        assert_eq!(settings.soft_fail_grace, Duration::from_secs(60));
        assert_eq!(settings.fetch_timeout, Duration::from_secs(2));
        assert_eq!(settings.max_crl_bytes, 1024);
        assert!(!settings.allow_private_addresses);
        assert_eq!(settings.prefetch_distribution_points.len(), 1);
        assert_eq!(
            settings.cache_directory.as_deref(),
            Some(std::path::Path::new(cache_directory))
        );
    }

    #[test]
    fn invalid_container_fails_validation() {
        for revocation in [
            r#","tacacsrs:certificate-revocation":{"enforcement":"hard-fail"}"#,
            r#","tacacsrs:certificate-revocation":{"allowed-distribution-point":["http://**/**"]}"#,
            r#","tacacsrs:certificate-revocation":{"allowed-distribution-point":["http://crl.example.com/**"],"prefetch-distribution-point":["http://other.example.com/a.crl"]}"#,
            r#","tacacsrs:certificate-revocation":{"cache-directory":"relative"}"#,
        ] {
            assert!(parse(revocation).is_err(), "accepted {revocation}");
        }
    }
}
