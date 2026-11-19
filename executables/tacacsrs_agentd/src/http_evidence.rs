//! Maps the HTTP evidence flags to the library settings.

use std::collections::BTreeMap;
use std::path::PathBuf;

use tacacsrs_agent::components::{HttpCrlRegistration, HttpEvidenceSettings, HttpOcspRegistration};

use crate::cli::Cli;

/// Groups the HTTP evidence flags of the command line by reference.
///
/// # Errors
/// Returns an error for an incomplete flag group, or for a CRL discovery
/// certificate without CRL locations. The error does not contain a value.
pub(crate) fn settings(cli: &Cli) -> anyhow::Result<HttpEvidenceSettings> {
    let mut crl = BTreeMap::<&str, HttpCrlRegistration>::new();
    let mut pairs = cli.http_crl_source.chunks_exact(2);
    anyhow::ensure!(
        pairs.remainder().is_empty(),
        "HTTP CRL registration requires reference and URL pairs"
    );
    for pair in &mut pairs {
        let registration = crl.entry(&pair[0]).or_insert_with(|| HttpCrlRegistration {
            reference: pair[0].clone(),
            ..HttpCrlRegistration::default()
        });
        registration.urls.push(pair[1].clone());
    }
    let pairs = cli.http_crl_certificate.chunks_exact(2);
    anyhow::ensure!(
        pairs.remainder().is_empty(),
        "CRL certificate registration requires reference and file pairs"
    );
    for pair in pairs {
        let registration = crl.get_mut(pair[0].as_str()).ok_or_else(|| {
            anyhow::anyhow!("CRL discovery reference has no authorized locations")
        })?;
        registration
            .discovery_certificates
            .push(PathBuf::from(&pair[1]));
    }

    let mut ocsp = Vec::new();
    let explicit = cli.http_ocsp_source.chunks_exact(4);
    anyhow::ensure!(
        explicit.remainder().is_empty(),
        "OCSP source registration requires four values"
    );
    for values in explicit {
        ocsp.push(HttpOcspRegistration {
            reference: values[0].clone(),
            responder: Some(values[1].clone()),
            certificate: PathBuf::from(&values[2]),
            issuer: PathBuf::from(&values[3]),
        });
    }
    let discovered = cli.http_ocsp_certificate.chunks_exact(3);
    anyhow::ensure!(
        discovered.remainder().is_empty(),
        "OCSP discovery registration requires three values"
    );
    for values in discovered {
        ocsp.push(HttpOcspRegistration {
            reference: values[0].clone(),
            responder: None,
            certificate: PathBuf::from(&values[1]),
            issuer: PathBuf::from(&values[2]),
        });
    }
    Ok(HttpEvidenceSettings {
        crl_sources: crl.into_values().collect(),
        ocsp_sources: ocsp,
        ocsp_allowed_urls: cli.http_ocsp_allow_url.clone(),
    })
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn incomplete_registration_groups_are_rejected() {
        let mut cli = Cli::try_parse_from(["agentd", "--server-addr", "127.0.0.1"]).unwrap();
        cli.http_crl_source = vec!["reference".to_owned()];
        assert!(settings(&cli).is_err());
        cli.http_crl_source.clear();
        cli.http_crl_certificate = vec!["reference".to_owned()];
        assert!(settings(&cli).is_err());
        cli.http_crl_certificate.clear();
        cli.http_ocsp_source = vec!["reference".to_owned()];
        assert!(settings(&cli).is_err());
        cli.http_ocsp_source.clear();
        cli.http_ocsp_certificate = vec!["reference".to_owned()];
        assert!(settings(&cli).is_err());
        assert!(
            Cli::try_parse_from(["agentd", "--sonic", "--http-crl-source", "missing-url"]).is_err()
        );
    }

    #[test]
    fn crl_flags_group_by_reference_and_require_locations_for_discovery() {
        let cli = Cli::try_parse_from([
            "agentd",
            "--sonic",
            "--http-crl-source",
            "opaque",
            "https://example.test/root.crl",
            "--http-crl-source",
            "opaque",
            "https://example.test/issuer.crl",
            "--http-crl-certificate",
            "opaque",
            "/etc/tacacs/leaf.der",
        ])
        .unwrap();
        let settings = settings(&cli).unwrap();
        assert_eq!(settings.crl_sources.len(), 1);
        assert_eq!(settings.crl_sources[0].urls.len(), 2);
        assert_eq!(
            settings.crl_sources[0].discovery_certificates,
            [PathBuf::from("/etc/tacacs/leaf.der")]
        );
        let mut unknown = cli;
        unknown.http_crl_certificate = vec!["other".to_owned(), "/etc/tacacs/leaf.der".to_owned()];
        assert!(super::settings(&unknown).is_err());
    }
}
