//! Host-authorized credential provider registration and composition.

use std::collections::BTreeMap;
use std::sync::Arc;

use tacacsrs_credential_http::{CrlFetchLimits, HttpCrlResolver, HttpCrlSource};
use tacacsrs_credential_resolution::{CredentialChangeSource, CredentialResolver};
use tacacsrs_sonic::{
    SonicCredentialChangeSource, SonicCredentialPolicy, SonicCredentialResolver,
    SonicCredentialRoots,
};

use crate::cli::Cli;
use crate::sonic_connection_from_cli;

pub(crate) type CredentialProvider =
    (Option<Arc<dyn CredentialResolver>>, Option<Arc<dyn CredentialChangeSource>>);

pub(crate) fn build(cli: &Cli) -> anyhow::Result<CredentialProvider> {
    let mut locations = BTreeMap::<&str, Vec<&str>>::new();
    let mut pairs = cli.http_crl_source.chunks_exact(2);
    anyhow::ensure!(
        pairs.remainder().is_empty(),
        "HTTP CRL registration requires reference and URL pairs"
    );
    for pair in &mut pairs {
        locations.entry(&pair[0]).or_default().push(&pair[1]);
    }
    let sources = locations
        .into_iter()
        .map(|(reference, urls)| HttpCrlSource::new(reference, urls))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let (mut resolver, change_source): CredentialProvider = if cli.sonic {
        let resolver = Arc::new(SonicCredentialResolver::reloadable(
            SonicCredentialRoots::default(),
            SonicCredentialPolicy::production_from_root_group(),
        ));
        let settings = sonic_connection_from_cli(cli);
        let changes = settings.credential_watch_root.map(|root| {
            Arc::new(SonicCredentialChangeSource::new(root, settings.debounce))
                as Arc<dyn CredentialChangeSource>
        });
        (Some(resolver), changes)
    } else {
        (None, None)
    };
    if !sources.is_empty() {
        let mut http = HttpCrlResolver::new(sources, CrlFetchLimits::default())?;
        if let Some(fallback) = resolver.take() {
            http = http.with_fallback(fallback);
        }
        resolver = Some(Arc::new(http));
    }
    Ok((resolver, change_source))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn http_registration_groups_locations_and_rejects_invalid_sources() {
        let cli = Cli::try_parse_from([
            "agentd",
            "--server-addr",
            "127.0.0.1",
            "--http-crl-source",
            "opaque",
            "https://example.test/root.crl",
            "--http-crl-source",
            "opaque",
            "https://example.test/issuer.crl",
        ])
        .unwrap();
        assert!(build(&cli).unwrap().0.is_some());
        let duplicate = Cli::try_parse_from([
            "agentd",
            "--server-addr",
            "127.0.0.1",
            "--http-crl-source",
            "opaque",
            "https://example.test/root.crl",
            "--http-crl-source",
            "opaque",
            "https://example.test/root.crl",
        ])
        .unwrap();
        assert!(build(&duplicate).is_err());
        for url in [
            "file:///etc/private",
            "http://user:secret@example.test/crl",
            "http://example.test/crl?secret=value",
        ] {
            let cli = Cli::try_parse_from([
                "agentd",
                "--sonic",
                "--http-crl-source",
                "private-reference",
                url,
            ])
            .unwrap();
            let error = build(&cli).err().unwrap();
            assert!(!format!("{error:#}").contains(url));
            assert!(!format!("{error:#}").contains("private-reference"));
        }
        assert!(
            Cli::try_parse_from(["agentd", "--sonic", "--http-crl-source", "missing-url"]).is_err()
        );
    }

    #[test]
    fn provider_is_optional_and_composes_with_sonic() {
        let direct = Cli::try_parse_from(["agentd", "--server-addr", "127.0.0.1"]).unwrap();
        let (resolver, changes) = build(&direct).unwrap();
        assert!(resolver.is_none() && changes.is_none());
        for extra in [
            vec![],
            vec!["--http-crl-source", "opaque", "https://example.test/crl"],
        ] {
            let cli = Cli::try_parse_from(["agentd", "--sonic"].into_iter().chain(extra)).unwrap();
            let (resolver, changes) = build(&cli).unwrap();
            assert!(resolver.is_some() && changes.is_some());
        }
    }
}
