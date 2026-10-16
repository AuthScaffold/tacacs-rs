//! Host-authorized credential provider registration and composition.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use tokio::io::AsyncReadExt;

use tacacsrs_credential_http::{CrlFetchLimits, HttpCrlResolver, HttpCrlSource, HttpOcspSource};
use tacacsrs_credential_resolution::{CredentialChangeSource, CredentialResolver};
use tacacsrs_sonic::{
    SonicCredentialChangeSource, SonicCredentialPolicy, SonicCredentialResolver,
    SonicCredentialRoots,
};

use crate::cli::Cli;
use crate::sonic_connection_from_cli;

pub(crate) type CredentialProvider =
    (Option<Arc<dyn CredentialResolver>>, Option<Arc<dyn CredentialChangeSource>>);

async fn crl_sources(cli: &Cli) -> anyhow::Result<Vec<HttpCrlSource>> {
    let mut locations = BTreeMap::<&str, Vec<&str>>::new();
    let mut pairs = cli.http_crl_source.chunks_exact(2);
    anyhow::ensure!(
        pairs.remainder().is_empty(),
        "HTTP CRL registration requires reference and URL pairs"
    );
    for pair in &mut pairs {
        locations.entry(&pair[0]).or_default().push(&pair[1]);
    }
    let mut certificates = BTreeMap::<&str, Vec<Vec<u8>>>::new();
    let pairs = cli.http_crl_certificate.chunks_exact(2);
    anyhow::ensure!(
        pairs.remainder().is_empty(),
        "CRL certificate registration requires reference and file pairs"
    );
    for pair in pairs {
        anyhow::ensure!(
            locations.contains_key(pair[0].as_str()),
            "CRL discovery reference has no authorized locations"
        );
        certificates
            .entry(&pair[0])
            .or_default()
            .push(read_certificate(Path::new(&pair[1])).await?);
    }
    locations
        .into_iter()
        .map(|(reference, urls)| match certificates.remove(reference) {
            Some(certificates) => HttpCrlSource::from_certificates(
                reference,
                &certificates.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                urls,
            ),
            None => HttpCrlSource::new(reference, urls),
        })
        .collect()
}

async fn read_certificate(path: &Path) -> anyhow::Result<Vec<u8>> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| anyhow::anyhow!("Could not open registered discovery certificate"))?;
    let mut data = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut data)
        .await
        .map_err(|_| anyhow::anyhow!("Could not read registered discovery certificate"))?;
    anyhow::ensure!(
        !data.is_empty() && data.len() <= 1024 * 1024,
        "Discovery certificate size is invalid"
    );
    Ok(data)
}

async fn ocsp_sources(cli: &Cli) -> anyhow::Result<Vec<HttpOcspSource>> {
    let mut sources = Vec::new();
    let explicit = cli.http_ocsp_source.chunks_exact(4);
    anyhow::ensure!(
        explicit.remainder().is_empty(),
        "OCSP source registration requires four values"
    );
    for source in explicit {
        let certificate = read_certificate(Path::new(&source[2])).await?;
        let issuer = read_certificate(Path::new(&source[3])).await?;
        sources.push(HttpOcspSource::new(&source[0], &source[1], &certificate, &issuer)?);
    }
    let discovered = cli.http_ocsp_certificate.chunks_exact(3);
    anyhow::ensure!(
        discovered.remainder().is_empty(),
        "OCSP discovery registration requires three values"
    );
    for source in discovered {
        let certificate = read_certificate(Path::new(&source[1])).await?;
        let issuer = read_certificate(Path::new(&source[2])).await?;
        sources.push(HttpOcspSource::from_certificate(
            &source[0],
            &certificate,
            &issuer,
            &cli.http_ocsp_allow_url,
        )?);
    }
    Ok(sources)
}

pub(crate) async fn build(cli: &Cli) -> anyhow::Result<CredentialProvider> {
    let sources = crl_sources(cli).await?;
    let ocsp = ocsp_sources(cli).await?;
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
    if !sources.is_empty() || !ocsp.is_empty() {
        let mut http =
            HttpCrlResolver::new(sources, CrlFetchLimits::default())?.with_ocsp_sources(ocsp)?;
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

    #[tokio::test]
    async fn http_registration_groups_locations_and_rejects_invalid_sources() {
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
        assert!(build(&cli).await.unwrap().0.is_some());
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
        assert!(build(&duplicate).await.is_err());
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
            let error = build(&cli).await.err().unwrap();
            assert!(!format!("{error:#}").contains(url));
            assert!(!format!("{error:#}").contains("private-reference"));
        }
        assert!(
            Cli::try_parse_from(["agentd", "--sonic", "--http-crl-source", "missing-url"]).is_err()
        );
    }

    #[tokio::test]
    async fn provider_is_optional_and_composes_with_sonic() {
        let direct = Cli::try_parse_from(["agentd", "--server-addr", "127.0.0.1"]).unwrap();
        let (resolver, changes) = build(&direct).await.unwrap();
        assert!(resolver.is_none() && changes.is_none());
        for extra in [
            vec![],
            vec!["--http-crl-source", "opaque", "https://example.test/crl"],
        ] {
            let cli = Cli::try_parse_from(["agentd", "--sonic"].into_iter().chain(extra)).unwrap();
            let (resolver, changes) = build(&cli).await.unwrap();
            assert!(resolver.is_some() && changes.is_some());
        }
    }
}
