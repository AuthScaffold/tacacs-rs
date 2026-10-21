//! Decoded configuration payload sizing and checked admission accounting.

use anyhow::{ensure, Context};

use crate::{TacacsPlus, TacacsPlusServer};
use crate::generated::tacacs_plus::{ClientIdentityCertificate, Tls13Epsk, ServerAuthenticationCaCerts};

fn add(total: &mut u64, bytes: usize) -> anyhow::Result<()> {
    *total = total
        .checked_add(u64::try_from(bytes)?)
        .context("candidate payload size overflow")?;
    Ok(())
}

fn client_payload(
    certificate: Option<&ClientIdentityCertificate>,
    epsk: Option<&Tls13Epsk>,
) -> anyhow::Result<u64> {
    let mut total = 0;
    if let Some(inline) = certificate.and_then(|certificate| certificate.inline_definition.as_ref())
    {
        for value in [inline.public_key.as_deref(), inline.cert_data.as_deref()]
            .into_iter()
            .flatten()
        {
            add(&mut total, value.len())?;
        }
        if let Some(key) = &inline.cleartext_private_key {
            add(&mut total, key.expose_secret().len())?;
        }
        for certificate in &inline.intermediate_certificate {
            add(&mut total, certificate.len())?;
        }
    }
    if let Some(key) = epsk
        .and_then(|epsk| epsk.inline_definition.as_ref())
        .and_then(|inline| inline.cleartext_symmetric_key.as_ref())
    {
        add(&mut total, key.expose_secret().len())?;
    }
    Ok(total)
}

fn authentication_payload(
    authority: Option<&ServerAuthenticationCaCerts>,
    peer: Option<&ServerAuthenticationCaCerts>,
    crls: Option<&crate::tacacsrs::RequireCrls>,
    ocsp: Option<&crate::tacacsrs::RequireOcsp>,
) -> anyhow::Result<u64> {
    let mut total = 0;
    for bag in [authority, peer].into_iter().flatten() {
        if let Some(inline) = &bag.inline_definition {
            for certificate in &inline.certificate {
                add(&mut total, certificate.cert_data.len())?;
            }
        }
    }
    if let Some(lists) = crls.and_then(|policy| policy.crl.as_ref()) {
        for list in lists {
            add(&mut total, list.len())?;
        }
    }
    if let Some(response) = ocsp.and_then(|policy| policy.response.as_ref()) {
        add(&mut total, response.len())?;
    }
    Ok(total)
}

fn sum(total: &mut u64, bytes: u64) -> anyhow::Result<()> {
    *total = total
        .checked_add(bytes)
        .context("candidate payload size overflow")?;
    Ok(())
}

/// Sizes one server's inline decoded payload without cloning it.
///
/// Names, opaque references, collection metadata, and allocator slack are excluded.
/// # Errors
/// Returns an error if the byte count exceeds `u64`.
pub fn server_payload_bytes(server: &TacacsPlusServer) -> anyhow::Result<u64> {
    let mut total = 0;
    if let Some(secret) = &server.shared_secret {
        add(&mut total, secret.expose_secret().len())?;
    }
    if let Some(client) = &server.client_identity {
        sum(&mut total, client_payload(client.certificate.as_ref(), client.tls13_epsk.as_ref())?)?;
    }
    if let Some(auth) = &server.server_authentication {
        sum(
            &mut total,
            authentication_payload(
                auth.ca_certs.as_ref(),
                auth.ee_certs.as_ref(),
                auth.require_crls.as_ref(),
                auth.require_ocsp.as_ref(),
            )?,
        )?;
    }
    Ok(total)
}

/// Sizes the known payload of one destination after local bundle expansion.
/// # Errors
/// Returns an error for a missing bundle or byte-count overflow.
pub fn enumerated_payload_bytes(
    source: &TacacsPlus,
    server: &TacacsPlusServer,
) -> anyhow::Result<u64> {
    let mut total = server_payload_bytes(server)?;
    if let Some(reference) = server
        .client_identity
        .as_ref()
        .and_then(|client| client.credentials_reference.as_ref())
    {
        let bundle = source
            .client_credentials
            .iter()
            .find(|bundle| &bundle.id == reference)
            .context("candidate client bundle is missing")?;
        sum(&mut total, client_payload(bundle.certificate.as_ref(), bundle.tls13_epsk.as_ref())?)?;
    }
    if let Some(reference) = server
        .server_authentication
        .as_ref()
        .and_then(|auth| auth.credentials_reference.as_ref())
    {
        let bundle = source
            .server_credentials
            .iter()
            .find(|bundle| &bundle.id == reference)
            .context("candidate server bundle is missing")?;
        sum(
            &mut total,
            authentication_payload(
                bundle.ca_certs.as_ref(),
                bundle.ee_certs.as_ref(),
                bundle.require_crls.as_ref(),
                bundle.require_ocsp.as_ref(),
            )?,
        )?;
    }
    Ok(total)
}

/// Sizes every decoded allocation in an owned configuration projection.
/// # Errors
/// Returns an error if the byte count exceeds `u64`.
pub fn source_payload_bytes(source: &TacacsPlus) -> anyhow::Result<u64> {
    let mut total = 0;
    for server in &source.server {
        sum(&mut total, server_payload_bytes(server)?)?;
    }
    for bundle in &source.client_credentials {
        sum(&mut total, client_payload(bundle.certificate.as_ref(), bundle.tls13_epsk.as_ref())?)?;
    }
    for bundle in &source.server_credentials {
        sum(
            &mut total,
            authentication_payload(
                bundle.ca_certs.as_ref(),
                bundle.ee_certs.as_ref(),
                bundle.require_crls.as_ref(),
                bundle.require_ocsp.as_ref(),
            )?,
        )?;
    }
    Ok(total)
}

/// Checked logical destination payload plus additional retained configuration copies.
///
/// This ledger does not measure provider internals, native allocators, or RSS.
#[derive(Debug)]
pub struct ConfigurationMaterialBudget {
    byte_limit: u64,
    request_limit: u64,
    logical: u64,
    extra: u64,
    high_water: u64,
    planned: u64,
    attempts: u64,
}

impl ConfigurationMaterialBudget {
    /// Creates a ledger with explicit caller-supplied limits, not configuration defaults.
    #[must_use]
    pub const fn new(byte_limit: u64, request_limit: u64) -> Self {
        Self {
            byte_limit,
            request_limit,
            logical: 0,
            extra: 0,
            high_water: 0,
            planned: 0,
            attempts: 0,
        }
    }

    /// Reserves complete logical payload before enumeration or installation.
    /// # Errors
    /// Returns an error for overflow or an exceeded limit.
    pub fn reserve_logical(&mut self, bytes: u64) -> anyhow::Result<()> {
        let logical = self
            .logical
            .checked_add(bytes)
            .context("candidate payload size overflow")?;
        self.charge(logical, self.extra)?;
        self.logical = logical;
        Ok(())
    }

    /// Sets the retained copy charge, after reservation and before a known clone.
    /// # Errors
    /// Returns an error for overflow or an exceeded limit.
    pub fn retain_extra(&mut self, bytes: u64) -> anyhow::Result<()> {
        self.charge(self.logical, bytes)?;
        self.extra = bytes;
        Ok(())
    }

    /// Reserves additional live Rust payload before a prepared copy.
    /// # Errors
    /// Returns an error for overflow or an exceeded limit.
    pub fn reserve_extra(&mut self, bytes: u64) -> anyhow::Result<()> {
        self.retain_extra(
            self.extra
                .checked_add(bytes)
                .context("candidate payload size overflow")?,
        )
    }

    /// Releases bytes only after their additional payload owner drops.
    /// # Panics
    /// Panics if `bytes` exceeds the current extra payload reservation.
    pub fn release_extra(&mut self, bytes: u64) {
        self.extra = self
            .extra
            .checked_sub(bytes)
            .expect("released payload was reserved");
    }

    fn charge(&mut self, logical: u64, extra: u64) -> anyhow::Result<()> {
        let total = logical
            .checked_add(extra)
            .context("candidate payload size overflow")?;
        ensure!(total <= self.byte_limit, "candidate retained material limit exceeded");
        self.high_water = self.high_water.max(total);
        Ok(())
    }

    /// Admits the complete plan before the first provider call.
    /// # Errors
    /// Returns an error if all planned slots do not fit.
    pub fn plan_requests(&mut self, count: u64) -> anyhow::Result<()> {
        ensure!(count <= self.request_limit, "candidate resolution request limit exceeded");
        self.planned = count;
        Ok(())
    }

    /// Counts a slot attempt before provider entry. Failures do not refund attempts.
    /// # Errors
    /// Returns an error for overflow or an exceeded limit.
    pub fn attempt_request(&mut self) -> anyhow::Result<()> {
        let attempts = self
            .attempts
            .checked_add(1)
            .context("candidate request count overflow")?;
        ensure!(
            attempts <= self.request_limit && attempts <= self.planned,
            "candidate resolution request limit exceeded"
        );
        self.attempts = attempts;
        Ok(())
    }

    /// Checks original counts and high-water charge against final effective limits.
    /// # Errors
    /// Returns an error if any original or current limit is exceeded.
    pub fn check(&self, byte_limit: u64, request_limit: u64) -> anyhow::Result<()> {
        ensure!(
            self.high_water <= byte_limit.min(self.byte_limit),
            "candidate retained material limit exceeded"
        );
        ensure!(
            self.planned <= request_limit.min(self.request_limit)
                && self.attempts <= request_limit.min(self.request_limit),
            "candidate resolution request limit exceeded"
        );
        Ok(())
    }

    /// Returns live logical and additional payload charges and their high-water mark.
    #[must_use]
    pub const fn charges(&self) -> (u64, u64, u64) {
        (self.logical, self.extra, self.high_water)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_sizing_covers_all_decoded_fields_not_names_or_references() {
        let mut server = crate::TacacsPlusServerBuilder::new(
            "metadata",
            crate::TacacsPlusServerType::all(),
            "192.0.2.1",
            300,
        )
        .with_tls_client_certificate(Some(vec![1; 3]), Some(vec![2; 5]))
        .build();
        let identity = server.client_identity.as_mut().unwrap();
        let inline = identity
            .certificate
            .as_mut()
            .unwrap()
            .inline_definition
            .as_mut()
            .unwrap();
        inline.public_key = Some(vec![3; 7]);
        inline.intermediate_certificate = vec![vec![4; 11], vec![5; 13]];
        let mut epsk = crate::TacacsPlusServerBuilder::new(
            "epsk",
            crate::TacacsPlusServerType::all(),
            "192.0.2.2",
            300,
        )
        .with_tls13_epsk_psk_only("ignored identity", vec![6; 37])
        .build();
        identity.tls13_epsk = epsk.client_identity.as_mut().unwrap().tls13_epsk.take();
        let mut auth = crate::TlsClientServerAuthentication::default();
        for (target, length) in [(&mut auth.ca_certs, 17), (&mut auth.ee_certs, 19)] {
            *target = Some(crate::ServerAuthenticationCaCerts {
                central_truststore_reference: Some("ignored opaque reference".repeat(100)),
                inline_definition: Some(crate::truststore::CertsInlineDefinition {
                    certificate: vec![crate::truststore::CertsCertificate {
                        name: "ignored name".repeat(100),
                        cert_data: vec![7; length],
                    }],
                }),
            });
        }
        auth.require_crls = Some(crate::tacacsrs::RequireCrls {
            crl: Some(vec![vec![8; 23]]),
            ..Default::default()
        });
        auth.require_ocsp = Some(crate::tacacsrs::RequireOcsp {
            response: Some(vec![9; 29]),
            ..Default::default()
        });
        server.server_authentication = Some(auth);
        server.shared_secret = Some(tacacsrs_secrets::SecretString::new("x".repeat(31)));
        assert_eq!(server_payload_bytes(&server).unwrap(), 195);
    }

    #[test]
    fn payload_budget_exact_plus_one_overflow_and_copy_vs_move() {
        let mut budget = ConfigurationMaterialBudget::new(8, 2);
        budget.reserve_logical(4).unwrap();
        budget.retain_extra(4).unwrap();
        assert_eq!(budget.charges(), (4, 4, 8));
        assert!(budget.reserve_logical(1).is_err());
        budget.retain_extra(0).unwrap();
        budget.reserve_logical(4).unwrap();
        assert_eq!(budget.charges(), (8, 0, 8));
        assert!(budget.check(7, 2).is_err());
        assert!(budget.reserve_logical(u64::MAX).is_err());
        budget.plan_requests(2).unwrap();
        budget.attempt_request().unwrap();
        budget.attempt_request().unwrap();
        assert!(budget.attempt_request().is_err());
        assert!(budget.check(8, 1).is_err());
    }
}
