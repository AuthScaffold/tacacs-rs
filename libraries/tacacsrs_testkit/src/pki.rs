//! Fast ECDSA P-256 X.509 test PKI, CRL signing, and TLS 1.3 contexts.
//!
//! Generating 256-bit ECDSA keys avoids expensive 4096-bit RSA key operations
//! when running large handshake bursts under 32-bit `qemu-arm` emulation.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sha::sha256;
use openssl::ssl::{SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, CrlNumber, ExtendedKeyUsage, KeyUsage,
    SubjectAlternativeName, SubjectKeyIdentifier,
};
use openssl::x509::{X509, X509CrlBuilder, X509Extension, X509NameBuilder, X509RevokedBuilder};
use tacacsrs_config::truststore::{CertsCertificate, CertsInlineDefinition};
use tacacsrs_config::{ServerAuthenticationCaCerts, TlsClientServerAuthentication};

const OID_CRL_DISTRIBUTION_POINTS: &str = "2.5.29.31";

/// One X.509 certificate paired with its ECDSA P-256 private key.
#[derive(Clone)]
pub struct TestIdentity {
    certificate: X509,
    key: PKey<Private>,
}

impl TestIdentity {
    /// Generates a self-signed ECDSA P-256 root CA certificate.
    ///
    /// # Errors
    ///
    /// Returns an error if OpenSSL cannot generate or sign the certificate.
    pub fn new_ca(common_name: &str, serial: u32) -> Result<Self> {
        let key = generate_p256_key()?;
        let name = build_subject(common_name)?;
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_serial_number(BigNum::from_u32(serial)?.to_asn1_integer()?.as_ref())?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&key)?;
        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(2)?.as_ref())?;
        builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;
        let ski = SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
        builder.append_extension(ski)?;
        builder.sign(&key, MessageDigest::sha256())?;
        Ok(Self {
            certificate: builder.build(),
            key,
        })
    }

    /// Issues a server certificate for `127.0.0.1` and `localhost`, optionally embedding a CRL URL.
    ///
    /// # Errors
    ///
    /// Returns an error if OpenSSL cannot build or sign the certificate.
    pub fn issue_server(
        &self,
        common_name: &str,
        serial: u32,
        crl_uri: Option<&str>,
    ) -> Result<Self> {
        let key = generate_p256_key()?;
        let name = build_subject(common_name)?;
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_serial_number(BigNum::from_u32(serial)?.to_asn1_integer()?.as_ref())?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(self.certificate.subject_name())?;
        builder.set_pubkey(&key)?;
        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
        builder.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
        let san = SubjectAlternativeName::new()
            .ip("127.0.0.1")
            .dns("localhost")
            .build(&builder.x509v3_context(Some(&self.certificate), None))?;
        builder.append_extension(san)?;
        let aki = AuthorityKeyIdentifier::new()
            .keyid(false)
            .build(&builder.x509v3_context(Some(&self.certificate), None))?;
        builder.append_extension(aki)?;
        if let Some(uri) = crl_uri {
            builder.append_extension(crl_distribution_point_extension(uri)?)?;
        }
        builder.sign(&self.key, MessageDigest::sha256())?;
        Ok(Self {
            certificate: builder.build(),
            key,
        })
    }

    /// Issues a client authentication leaf certificate signed by this CA.
    ///
    /// # Errors
    ///
    /// Returns an error if OpenSSL cannot build or sign the certificate.
    pub fn issue_client(&self, common_name: &str, serial: u32) -> Result<Self> {
        let key = generate_p256_key()?;
        let name = build_subject(common_name)?;
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_serial_number(BigNum::from_u32(serial)?.to_asn1_integer()?.as_ref())?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(self.certificate.subject_name())?;
        builder.set_pubkey(&key)?;
        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
        builder.append_extension(ExtendedKeyUsage::new().client_auth().build()?)?;
        builder.sign(&self.key, MessageDigest::sha256())?;
        Ok(Self {
            certificate: builder.build(),
            key,
        })
    }

    /// Generates a self-signed certificate valid for `valid_for` from now, returning `(Self, expires_at)`.
    ///
    /// Uses generalized ASN.1 time strings (`YYYYMMDDHHMMSSZ`) rather than `time_t`
    /// so validity windows behave identically on 32-bit and 64-bit targets.
    ///
    /// # Errors
    ///
    /// Returns an error if OpenSSL cannot build or sign the certificate.
    pub fn self_signed_for_duration(
        common_name: &str,
        valid_for: Duration,
    ) -> Result<(Self, SystemTime)> {
        let key = generate_p256_key()?;
        let name = build_subject(common_name)?;
        let now_secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let start = UNIX_EPOCH + Duration::from_secs(now_secs.saturating_sub(60));
        let expires_at = UNIX_EPOCH + Duration::from_secs(now_secs) + valid_for;
        let not_before = Asn1Time::from_str_x509(&format_asn1_generalized_time(start)?)?;
        let not_after = Asn1Time::from_str_x509(&format_asn1_generalized_time(expires_at)?)?;

        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_serial_number(BigNum::from_u32(1)?.to_asn1_integer()?.as_ref())?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&key)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;
        let san = SubjectAlternativeName::new()
            .ip("127.0.0.1")
            .dns("localhost")
            .build(&builder.x509v3_context(None, None))?;
        builder.append_extension(san)?;
        builder.sign(&key, MessageDigest::sha256())?;
        Ok((
            Self {
                certificate: builder.build(),
                key,
            },
            expires_at,
        ))
    }

    /// Generates an untrusted self-signed server certificate for `127.0.0.1`.
    ///
    /// # Errors
    ///
    /// Returns an error if OpenSSL cannot build or sign the certificate.
    pub fn self_signed_server(common_name: &str) -> Result<Self> {
        let (identity, _) =
            Self::self_signed_for_duration(common_name, Duration::from_secs(86_400))?;
        Ok(identity)
    }

    /// Signs a DER-encoded X.509 v2 CRL that optionally revokes `leaf`.
    ///
    /// # Errors
    ///
    /// Returns an error if OpenSSL cannot build or sign the CRL.
    pub fn sign_crl(&self, crl_number: u32, revoked_leaf: Option<&Self>) -> Result<Vec<u8>> {
        let mut crl = X509CrlBuilder::new()?;
        crl.set_issuer_name(self.certificate.subject_name())?;
        crl.set_last_update(Asn1Time::days_from_now(0)?.as_ref())?;
        crl.set_next_update(Asn1Time::days_from_now(1)?.as_ref())?;
        let context_holder = X509::builder()?;
        let context = context_holder.x509v3_context(Some(&self.certificate), None);
        crl.append_extension(AuthorityKeyIdentifier::new().keyid(true).build(&context)?)?;
        crl.append_extension(CrlNumber::new(BigNum::from_u32(crl_number)?)?.build()?)?;
        if let Some(leaf) = revoked_leaf {
            let mut entry = X509RevokedBuilder::new()?;
            entry.set_serial_number(leaf.certificate.serial_number())?;
            entry.set_revocation_date(Asn1Time::days_from_now(0)?.as_ref())?;
            crl.add_revoked(entry.build())?;
        }
        crl.sign(&self.key, MessageDigest::sha256())?;
        Ok(crl.build()?.to_der()?)
    }

    /// Borrows the underlying OpenSSL certificate.
    #[must_use]
    pub const fn certificate(&self) -> &X509 {
        &self.certificate
    }

    /// Borrows the underlying OpenSSL private key.
    #[must_use]
    pub const fn private_key(&self) -> &PKey<Private> {
        &self.key
    }

    /// Encodes the certificate as DER bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if OpenSSL DER serialization fails.
    pub fn certificate_der(&self) -> Result<Vec<u8>> {
        Ok(self.certificate.to_der()?)
    }

    /// Encodes the certificate as PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if OpenSSL PEM serialization fails.
    pub fn certificate_pem(&self) -> Result<Vec<u8>> {
        Ok(self.certificate.to_pem()?)
    }

    /// Encodes the private key as PKCS#8 DER bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if OpenSSL PKCS#8 serialization fails.
    pub fn private_key_pkcs8_der(&self) -> Result<Vec<u8>> {
        Ok(self.key.private_key_to_pkcs8()?)
    }

    /// Encodes the private key as PKCS#8 PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if OpenSSL PEM serialization fails.
    pub fn private_key_pem(&self) -> Result<Vec<u8>> {
        Ok(self.key.private_key_to_pem_pkcs8()?)
    }

    /// Computes the lowercase hex SHA-256 fingerprint of the DER certificate.
    ///
    /// # Errors
    ///
    /// Returns an error if OpenSSL DER serialization fails.
    pub fn sha256_hex(&self) -> Result<String> {
        let digest = sha256(&self.certificate_der()?);
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
        }
        Ok(out)
    }
}

/// Ready-to-use ECDSA P-256 CA, server, and client certificate bundle.
#[derive(Clone)]
pub struct TestPki {
    /// Root certificate authority.
    pub ca: TestIdentity,
    /// Server leaf identity valid for `127.0.0.1` and `localhost`.
    pub server: TestIdentity,
    /// Client leaf identity for mutual TLS.
    pub client: TestIdentity,
}

impl TestPki {
    /// Generates a fresh ECDSA P-256 CA, server certificate, and client certificate.
    ///
    /// # Errors
    ///
    /// Returns an error if OpenSSL certificate generation fails.
    pub fn new() -> Result<Self> {
        let ca = TestIdentity::new_ca("tacacsrs-test-ca", 1)?;
        let server = ca.issue_server("localhost", 2, None)?;
        let client = ca.issue_client("tacacsrs-test-client", 3)?;
        Ok(Self { ca, server, client })
    }

    /// Builds a YANG `TlsClientServerAuthentication` inline CA trust store for this PKI.
    ///
    /// # Errors
    ///
    /// Returns an error if OpenSSL DER serialization fails.
    pub fn inline_ca_trust_store(&self) -> Result<TlsClientServerAuthentication> {
        Ok(TlsClientServerAuthentication {
            credentials_reference: None,
            ca_certs: Some(ServerAuthenticationCaCerts {
                inline_definition: Some(CertsInlineDefinition {
                    certificate: vec![CertsCertificate {
                        name: "testkit-ca".to_owned(),
                        cert_data: self.ca.certificate_der()?,
                    }],
                }),
                central_truststore_reference: None,
            }),
            ee_certs: None,
            tls13_epsks: None,
        })
    }

    /// Builds a TLS 1.3 server `SslContext` requiring a client certificate from this CA.
    ///
    /// # Errors
    ///
    /// Returns an error if OpenSSL rejects the certificate or key material.
    pub fn mtls_server_context(&self) -> Result<SslContext> {
        let mut builder = tls13_server_builder()?;
        builder.set_certificate(self.server.certificate())?;
        builder.set_private_key(self.server.private_key())?;
        builder
            .cert_store_mut()
            .add_cert(self.ca.certificate().clone())?;
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        Ok(builder.build())
    }

    /// Builds a TLS 1.3 server `SslContext` without requiring a client certificate.
    ///
    /// # Errors
    ///
    /// Returns an error if OpenSSL rejects the certificate or key material.
    pub fn tls_server_context(&self) -> Result<SslContext> {
        let mut builder = tls13_server_builder()?;
        builder.set_certificate(self.server.certificate())?;
        builder.set_private_key(self.server.private_key())?;
        builder.set_verify(SslVerifyMode::NONE);
        Ok(builder.build())
    }
}

/// Builds a TLS 1.3-only OpenSSL server context builder.
///
/// # Errors
///
/// Returns an error if OpenSSL cannot initialize the TLS server method.
pub fn tls13_server_builder() -> Result<SslContextBuilder> {
    let mut builder = SslContext::builder(SslMethod::tls_server())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    Ok(builder)
}

/// Builds a TLS 1.3 server `SslContext` presenting an untrusted self-signed certificate.
///
/// # Errors
///
/// Returns an error if OpenSSL cannot generate or configure the certificate.
pub fn untrusted_server_context() -> Result<SslContext> {
    let untrusted = TestIdentity::self_signed_server("untrusted-server")?;
    let mut builder = tls13_server_builder()?;
    builder.set_certificate(untrusted.certificate())?;
    builder.set_private_key(untrusted.private_key())?;
    Ok(builder.build())
}

fn generate_p256_key() -> Result<PKey<Private>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = EcKey::generate(&group)?;
    Ok(PKey::from_ec_key(key)?)
}

fn build_subject(common_name: &str) -> Result<openssl::x509::X509Name> {
    let mut builder = X509NameBuilder::new()?;
    builder.append_entry_by_nid(Nid::COMMONNAME, common_name)?;
    Ok(builder.build())
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = value.len();
    if length < 0x80 {
        out.push(u8::try_from(length).expect("short DER length"));
    } else {
        let bytes: Vec<u8> = length
            .to_be_bytes()
            .into_iter()
            .skip_while(|byte| *byte == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).expect("DER length octets"));
        out.extend(bytes);
    }
    out.extend_from_slice(value);
    out
}

fn crl_distribution_point_extension(uri: &str) -> Result<X509Extension> {
    let ia5_uri = der_tlv(0x86, uri.as_bytes());
    let full_name = der_tlv(0xa0, &ia5_uri);
    let point = der_tlv(0xa0, &full_name);
    let points = der_tlv(0x30, &der_tlv(0x30, &point));
    Ok(X509Extension::new_from_der(
        Asn1Object::from_str(OID_CRL_DISTRIBUTION_POINTS)?.as_ref(),
        false,
        Asn1OctetString::new_from_bytes(&points)?.as_ref(),
    )?)
}

fn format_asn1_generalized_time(time: SystemTime) -> Result<String> {
    let total_seconds = time.duration_since(UNIX_EPOCH)?.as_secs();
    let days = i64::try_from(total_seconds / 86_400)?;
    let day_seconds = total_seconds % 86_400;
    // Civil date conversion by Howard Hinnant.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 {
        mp + 3
    } else {
        mp - 9
    };
    let year = yoe + era * 400 + i64::from(month <= 2);
    Ok(format!(
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}Z",
        day_seconds / 3600,
        (day_seconds % 3600) / 60,
        day_seconds % 60
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pki_generates_valid_mtls_and_crl_artifacts() -> Result<()> {
        let pki = TestPki::new()?;
        let server_with_crl =
            pki.ca
                .issue_server("localhost", 10, Some("http://127.0.0.1/root.crl"))?;
        let crl = pki.ca.sign_crl(1, Some(&server_with_crl))?;
        assert!(!crl.is_empty());
        assert_eq!(pki.client.sha256_hex()?.len(), 64);
        let _context = pki.mtls_server_context()?;
        let _untrusted = untrusted_server_context()?;
        Ok(())
    }
}
