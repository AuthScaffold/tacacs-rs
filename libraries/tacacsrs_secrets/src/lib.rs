//! Secret value ownership with redacted formatting and zeroization on drop.

use std::fmt;

#[cfg(feature = "rfc7951")]
use base64::Engine;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Secret byte ownership that zeroizes its allocation on drop.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

/// Secret string ownership that zeroizes its allocation on drop.
pub struct SecretString(Zeroizing<String>);

impl SecretBytes {
    /// Takes ownership of secret bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Adopts an already-zeroizing allocation without copying the secret.
    ///
    /// Use this if code reads the secret into a [`Zeroizing<Vec<u8>>`]. The
    /// bytes stay protected from the initial read until [`SecretBytes`] owns
    /// them. No unprotected buffer exists between these steps.
    #[must_use]
    pub fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    /// Explicitly borrows the secret value.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Transfers the existing allocation into a non-zeroizing byte vector.
    ///
    /// This avoids copying secret bytes when ownership must cross into an
    /// external type that requires `Vec<u8>`, such as a generated protobuf
    /// request. The returned vector no longer zeroizes on drop. Callers must
    /// keep its lifetime short and must not log or persist it.
    #[must_use]
    pub fn into_unprotected_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut *self.0)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes(<redacted>)")
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::new(self.expose_secret().to_vec())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.expose_secret().ct_eq(other.expose_secret()).into()
    }
}

impl Eq for SecretBytes {}

#[cfg(feature = "rfc7951")]
impl serde::Serialize for SecretBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str("<redacted>")
    }
}

#[cfg(feature = "rfc7951")]
impl<'de> serde::Deserialize<'de> for SecretBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = <String as serde::Deserialize>::deserialize(deserializer)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)?;
        Ok(Self::new(bytes))
    }
}

impl SecretString {
    /// Takes ownership of a secret string.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Explicitly borrows the secret value.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString(<redacted>)")
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self::new(self.expose_secret().to_owned())
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.expose_secret()
            .as_bytes()
            .ct_eq(other.expose_secret().as_bytes())
            .into()
    }
}

impl Eq for SecretString {}

#[cfg(feature = "rfc7951")]
impl serde::Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str("<redacted>")
    }
}

#[cfg(feature = "rfc7951")]
impl<'de> serde::Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self::new(<String as serde::Deserialize>::deserialize(deserializer)?))
    }
}

#[cfg(test)]
mod tests {
    use super::{SecretBytes, SecretString};

    #[test]
    fn debug_redacts_secret_bytes() {
        let secret = SecretBytes::new(b"not-in-secret-debug".to_vec());
        let debug = format!("{secret:?}");

        assert_eq!(debug, "SecretBytes(<redacted>)");
        assert!(!debug.contains("not-in-secret-debug"));
        assert_eq!(secret.expose_secret(), b"not-in-secret-debug");
    }

    #[test]
    fn ownership_handoff_reuses_the_secret_allocation() {
        let secret = SecretBytes::new(b"handoff-secret".to_vec());
        let original_allocation = secret.expose_secret().as_ptr();

        let bytes = secret.into_unprotected_vec();

        assert_eq!(bytes, b"handoff-secret");
        assert_eq!(bytes.as_ptr(), original_allocation);
    }

    #[test]
    fn zeroizing_handoff_reuses_the_secret_allocation() {
        let protected = zeroize::Zeroizing::new(b"zeroizing-handoff-secret".to_vec());
        let original_allocation = protected.as_ptr();

        let secret = SecretBytes::from_zeroizing(protected);

        assert_eq!(secret.expose_secret(), b"zeroizing-handoff-secret");
        assert_eq!(secret.expose_secret().as_ptr(), original_allocation);
    }

    #[test]
    fn clones_compare_by_secret_value_and_redact_debug() {
        let bytes = SecretBytes::new(b"clone-secret".to_vec());
        let bytes_clone = bytes.clone();
        assert_eq!(bytes, bytes_clone);
        assert_ne!(bytes, SecretBytes::new(b"different-secret".to_vec()));

        let string = SecretString::new("clone-secret".to_owned());
        let string_clone = string.clone();
        assert_eq!(string, string_clone);
        assert_ne!(string, SecretString::new("different-secret".to_owned()));
        assert_eq!(format!("{string:?}"), "SecretString(<redacted>)");
    }

    #[cfg(feature = "rfc7951")]
    #[test]
    fn rfc7951_serde_redacts_and_deserializes_actual_scalar_rules() {
        let string = SecretString::new("string-secret".to_owned());
        let bytes = SecretBytes::new(b"binary-secret".to_vec());
        assert_eq!(serde_json::to_string(&string).unwrap(), r#""<redacted>""#);
        assert_eq!(serde_json::to_string(&bytes).unwrap(), r#""<redacted>""#);

        let parsed_string: SecretString = serde_json::from_str(r#""<redacted>""#).unwrap();
        assert_eq!(parsed_string.expose_secret(), "<redacted>");
        let parsed_bytes: SecretBytes = serde_json::from_str(r#""YmluYXJ5LXNlY3JldA==""#).unwrap();
        assert_eq!(parsed_bytes.expose_secret(), b"binary-secret");
        assert!(serde_json::from_str::<SecretBytes>(r#""<redacted>""#).is_err());
    }
}
