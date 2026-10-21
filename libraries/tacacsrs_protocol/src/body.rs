//! TACACS+ message body serialization.

/// Serializes a TACACS+ message body to its wire representation.
pub trait TacacsBodyTrait {
    /// Serializes this message body to its TACACS+ wire representation.
    ///
    /// # Errors
    /// Returns an error if a field value exceeds the protocol length limit.
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>>;
}
