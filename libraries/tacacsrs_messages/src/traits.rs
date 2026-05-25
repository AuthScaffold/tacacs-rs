pub trait TacacsBodyTrait {
    /// Serializes this message body to its TACACS+ wire representation.
    ///
    /// # Errors
    /// Returns an error if a field value exceeds the protocol length limit.
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>>;
}
