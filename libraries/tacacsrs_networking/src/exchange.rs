//! Fixed TACACS+ request/reply exchanges.

use tacacsrs_messages::enumerations::{TacacsMinorVersion, TacacsType};

/// Describes one TACACS+ request followed by exactly one reply.
///
/// Networking owns packet headers, session identifiers, sequence numbers, and
/// transport flags. Implementations only serialize the operation-specific
/// request body and parse the validated reply body.
pub trait FixedExchange: Send {
    /// Typed reply produced by this exchange.
    type Reply: Send;

    /// Returns the TACACS+ packet type used for both request and reply.
    fn packet_type(&self) -> TacacsType;

    /// Returns the TACACS+ minor version required by this exchange.
    fn minor_version(&self) -> TacacsMinorVersion;

    /// Serializes the request packet body.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be represented on the wire.
    fn encode_request(&self) -> anyhow::Result<Vec<u8>>;

    /// Parses the reply body after networking validates its packet header.
    ///
    /// # Errors
    ///
    /// Returns an error when the server reply body is invalid for this exchange.
    fn decode_reply(self, body: &[u8]) -> anyhow::Result<Self::Reply>;
}
