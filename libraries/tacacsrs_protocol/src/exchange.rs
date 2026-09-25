//! Pure descriptions of fixed TACACS+ request/reply exchanges.

pub mod accounting;
pub mod authentication;
pub mod authorization;

use crate::enumerations::{TacacsMinorVersion, TacacsType};

/// Describes one TACACS+ request and its single reply without performing I/O.
///
/// The executor supplies headers, session identifiers, sequence numbers, and
/// transport flags. An exchange encodes its body and decodes a validated reply.
pub trait FixedExchange: Send {
    /// Typed reply produced by this exchange.
    type Reply: Send;

    /// Returns the TACACS+ packet type for the request and reply.
    fn packet_type(&self) -> TacacsType;

    /// Returns the protocol minor version required by the exchange.
    fn minor_version(&self) -> TacacsMinorVersion;

    /// Encodes the request body.
    ///
    /// # Errors
    ///
    /// Returns an error if the request cannot be represented on the wire.
    fn encode_request(&self) -> anyhow::Result<Vec<u8>>;

    /// Decodes the reply body after the executor validates its header.
    ///
    /// # Errors
    ///
    /// Returns an error if the reply body is invalid for this exchange.
    fn decode_reply(self, body: &[u8]) -> anyhow::Result<Self::Reply>;
}
