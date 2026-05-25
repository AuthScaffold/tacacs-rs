use tacacsrs_messages::authorization::reply::AuthorizationReply;
use tacacsrs_messages::authorization::request::AuthorizationRequest;
use tacacsrs_messages::enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_messages::traits::TacacsBodyTrait;

/// Builds a TACACS+ authorization packet ready to send.
///
/// The standard unencrypted flag is always set; callers can add protocol
/// negotiation or custom flags through `custom_flags`.
///
/// # Errors
///
/// Returns an error if the serialized request is too large for a TACACS+
/// header or if the packet cannot be constructed.
pub fn build_authorization_packet(
    session_id: u32,
    seq_no: u8,
    request: &AuthorizationRequest,
    custom_flags: TacacsFlags,
) -> anyhow::Result<Packet> {
    let data = request.to_bytes()?;
    let length = u32::try_from(data.len())
        .map_err(|_| anyhow::Error::msg("authorization request payload exceeds u32 length"))?;
    let flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG | custom_flags;

    Packet::new(
        Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAuthorisation,
            seq_no,
            flags,
            session_id,
            length,
        },
        data,
    )
}

/// Parses an authorization reply from a response packet.
///
/// # Errors
///
/// Returns an error if the packet body is not a valid TACACS+ authorization reply.
pub fn parse_authorization_reply(response: &Packet) -> anyhow::Result<AuthorizationReply> {
    AuthorizationReply::from_bytes(response.body())
}
