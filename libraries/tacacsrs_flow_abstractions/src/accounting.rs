use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_messages::traits::TacacsBodyTrait;

/// Builds a TACACS+ accounting packet ready to send.
///
/// The standard unencrypted flag is always set; callers can add protocol
/// negotiation or custom flags through `custom_flags`.
pub fn build_accounting_packet(
    session_id: u32,
    seq_no: u8,
    request: &AccountingRequest,
    custom_flags: TacacsFlags,
) -> anyhow::Result<Packet> {
    let data = request.to_bytes();
    let length = u32::try_from(data.len())
        .map_err(|_| anyhow::Error::msg("Accounting request payload exceeds u32 length"))?;
    let flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG | custom_flags;

    Packet::new(
        Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAccounting,
            seq_no,
            flags,
            session_id,
            length,
        },
        data,
    )
}

/// Parses an accounting reply from a response packet.
pub fn parse_accounting_reply(response: &Packet) -> anyhow::Result<AccountingReply> {
    AccountingReply::from_bytes(response.body())
}
