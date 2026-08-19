//! Type-correct local TACACS+ error replies.

use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::authentication::reply::AuthenticationReply;
use tacacsrs_messages::authorization::reply::AuthorizationReply;
use tacacsrs_messages::enumerations::{
    TacacsAccountingStatus, TacacsAuthenticationReplyFlags, TacacsAuthenticationStatus,
    TacacsAuthorizationStatus, TacacsFlags, TacacsType,
};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_messages::traits::TacacsBodyTrait;

pub(super) fn local_error_reply(request: &Packet, message: &str) -> anyhow::Result<Packet> {
    let body = match request.header().tacacs_type {
        TacacsType::TacPlusAuthentication => AuthenticationReply {
            status: TacacsAuthenticationStatus::TacPlusAuthenStatusError,
            flags: TacacsAuthenticationReplyFlags::empty(),
            server_msg: message.to_owned(),
            data: Vec::new(),
        }
        .to_bytes()?,
        TacacsType::TacPlusAuthorisation => AuthorizationReply {
            status: TacacsAuthorizationStatus::TacPlusError,
            server_msg: message.to_owned(),
            data: String::new(),
            args: Vec::new(),
        }
        .to_bytes()?,
        TacacsType::TacPlusAccounting => AccountingReply {
            status: TacacsAccountingStatus::TacPlusAcctStatusError,
            server_msg: message.to_owned(),
            data: String::new(),
        }
        .to_bytes()?,
    };
    let sequence = request
        .header()
        .seq_no
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("TACACS+ error reply sequence exceeds 255"))?;
    let length = u32::try_from(body.len())?;
    Packet::new(
        Header {
            major_version: request.header().major_version,
            minor_version: request.header().minor_version,
            tacacs_type: request.header().tacacs_type,
            seq_no: sequence,
            flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            session_id: request.header().session_id,
            length,
        },
        body,
    )
}
