//! TACACS+ reply status classification for proxy session lifetime decisions.

use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::authentication::reply::AuthenticationReply;
use tacacsrs_messages::authorization::reply::AuthorizationReply;
use tacacsrs_messages::enumerations::{
    TacacsAccountingStatus, TacacsAuthenticationStatus, TacacsAuthorizationStatus, TacacsType,
};
use tacacsrs_messages::packet::{Packet, PacketTrait};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReplyAction {
    Continue,
    Complete,
    Unsupported(u8),
}

pub(super) fn reply_action(packet: &Packet) -> ReplyAction {
    match packet.header().tacacs_type {
        TacacsType::TacPlusAccounting => accounting_reply_action(packet),
        TacacsType::TacPlusAuthorisation => authorization_reply_action(packet),
        TacacsType::TacPlusAuthentication => authentication_reply_action(packet),
    }
}

fn accounting_reply_action(packet: &Packet) -> ReplyAction {
    let status = AccountingReply::status_from_packet(packet).unwrap_or_default();
    match TacacsAccountingStatus::try_from(status) {
        Ok(
            TacacsAccountingStatus::TacPlusAcctStatusSuccess
            | TacacsAccountingStatus::TacPlusAcctStatusError
            | TacacsAccountingStatus::TacPlusAcctStatusFollow,
        ) => ReplyAction::Complete,
        Err(_) => ReplyAction::Unsupported(status),
    }
}

fn authorization_reply_action(packet: &Packet) -> ReplyAction {
    let status = AuthorizationReply::status_from_packet(packet).unwrap_or_default();
    match TacacsAuthorizationStatus::try_from(status) {
        Ok(
            TacacsAuthorizationStatus::TacPlusPassAdd
            | TacacsAuthorizationStatus::TacPlusPassRepl
            | TacacsAuthorizationStatus::TacPlusFail
            | TacacsAuthorizationStatus::TacPlusError
            | TacacsAuthorizationStatus::TacPlusFollow,
        ) => ReplyAction::Complete,
        Err(_) => ReplyAction::Unsupported(status),
    }
}

fn authentication_reply_action(packet: &Packet) -> ReplyAction {
    let status = AuthenticationReply::status_from_packet(packet).unwrap_or_default();
    match TacacsAuthenticationStatus::try_from(status) {
        Ok(
            TacacsAuthenticationStatus::TacPlusAuthenStatusGetdata
            | TacacsAuthenticationStatus::TacPlusAuthenStatusGetuser
            | TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass,
        ) => ReplyAction::Continue,
        Ok(
            TacacsAuthenticationStatus::TacPlusAuthenStatusPass
            | TacacsAuthenticationStatus::TacPlusAuthenStatusFail
            | TacacsAuthenticationStatus::TacPlusAuthenStatusRestart
            | TacacsAuthenticationStatus::TacPlusAuthenStatusError
            | TacacsAuthenticationStatus::TacPlusAuthenStatusFollow,
        ) => ReplyAction::Complete,
        Err(_) => ReplyAction::Unsupported(status),
    }
}

#[cfg(test)]
mod tests {
    use tacacsrs_messages::accounting::reply::{ACCOUNTING_REPLY_STATUS_OFFSET, AccountingReply};
    use tacacsrs_messages::authentication::reply::{
        AUTHENTICATION_REPLY_STATUS_OFFSET, AuthenticationReply,
    };
    use tacacsrs_messages::authorization::reply::{
        AUTHORIZATION_REPLY_STATUS_OFFSET, AuthorizationReply,
    };
    use tacacsrs_messages::enumerations::{
        TacacsAccountingStatus, TacacsAuthenticationReplyFlags, TacacsAuthenticationStatus,
        TacacsAuthorizationStatus, TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType,
    };
    use tacacsrs_messages::header::Header;
    use tacacsrs_messages::packet::Packet;
    use tacacsrs_messages::traits::TacacsBodyTrait;

    use super::{ReplyAction, reply_action};

    fn test_packet(tacacs_type: TacacsType, session_id: u32, body: Vec<u8>) -> Packet {
        Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type,
                seq_no: 2,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                session_id,
                length: u32::try_from(body.len()).unwrap(),
            },
            body,
        )
        .unwrap()
    }

    fn accounting_reply_body(status: TacacsAccountingStatus) -> Vec<u8> {
        AccountingReply {
            status,
            server_msg: "ok".to_owned(),
            data: "display".to_owned(),
        }
        .to_bytes()
        .unwrap()
    }

    fn authorization_reply_body(status: TacacsAuthorizationStatus) -> Vec<u8> {
        AuthorizationReply {
            status,
            server_msg: "ok".to_owned(),
            data: "display".to_owned(),
            args: vec!["priv-lvl=15".to_owned()],
        }
        .to_bytes()
        .unwrap()
    }

    fn authentication_reply_body(status: TacacsAuthenticationStatus) -> Vec<u8> {
        AuthenticationReply {
            status,
            flags: TacacsAuthenticationReplyFlags::empty(),
            server_msg: "ok".to_owned(),
            data: vec![1, 2, 3],
        }
        .to_bytes()
        .unwrap()
    }

    #[test]
    fn reply_action_classifies_accounting_statuses() {
        for status in [
            TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            TacacsAccountingStatus::TacPlusAcctStatusError,
            TacacsAccountingStatus::TacPlusAcctStatusFollow,
        ] {
            assert_eq!(
                reply_action(&test_packet(
                    TacacsType::TacPlusAccounting,
                    1,
                    accounting_reply_body(status),
                )),
                ReplyAction::Complete,
            );
        }
    }

    #[test]
    fn reply_action_classifies_authorization_statuses() {
        for status in [
            TacacsAuthorizationStatus::TacPlusPassAdd,
            TacacsAuthorizationStatus::TacPlusPassRepl,
            TacacsAuthorizationStatus::TacPlusFail,
            TacacsAuthorizationStatus::TacPlusError,
            TacacsAuthorizationStatus::TacPlusFollow,
        ] {
            assert_eq!(
                reply_action(&test_packet(
                    TacacsType::TacPlusAuthorisation,
                    1,
                    authorization_reply_body(status),
                )),
                ReplyAction::Complete,
            );
        }
    }

    #[test]
    fn reply_action_classifies_unknown_statuses_as_unsupported() {
        let mut accounting_body =
            accounting_reply_body(TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        accounting_body[ACCOUNTING_REPLY_STATUS_OFFSET] = 0xff;
        assert_eq!(
            reply_action(&test_packet(TacacsType::TacPlusAccounting, 1, accounting_body,)),
            ReplyAction::Unsupported(0xff),
        );

        let mut authorization_body =
            authorization_reply_body(TacacsAuthorizationStatus::TacPlusPassAdd);
        authorization_body[AUTHORIZATION_REPLY_STATUS_OFFSET] = 0xff;
        assert_eq!(
            reply_action(&test_packet(TacacsType::TacPlusAuthorisation, 1, authorization_body,)),
            ReplyAction::Unsupported(0xff),
        );

        let mut authentication_body =
            authentication_reply_body(TacacsAuthenticationStatus::TacPlusAuthenStatusPass);
        authentication_body[AUTHENTICATION_REPLY_STATUS_OFFSET] = 0xff;
        assert_eq!(
            reply_action(&test_packet(TacacsType::TacPlusAuthentication, 1, authentication_body,)),
            ReplyAction::Unsupported(0xff),
        );
    }

    #[test]
    fn reply_action_classifies_authentication_statuses() {
        for status in [
            TacacsAuthenticationStatus::TacPlusAuthenStatusGetdata,
            TacacsAuthenticationStatus::TacPlusAuthenStatusGetuser,
            TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass,
        ] {
            assert_eq!(
                reply_action(&test_packet(
                    TacacsType::TacPlusAuthentication,
                    1,
                    authentication_reply_body(status),
                )),
                ReplyAction::Continue,
            );
        }

        for status in [
            TacacsAuthenticationStatus::TacPlusAuthenStatusPass,
            TacacsAuthenticationStatus::TacPlusAuthenStatusFail,
            TacacsAuthenticationStatus::TacPlusAuthenStatusRestart,
            TacacsAuthenticationStatus::TacPlusAuthenStatusError,
            TacacsAuthenticationStatus::TacPlusAuthenStatusFollow,
        ] {
            assert_eq!(
                reply_action(&test_packet(
                    TacacsType::TacPlusAuthentication,
                    1,
                    authentication_reply_body(status),
                )),
                ReplyAction::Complete,
            );
        }
    }
}
