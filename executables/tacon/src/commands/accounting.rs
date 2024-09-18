use std::sync::Arc;

use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService,
    TacacsAuthenticationType,
};
use tacacsrs_messages::packet::Packet;
use tacacsrs_messages::traits::TacacsBodyTrait;
use tacacsrs_messages::{
    enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType},
    header::Header,
};
use tacacsrs_networking::sessions::Session;

pub fn send_accounting_request(
    session: &Arc<Session>,
    user: &str,
    port: &str,
    rem_address: &str,
    cmd: &String,
    cmd_args: &Option<Vec<String>>,
) -> anyhow::Result<Option<AccountingReply>> {
    let args = std::iter::once(format!("cmd={}", cmd))
        .chain(
            cmd_args
                .as_ref()
                .unwrap_or(&Vec::new())
                .iter()
                .map(|arg| format!("cmd-arg={}", arg)),
        )
        .collect();

    let request = AccountingRequest {
        flags: TacacsAccountingFlags::START,
        authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodTacacsplus,
        priv_lvl: 15,
        authen_type: TacacsAuthenticationType::TacPlusAuthenTypeAscii,
        authen_service: TacacsAuthenticationService::TacPlusAuthenSvcRcmd,
        user: user.to_owned(),
        port: port.to_owned(),
        rem_address: rem_address.to_owned(),
        args,
    };
    let request_bytes = request.to_bytes();

    let header = Header {
        major_version: TacacsMajorVersion::TacacsPlusMajor1,
        minor_version: TacacsMinorVersion::TacacsPlusMinorVerOne,
        tacacs_type: TacacsType::TacPlusAccounting,
        seq_no: 1,
        flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
        session_id: 0xdeadbeef,
        length: request_bytes.len() as u32,
    };

    let packet = Packet::new(header, request_bytes);
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_accounting_request() {
        let result = send_accounting_request(
            &"user".to_string(),
            &"port".to_string(),
            &"rem_addr".to_string(),
            &"cmd".to_string(),
            &Some(vec!["arg1".to_string(), "arg2".to_string()]),
        );

        assert!(result.is_ok())
    }
}
