use std::sync::Arc;

use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService,
    TacacsAuthenticationType,
};
use tacacsrs_networking::session::Session;
use tacacsrs_networking::sessions::accounting_session::AccountingSessionTrait;

pub async fn send_accounting_request(
    session: &Arc<Session>,
    user: &str,
    port: &str,
    rem_address: &str,
    cmd: &String,
    cmd_args: &Option<Vec<String>>,
) -> anyhow::Result<AccountingReply> {
    let args = vec!["service=shell".to_string(), format!("cmd={}", cmd)].into_iter()
        .chain(
            cmd_args
                .as_ref()
                .unwrap_or(&Vec::new())
                .iter()
                .map(|arg| format!("cmd-arg={}", arg)),
        )
        .collect();

    let accounting_request = AccountingRequest {
        flags: TacacsAccountingFlags::START | TacacsAccountingFlags::STOP,
        authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
        priv_lvl: 0,
        authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
        authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
        user: user.to_owned(),
        port: port.to_owned(),
        rem_address: rem_address.to_owned(),
        args,
    };

    let session_clone = session.clone();
    let response = match session_clone.send_accounting_request(accounting_request).await {
        Ok(response) => response,
        Err(e) => {
            return Err(anyhow::Error::msg(format!(
                "Failed to send accounting request: {}",
                e
            )));
        }
    };

    println!("Received accounting response: {:?}", response);

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_accounting_request() {
        // let result = send_accounting_request(
        //     &"user".to_string(),
        //     &"port".to_string(),
        //     &"rem_addr".to_string(),
        //     &"cmd".to_string(),
        //     &Some(vec!["arg1".to_string(), "arg2".to_string()]),
        // );

        // assert!(result.is_ok())
    }
}
