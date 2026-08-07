//! Fixed accounting exchanges.

use tacacsrs_messages::accounting::{reply::AccountingReply, request::AccountingRequest};
use tacacsrs_messages::enumerations::{TacacsMinorVersion, TacacsType};
use tacacsrs_messages::traits::TacacsBodyTrait;
use tacacsrs_networking::FixedExchange;

/// One TACACS+ accounting request followed by one accounting reply.
#[derive(Debug)]
pub struct AccountingExchange {
    request: AccountingRequest,
}

impl AccountingExchange {
    /// Creates an accounting exchange from its protocol request body.
    #[must_use]
    pub const fn new(request: AccountingRequest) -> Self {
        Self { request }
    }
}


impl FixedExchange for AccountingExchange {
    type Reply = AccountingReply;

    fn packet_type(&self) -> TacacsType {
        TacacsType::TacPlusAccounting
    }

    fn minor_version(&self) -> TacacsMinorVersion {
        TacacsMinorVersion::TacacsPlusMinorVerDefault
    }

    fn encode_request(&self) -> anyhow::Result<Vec<u8>> {
        self.request.to_bytes()
    }

    fn decode_reply(self, body: &[u8]) -> anyhow::Result<Self::Reply> {
        AccountingReply::from_bytes(body)
    }
}

#[cfg(test)]
mod tests {
    use tacacsrs_messages::enumerations::{
        TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationMethod,
        TacacsAuthenticationService, TacacsAuthenticationType,
    };

    use super::*;

    #[test]
    fn exchange_encodes_request_and_decodes_reply() -> anyhow::Result<()> {
        let exchange = AccountingExchange::new(AccountingRequest {
            flags: TacacsAccountingFlags::START,
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
            priv_lvl: 0,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
            user: "admin".to_owned(),
            port: "tty0".to_owned(),
            rem_address: "192.0.2.1".to_owned(),
            args: vec!["service=shell".to_owned(), "cmd=show".to_owned()],
        });
        let request = AccountingRequest::from_bytes(&exchange.encode_request()?)?;
        assert_eq!(request.user, "admin");

        let body = AccountingReply {
            status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            server_msg: "accepted".to_owned(),
            data: String::new(),
        }
        .to_bytes()?;
        let reply = exchange.decode_reply(&body)?;
        assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        Ok(())
    }
}
