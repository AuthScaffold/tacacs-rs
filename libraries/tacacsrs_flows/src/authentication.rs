//! Fixed authentication exchanges.

use tacacsrs_messages::authentication::{reply::AuthenticationReply, start::AuthenticationStart};
use tacacsrs_messages::enumerations::{
    TacacsAuthenticationAction, TacacsAuthenticationService, TacacsAuthenticationStatus,
    TacacsAuthenticationType, TacacsMinorVersion, TacacsType,
};
use tacacsrs_messages::traits::TacacsBodyTrait;
use tacacsrs_networking::FixedExchange;
use tacacsrs_secrets::SecretBytes;

/// One RFC 8907 PAP login START followed by one terminal REPLY.
#[derive(Debug)]
pub struct PapAuthenticationExchange {
    user: String,
    password: SecretBytes,
    port: String,
    remote_address: String,
    privilege_level: u8,
}

impl PapAuthenticationExchange {
    /// Creates a PAP login exchange.
    #[must_use]
    pub fn new(
        user: impl Into<String>,
        password: SecretBytes,
        port: impl Into<String>,
        remote_address: impl Into<String>,
        privilege_level: u8,
    ) -> Self {
        Self {
            user: user.into(),
            password,
            port: port.into(),
            remote_address: remote_address.into(),
            privilege_level,
        }
    }
}

impl FixedExchange for PapAuthenticationExchange {
    type Reply = AuthenticationReply;

    fn packet_type(&self) -> TacacsType {
        TacacsType::TacPlusAuthentication
    }

    fn minor_version(&self) -> TacacsMinorVersion {
        TacacsMinorVersion::TacacsPlusMinorVerOne
    }

    fn encode_request(&self) -> anyhow::Result<Vec<u8>> {
        AuthenticationStart {
            action: TacacsAuthenticationAction::TacPlusAuthenLogin,
            priv_lvl: self.privilege_level,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypePap,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcLogin,
            user: self.user.clone(),
            port: self.port.clone(),
            rem_address: self.remote_address.clone(),
            data: self.password.expose_secret().to_vec(),
        }
        .to_bytes()
    }

    fn decode_reply(self, body: &[u8]) -> anyhow::Result<Self::Reply> {
        let reply = AuthenticationReply::from_bytes(body)?;
        match reply.status {
            TacacsAuthenticationStatus::TacPlusAuthenStatusPass
            | TacacsAuthenticationStatus::TacPlusAuthenStatusFail
            | TacacsAuthenticationStatus::TacPlusAuthenStatusError => Ok(reply),
            status => anyhow::bail!("PAP authentication returned non-terminal status {status:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use tacacsrs_messages::enumerations::TacacsAuthenticationReplyFlags;

    use super::*;

    #[test]
    fn pap_exchange_uses_minor_version_one_and_start_data() -> anyhow::Result<()> {
        let exchange = PapAuthenticationExchange::new(
            "admin",
            SecretBytes::new(b"s3cr3t-value".to_vec()),
            "tty0",
            "192.0.2.1",
            15,
        );

        assert_eq!(exchange.packet_type(), TacacsType::TacPlusAuthentication);
        assert_eq!(exchange.minor_version(), TacacsMinorVersion::TacacsPlusMinorVerOne);
        let start = AuthenticationStart::from_bytes(&exchange.encode_request()?)?;
        assert_eq!(start.action, TacacsAuthenticationAction::TacPlusAuthenLogin);
        assert_eq!(start.authen_type, TacacsAuthenticationType::TacPlusAuthenTypePap);
        assert_eq!(start.authen_service, TacacsAuthenticationService::TacPlusAuthenSvcLogin);
        assert_eq!(start.user, "admin");
        assert_eq!(start.data, b"s3cr3t-value");
        assert!(!format!("{exchange:?}").contains("s3cr3t-value"));
        Ok(())
    }

    #[test]
    fn pap_exchange_accepts_only_terminal_reply_statuses() -> anyhow::Result<()> {
        for status in [
            TacacsAuthenticationStatus::TacPlusAuthenStatusPass,
            TacacsAuthenticationStatus::TacPlusAuthenStatusFail,
            TacacsAuthenticationStatus::TacPlusAuthenStatusError,
        ] {
            let exchange = exchange();
            let reply = AuthenticationReply {
                status,
                flags: TacacsAuthenticationReplyFlags::empty(),
                server_msg: String::new(),
                data: Vec::new(),
            };
            assert_eq!(exchange.decode_reply(&reply.to_bytes()?)?.status, status);
        }

        let reply = AuthenticationReply {
            status: TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass,
            flags: TacacsAuthenticationReplyFlags::empty(),
            server_msg: "Password:".to_owned(),
            data: Vec::new(),
        };
        assert!(exchange().decode_reply(&reply.to_bytes()?).is_err());
        Ok(())
    }

    fn exchange() -> PapAuthenticationExchange {
        PapAuthenticationExchange::new(
            "admin",
            SecretBytes::new(b"password".to_vec()),
            "tty0",
            "192.0.2.1",
            15,
        )
    }
}
