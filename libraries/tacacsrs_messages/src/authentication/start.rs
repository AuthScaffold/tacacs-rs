use std::io::Cursor;

use anyhow::Context;
use byteorder::ReadBytesExt;
use num_enum::TryFromPrimitive;

use crate::enumerations::{
    TacacsAuthenticationAction, TacacsAuthenticationService, TacacsAuthenticationType,
};
use crate::helpers::{read_bytes, read_string};
use crate::packet::{Packet, PacketTrait};
use crate::traits::TacacsBodyTrait;

const AUTHENTICATION_START_MIN_LENGTH: usize = 8;

//  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
// +----------------+----------------+----------------+----------------+
// |    action      |    priv_lvl    |  authen_type   | authen_service |
// +----------------+----------------+----------------+----------------+
// |    user_len    |    port_len    |  rem_addr_len  |    data_len    |
// +----------------+----------------+----------------+----------------+
// |    user ...
// +----------------+----------------+----------------+----------------+
// |    port ...
// +----------------+----------------+----------------+----------------+
// |    rem_addr ...
// +----------------+----------------+----------------+----------------+
// |    data...
// +----------------+----------------+----------------+----------------+

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationStart {
    pub action: TacacsAuthenticationAction,
    pub priv_lvl: u8,
    pub authen_type: TacacsAuthenticationType,
    pub authen_service: TacacsAuthenticationService,
    pub user: String,
    pub port: String,
    pub rem_address: String,
    pub data: Vec<u8>,
}

impl AuthenticationStart {
    /// # Errors
    /// Returns an error if the packet body is too short or contains invalid fields.
    pub fn from_packet(packet: &Packet) -> anyhow::Result<Self> {
        let expected_length = Self::size_from_bytes(packet.body())
            .context("unable to determine expected length of authentication start packet")?;
        if packet.body().len() < expected_length {
            anyhow::bail!(
                "invalid authentication start body length: expected {expected_length}, actual {}",
                packet.body().len()
            );
        }

        Self::from_bytes(packet.body()).context("invalid TACACS+ authentication start")
    }

    fn size_from_bytes(data: &[u8]) -> anyhow::Result<usize> {
        if data.len() < AUTHENTICATION_START_MIN_LENGTH {
            anyhow::bail!(
                "body too short for authentication start fixed fields: expected at least {}, actual {}",
                AUTHENTICATION_START_MIN_LENGTH,
                data.len()
            );
        }

        Ok(AUTHENTICATION_START_MIN_LENGTH
            + usize::from(data[4])
            + usize::from(data[5])
            + usize::from(data[6])
            + usize::from(data[7]))
    }

    /// # Errors
    /// Returns an error if the data is too short or contains invalid field values.
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        let expected_length = Self::size_from_bytes(data)?;
        if data.len() < expected_length {
            anyhow::bail!(
                "data too short for authentication start: expected {expected_length}, actual {}",
                data.len()
            );
        }

        let mut cursor = Cursor::new(data);
        let action = TacacsAuthenticationAction::try_from_primitive(
            cursor.read_u8().context("unable to read action")?,
        )
        .context("invalid authentication action")?;
        let priv_lvl = cursor.read_u8().context("unable to read priv_lvl")?;
        let authen_type = TacacsAuthenticationType::try_from_primitive(
            cursor.read_u8().context("unable to read authen_type")?,
        )
        .context("invalid authentication authen_type")?;
        let authen_service = TacacsAuthenticationService::try_from_primitive(
            cursor.read_u8().context("unable to read authen_service")?,
        )
        .context("invalid authentication authen_service")?;
        let user_len = cursor.read_u8().context("unable to read user_len")?;
        let port_len = cursor.read_u8().context("unable to read port_len")?;
        let rem_addr_len = cursor.read_u8().context("unable to read rem_addr_len")?;
        let data_len = cursor.read_u8().context("unable to read data_len")?;

        let user = read_string(&mut cursor, usize::from(user_len))?;
        let port = read_string(&mut cursor, usize::from(port_len))?;
        let rem_address = read_string(&mut cursor, usize::from(rem_addr_len))?;
        let data = read_bytes(&mut cursor, usize::from(data_len))?;

        Ok(Self {
            action,
            priv_lvl,
            authen_type,
            authen_service,
            user,
            port,
            rem_address,
            data,
        })
    }
}

impl TacacsBodyTrait for AuthenticationStart {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let user_len = u8::try_from(self.user.len())
            .context("authentication start user field exceeds 255 bytes")?;
        let port_len = u8::try_from(self.port.len())
            .context("authentication start port field exceeds 255 bytes")?;
        let rem_addr_len = u8::try_from(self.rem_address.len())
            .context("authentication start rem_address field exceeds 255 bytes")?;
        let data_len = u8::try_from(self.data.len())
            .context("authentication start data field exceeds 255 bytes")?;

        let total = AUTHENTICATION_START_MIN_LENGTH
            + self.user.len()
            + self.port.len()
            + self.rem_address.len()
            + self.data.len();

        let mut bytes = Vec::with_capacity(total);
        bytes.push(self.action as u8);
        bytes.push(self.priv_lvl);
        bytes.push(self.authen_type as u8);
        bytes.push(self.authen_service as u8);
        bytes.push(user_len);
        bytes.push(port_len);
        bytes.push(rem_addr_len);
        bytes.push(data_len);
        bytes.extend(self.user.as_bytes());
        bytes.extend(self.port.as_bytes());
        bytes.extend(self.rem_address.as_bytes());
        bytes.extend(&self.data);

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType};
    use crate::header::Header;

    #[test]
    fn authentication_start_round_trips() {
        let start = AuthenticationStart {
            action: TacacsAuthenticationAction::TacPlusAuthenLogin,
            priv_lvl: 15,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypePap,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcLogin,
            user: "admin".to_owned(),
            port: "tty1".to_owned(),
            rem_address: "192.0.2.10".to_owned(),
            data: b"password".to_vec(),
        };

        let decoded = AuthenticationStart::from_bytes(&start.to_bytes().unwrap()).unwrap();

        assert_eq!(decoded, start);
    }

    #[test]
    fn authentication_start_accepts_standard_sendauth_action() {
        let body = vec![
            0x04,
            15,
            TacacsAuthenticationType::TacPlusAuthenTypeAscii as u8,
            TacacsAuthenticationService::TacPlusAuthenSvcLogin as u8,
            0,
            0,
            0,
            0,
        ];

        let decoded = AuthenticationStart::from_bytes(&body).unwrap();

        assert_eq!(decoded.action, TacacsAuthenticationAction::TacPlusAuthenSendauth);
    }

    #[test]
    fn authentication_start_from_packet_validates_length() {
        let body = vec![
            TacacsAuthenticationAction::TacPlusAuthenLogin as u8,
            15,
            TacacsAuthenticationType::TacPlusAuthenTypeAscii as u8,
            TacacsAuthenticationService::TacPlusAuthenSvcLogin as u8,
            5,
            0,
            0,
            0,
            b'a',
        ];
        let packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAuthentication,
                seq_no: 1,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                session_id: 1,
                length: u32::try_from(body.len()).unwrap(),
            },
            body,
        )
        .unwrap();

        let err = AuthenticationStart::from_packet(&packet).unwrap_err();

        assert!(
            err.to_string()
                .contains("invalid authentication start body length"),
            "Error actual: {err}"
        );
    }

    #[test]
    fn authentication_start_rejects_invalid_action() {
        let mut body = AuthenticationStart {
            action: TacacsAuthenticationAction::TacPlusAuthenLogin,
            priv_lvl: 15,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeAscii,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcLogin,
            user: String::new(),
            port: String::new(),
            rem_address: String::new(),
            data: Vec::new(),
        }
        .to_bytes()
        .unwrap();
        body[0] = 0xff;

        let err = AuthenticationStart::from_bytes(&body).unwrap_err();

        assert!(err.to_string().contains("invalid authentication action"), "Error actual: {err}");
    }
}
