use std::io::Cursor;

use anyhow::Context;
use byteorder::{BigEndian, ReadBytesExt};

use crate::enumerations::TacacsAuthenticationContinueFlags;
use crate::helpers::{read_bytes, read_string};
use crate::packet::{Packet, PacketTrait};
use crate::traits::TacacsBodyTrait;

const AUTHENTICATION_CONTINUE_MIN_LENGTH: usize = 5;

//  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
// +----------------+----------------+----------------+----------------+
// |          user_msg len           |            data_len             |
// +----------------+----------------+----------------+----------------+
// |     flags      |  user_msg ...
// +----------------+----------------+----------------+----------------+
// |    data ...
// +----------------+

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationContinue {
    pub user_msg: String,
    pub data: Vec<u8>,
    pub flags: TacacsAuthenticationContinueFlags,
}

impl AuthenticationContinue {
    /// # Errors
    /// Returns an error if the packet body is too short or contains invalid fields.
    pub fn from_packet(packet: &Packet) -> anyhow::Result<Self> {
        let expected_length = Self::size_from_bytes(packet.body())
            .context("unable to determine expected length of authentication continue packet")?;
        if packet.body().len() < expected_length {
            anyhow::bail!(
                "invalid authentication continue body length: expected {expected_length}, actual {}",
                packet.body().len()
            );
        }

        Self::from_bytes(packet.body()).context("invalid TACACS+ authentication continue")
    }

    fn size_from_bytes(data: &[u8]) -> anyhow::Result<usize> {
        if data.len() < AUTHENTICATION_CONTINUE_MIN_LENGTH {
            anyhow::bail!(
                "body too short for authentication continue fixed fields: expected at least {}, actual {}",
                AUTHENTICATION_CONTINUE_MIN_LENGTH,
                data.len()
            );
        }

        let user_msg_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
        let data_len = usize::from(u16::from_be_bytes([data[2], data[3]]));

        Ok(AUTHENTICATION_CONTINUE_MIN_LENGTH + user_msg_len + data_len)
    }

    /// # Errors
    /// Returns an error if the data is too short or contains invalid field values.
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        let expected_length = Self::size_from_bytes(data)?;
        if data.len() < expected_length {
            anyhow::bail!(
                "data too short for authentication continue: expected {expected_length}, actual {}",
                data.len()
            );
        }

        let mut cursor = Cursor::new(data);
        let user_msg_len = cursor
            .read_u16::<BigEndian>()
            .context("unable to read user_msg_len")?;
        let data_len = cursor
            .read_u16::<BigEndian>()
            .context("unable to read data_len")?;
        let flags = TacacsAuthenticationContinueFlags::from_bits(
            cursor
                .read_u8()
                .context("unable to read authentication continue flags")?,
        )
        .context("invalid authentication continue flags")?;

        let user_msg = read_string(&mut cursor, usize::from(user_msg_len))?;
        let data = read_bytes(&mut cursor, usize::from(data_len))?;

        Ok(Self {
            user_msg,
            data,
            flags,
        })
    }
}

impl TacacsBodyTrait for AuthenticationContinue {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let user_msg_len = u16::try_from(self.user_msg.len())
            .context("authentication continue user_msg exceeds 65535 bytes")?;
        let data_len = u16::try_from(self.data.len())
            .context("authentication continue data exceeds 65535 bytes")?;

        let total = AUTHENTICATION_CONTINUE_MIN_LENGTH + self.user_msg.len() + self.data.len();

        let mut bytes = Vec::with_capacity(total);
        bytes.extend(user_msg_len.to_be_bytes());
        bytes.extend(data_len.to_be_bytes());
        bytes.push(self.flags.bits());
        bytes.extend(self.user_msg.as_bytes());
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
    fn authentication_continue_round_trips() {
        let continue_packet = AuthenticationContinue {
            user_msg: "password".to_owned(),
            data: vec![1, 2, 3, 4],
            flags: TacacsAuthenticationContinueFlags::empty(),
        };

        let decoded =
            AuthenticationContinue::from_bytes(&continue_packet.to_bytes().unwrap()).unwrap();

        assert_eq!(decoded, continue_packet);
    }

    #[test]
    fn authentication_continue_from_packet_validates_length() {
        let body = vec![
            0,
            10,
            0,
            0,
            TacacsAuthenticationContinueFlags::empty().bits(),
            b'a',
        ];
        let packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAuthentication,
                seq_no: 3,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                session_id: 1,
                length: u32::try_from(body.len()).unwrap(),
            },
            body,
        )
        .unwrap();

        let err = AuthenticationContinue::from_packet(&packet).unwrap_err();

        assert!(
            err.to_string()
                .contains("invalid authentication continue body length"),
            "Error actual: {err}"
        );
    }

    #[test]
    fn authentication_continue_rejects_invalid_flags() {
        let mut body = AuthenticationContinue {
            user_msg: String::new(),
            data: Vec::new(),
            flags: TacacsAuthenticationContinueFlags::empty(),
        }
        .to_bytes()
        .unwrap();
        body[4] = 0xff;

        let err = AuthenticationContinue::from_bytes(&body).unwrap_err();

        assert!(
            err.to_string()
                .contains("invalid authentication continue flags"),
            "Error actual: {err}"
        );
    }
}
