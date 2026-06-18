use std::io::Cursor;

use anyhow::Context;
use byteorder::{BigEndian, ReadBytesExt};
use num_enum::TryFromPrimitive;

use crate::enumerations::{TacacsAuthenticationReplyFlags, TacacsAuthenticationStatus};
use crate::helpers::{read_bytes, read_string};
use crate::packet::{Packet, PacketTrait};
use crate::traits::TacacsBodyTrait;

const AUTHENTICATION_REPLY_MIN_LENGTH: usize = 6;

/// The byte offset of the status field within an authentication reply body.
pub const AUTHENTICATION_REPLY_STATUS_OFFSET: usize = 0;

//  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
// +----------------+----------------+----------------+----------------+
// |     status     |      flags     |        server_msg_len           |
// +----------------+----------------+----------------+----------------+
// |           data_len              |        server_msg ...
// +----------------+----------------+----------------+----------------+
// |           data ...
// +----------------+----------------+

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationReply {
    pub status: TacacsAuthenticationStatus,
    pub flags: TacacsAuthenticationReplyFlags,
    pub server_msg: String,
    pub data: Vec<u8>,
}

impl AuthenticationReply {
    #[must_use]
    pub fn status_from_packet(packet: &Packet) -> Option<u8> {
        Self::status_from_bytes(packet.body())
    }

    #[must_use]
    pub fn status_from_bytes(data: &[u8]) -> Option<u8> {
        data.get(AUTHENTICATION_REPLY_STATUS_OFFSET).copied()
    }

    /// # Errors
    /// Returns an error if the packet body is too short or contains invalid fields.
    pub fn from_packet(packet: &Packet) -> anyhow::Result<Self> {
        let expected_length = Self::size_from_bytes(packet.body())
            .context("unable to determine expected length of authentication reply packet")?;
        if packet.body().len() < expected_length {
            anyhow::bail!(
                "invalid authentication reply body length: expected {expected_length}, actual {}",
                packet.body().len()
            );
        }

        Self::from_bytes(packet.body()).context("invalid TACACS+ authentication reply")
    }

    fn size_from_bytes(data: &[u8]) -> anyhow::Result<usize> {
        if data.len() < AUTHENTICATION_REPLY_MIN_LENGTH {
            anyhow::bail!(
                "body too short for authentication reply fixed fields: expected at least {}, actual {}",
                AUTHENTICATION_REPLY_MIN_LENGTH,
                data.len()
            );
        }

        let msg_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
        let data_len = usize::from(u16::from_be_bytes([data[4], data[5]]));

        Ok(AUTHENTICATION_REPLY_MIN_LENGTH + msg_len + data_len)
    }

    /// # Errors
    /// Returns an error if the data is too short or contains invalid field values.
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        let expected_length = Self::size_from_bytes(data)?;
        if data.len() < expected_length {
            anyhow::bail!(
                "data too short for authentication reply: expected {expected_length}, actual {}",
                data.len()
            );
        }

        let mut cursor = Cursor::new(data);
        let status = TacacsAuthenticationStatus::try_from_primitive(
            cursor
                .read_u8()
                .context("unable to read authentication status")?,
        )
        .context("invalid authentication status")?;
        let flags = TacacsAuthenticationReplyFlags::from_bits(
            cursor
                .read_u8()
                .context("unable to read authentication reply flags")?,
        )
        .context("invalid authentication reply flags")?;
        let msg_len = cursor
            .read_u16::<BigEndian>()
            .context("unable to read msg_len")?;
        let data_len = cursor
            .read_u16::<BigEndian>()
            .context("unable to read data_len")?;

        let server_msg = read_string(&mut cursor, usize::from(msg_len))?;
        let data = read_bytes(&mut cursor, usize::from(data_len))?;

        Ok(Self {
            status,
            flags,
            server_msg,
            data,
        })
    }
}

impl TacacsBodyTrait for AuthenticationReply {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let msg_len = u16::try_from(self.server_msg.len())
            .context("authentication reply server_msg exceeds 65535 bytes")?;
        let data_len = u16::try_from(self.data.len())
            .context("authentication reply data exceeds 65535 bytes")?;

        let total = AUTHENTICATION_REPLY_MIN_LENGTH + self.server_msg.len() + self.data.len();

        let mut bytes = Vec::with_capacity(total);
        bytes.push(self.status as u8);
        bytes.push(self.flags.bits());
        bytes.extend(msg_len.to_be_bytes());
        bytes.extend(data_len.to_be_bytes());
        bytes.extend(self.server_msg.as_bytes());
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
    fn authentication_reply_round_trips() {
        let reply = AuthenticationReply {
            status: TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass,
            flags: TacacsAuthenticationReplyFlags::TAC_PLUS_REPLY_FLAG_NOECHO,
            server_msg: "Password:".to_owned(),
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };

        let decoded = AuthenticationReply::from_bytes(&reply.to_bytes().unwrap()).unwrap();

        assert_eq!(decoded, reply);
    }

    #[test]
    fn authentication_reply_status_from_bytes() {
        let reply = AuthenticationReply {
            status: TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass,
            flags: TacacsAuthenticationReplyFlags::empty(),
            server_msg: "Password:".to_owned(),
            data: Vec::new(),
        };
        let body = reply.to_bytes().unwrap();

        let status = AuthenticationReply::status_from_bytes(&body).unwrap();

        assert_eq!(status, TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass as u8);
    }

    #[test]
    fn authentication_reply_from_packet_validates_length() {
        let body = vec![
            TacacsAuthenticationStatus::TacPlusAuthenStatusPass as u8,
            TacacsAuthenticationReplyFlags::empty().bits(),
            0,
            10,
            0,
            0,
            b'o',
            b'k',
        ];
        let packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAuthentication,
                seq_no: 2,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                session_id: 1,
                length: u32::try_from(body.len()).unwrap(),
            },
            body,
        )
        .unwrap();

        let err = AuthenticationReply::from_packet(&packet).unwrap_err();

        assert!(
            err.to_string()
                .contains("invalid authentication reply body length"),
            "Error actual: {err}"
        );
    }

    #[test]
    fn authentication_reply_status_from_packet() {
        let reply = AuthenticationReply {
            status: TacacsAuthenticationStatus::TacPlusAuthenStatusPass,
            flags: TacacsAuthenticationReplyFlags::empty(),
            server_msg: "ok".to_owned(),
            data: Vec::new(),
        };
        let body = reply.to_bytes().unwrap();
        let packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAuthentication,
                seq_no: 2,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                session_id: 1,
                length: u32::try_from(body.len()).unwrap(),
            },
            body,
        )
        .unwrap();

        let status = AuthenticationReply::status_from_packet(&packet).unwrap();

        assert_eq!(status, TacacsAuthenticationStatus::TacPlusAuthenStatusPass as u8);
    }

    #[test]
    fn authentication_reply_rejects_invalid_status() {
        let mut body = AuthenticationReply {
            status: TacacsAuthenticationStatus::TacPlusAuthenStatusPass,
            flags: TacacsAuthenticationReplyFlags::empty(),
            server_msg: String::new(),
            data: Vec::new(),
        }
        .to_bytes()
        .unwrap();
        body[AUTHENTICATION_REPLY_STATUS_OFFSET] = 0xff;

        let err = AuthenticationReply::from_bytes(&body).unwrap_err();

        assert!(err.to_string().contains("invalid authentication status"), "Error actual: {err}");
    }
}
