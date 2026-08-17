use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt};
use num_enum::TryFromPrimitive;
use crate::{
    constants::TACACS_ACCOUNTING_REPLY_MIN_LENGTH, helpers::read_string, traits::TacacsBodyTrait,
};
use crate::packet::{Packet, PacketTrait};
use anyhow::Context;
use crate::enumerations::TacacsAccountingStatus;

// 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
// +----------------+----------------+----------------+----------------+
// |         server_msg len          |            data_len             |
// +----------------+----------------+----------------+----------------+
// |     status     |         server_msg ...
// +----------------+----------------+----------------+----------------+
// |     data ...
// +----------------+

/// The byte offset of the status field within an accounting reply body.
pub const ACCOUNTING_REPLY_STATUS_OFFSET: usize = 4;

#[derive(Debug)]
pub struct AccountingReply {
    pub status: TacacsAccountingStatus,
    pub server_msg: String,
    pub data: String,
}

impl AccountingReply {
    #[must_use]
    pub fn status_from_packet(packet: &Packet) -> Option<u8> {
        Self::status_from_bytes(packet.body())
    }

    #[must_use]
    pub fn status_from_bytes(bytes: &[u8]) -> Option<u8> {
        bytes.get(ACCOUNTING_REPLY_STATUS_OFFSET).copied()
    }

    /// # Errors
    /// Returns an error if the packet body is too short or contains invalid fields.
    pub fn from_packet(packet: &Packet) -> Result<Self, anyhow::Error> {
        let expected_length = Self::size_from_bytes(packet.body())
            .with_context(|| "failed to determine the expected accounting reply length")?;
        if packet.body().len() < expected_length {
            return Err(anyhow::Error::msg(format!(
                "invalid accounting reply body length: expected {}, actual {}",
                expected_length,
                packet.body().len()
            )));
        }

        match Self::from_bytes(packet.body()).with_context(|| "invalid TACACS+ accounting reply") {
            Ok(reply) => Ok(reply),
            Err(err) => Err(err),
        }
    }

    fn size_from_bytes(data: &[u8]) -> Result<usize, anyhow::Error> {
        let mut cursor = Cursor::new(data);

        let server_msg_len = {
            let len = cursor
                .read_u16::<BigEndian>()
                .with_context(|| "failed to read server_msg_len")?;
            len as usize
        };

        let data_len = {
            let len = cursor
                .read_u16::<BigEndian>()
                .with_context(|| "failed to read data_len")?;
            len as usize
        };

        Ok(TACACS_ACCOUNTING_REPLY_MIN_LENGTH + server_msg_len + data_len)
    }

    /// # Errors
    /// Returns an error if the data is too short or contains invalid field values.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        let mut cursor = Cursor::new(bytes);

        let server_msg_len = {
            let len = cursor
                .read_u16::<BigEndian>()
                .with_context(|| "failed to read server_msg_len")?;
            len as usize
        };

        let data_len = {
            let len = cursor
                .read_u16::<BigEndian>()
                .with_context(|| "failed to read data_len")?;
            len as usize
        };

        let status = {
            let status = cursor.read_u8().with_context(|| "failed to read status")?;
            TacacsAccountingStatus::try_from_primitive(status)
                .with_context(|| "invalid accounting status")?
        };

        let server_msg = read_string(&mut cursor, server_msg_len)
            .with_context(|| "failed to read server_msg")?;

        let data = read_string(&mut cursor, data_len).with_context(|| "failed to read data")?;

        Ok(Self {
            status,
            server_msg,
            data,
        })
    }
}

impl TacacsBodyTrait for AccountingReply {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let server_msg_len = u16::try_from(self.server_msg.len())
            .context("accounting reply server_msg exceeds 65535 bytes")?;
        let data_len =
            u16::try_from(self.data.len()).context("accounting reply data exceeds 65535 bytes")?;

        let total = TACACS_ACCOUNTING_REPLY_MIN_LENGTH + self.server_msg.len() + self.data.len();

        let mut bytes = Vec::with_capacity(total);
        bytes.extend(server_msg_len.to_be_bytes());
        bytes.extend(data_len.to_be_bytes());
        bytes.push(self.status as u8);
        bytes.extend(self.server_msg.as_bytes());
        bytes.extend(self.data.as_bytes());
        Ok(bytes)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{
        enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType},
        header::Header,
    };

    use super::*;

    #[allow(clippy::cast_possible_truncation)] // The test data is small.
    fn generate_accounting_reply_data() -> Vec<u8> {
        let server_message_string = "server_msg";
        let data_string = "data";

        let mut data: Vec<u8> = Vec::new();
        data.extend((server_message_string.len() as u16).to_be_bytes()); // 0: server_msg_len
        data.extend((data_string.len() as u16).to_be_bytes()); // 1: data_len
        data.push(TacacsAccountingStatus::TacPlusAcctStatusSuccess as u8); // 2: status

        data.extend(server_message_string.as_bytes());
        data.extend(data_string.as_bytes());

        data
    }

    #[test]
    fn test_reply_from_bytes() {
        let bytes = generate_accounting_reply_data();
        let reply = AccountingReply::from_bytes(&bytes).unwrap();

        assert_eq!(reply.server_msg, "server_msg");
        assert_eq!(reply.data, "data");
        assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);
    }

    #[test]
    fn test_status_from_bytes() {
        let bytes = generate_accounting_reply_data();

        let status = AccountingReply::status_from_bytes(&bytes).unwrap();

        assert_eq!(status, TacacsAccountingStatus::TacPlusAcctStatusSuccess as u8);
    }

    #[test]
    fn test_read_bytes_incorrect_status() {
        let mut data = generate_accounting_reply_data();
        data[4] = 0xff; // Set status to 0xff.

        let reply = AccountingReply::from_bytes(&data);

        assert!(reply.is_err());

        let error = reply.unwrap_err();
        assert!(error.to_string().contains("invalid accounting status"), "Actual error: {error}");
    }

    #[test]
    fn test_read_bytes_truncated() {
        let data = generate_accounting_reply_data();
        let reply = AccountingReply::from_bytes(&data[..data.len() - 1]);

        assert!(reply.is_err());

        let error = reply.unwrap_err();
        assert!(error.to_string().contains("failed to read data"), "Actual error: {error}");
    }

    #[test]
    fn test_reply_to_bytes() {
        let bytes = generate_accounting_reply_data();
        let reply = AccountingReply::from_bytes(&bytes).unwrap();

        assert_eq!(reply.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn test_reply_size_from_bytes() {
        let bytes = generate_accounting_reply_data();
        let size = AccountingReply::size_from_bytes(&bytes).unwrap();

        assert_eq!(size, bytes.len());
    }

    #[test]
    fn test_reply_from_packet() {
        let data = generate_accounting_reply_data();
        #[allow(clippy::cast_possible_truncation)] // The test data is small.
        let header = Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAccounting,
            seq_no: 1,
            flags: TacacsFlags::empty(),
            session_id: 0,
            length: data.len() as u32,
        };

        let packet = Packet::new(header, data).unwrap();
        let reply = AccountingReply::from_packet(&packet).unwrap();

        assert_eq!(reply.server_msg, "server_msg");
        assert_eq!(reply.data, "data");
        assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        assert_eq!(
            AccountingReply::status_from_packet(&packet),
            Some(TacacsAccountingStatus::TacPlusAcctStatusSuccess as u8)
        );
    }

    #[test]
    fn test_reply_from_packet_invalid_length() {
        let mut data = generate_accounting_reply_data();
        data[0] = 0xff; // Set the first server_msg_len octet to 0xff.

        #[allow(clippy::cast_possible_truncation)] // The test data is small.
        let header = Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAccounting,
            seq_no: 1,
            flags: TacacsFlags::empty(),
            session_id: 0,
            length: data.len() as u32,
        };

        let packet = Packet::new(header, data).unwrap();
        let reply = AccountingReply::from_packet(&packet);

        assert!(reply.is_err());
        assert!(reply
            .unwrap_err()
            .to_string()
            .contains("invalid accounting reply body length"));
    }
}
