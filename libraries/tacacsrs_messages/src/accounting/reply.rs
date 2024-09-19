use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt};
use num_enum::TryFromPrimitive;
use crate::{constants::TACACS_ACCOUNTING_REPLY_MIN_LENGTH, helpers::read_string, traits::TacacsBodyTrait};
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


#[derive(Debug)]
pub struct AccountingReply {
    pub status: TacacsAccountingStatus,
    pub server_msg: String,
    pub data: String,
}

impl AccountingReply {
    pub fn from_packet(packet: &Packet) -> Result<Self, anyhow::Error> {
        let expected_length = Self::size_from_bytes(packet.body()).with_context(|| "Unable to determine expected length of packet")?;
        if packet.body().len() < expected_length {
            return Err(anyhow::Error::msg(format!("Packet body length does not match expected length. Expected: {}, Actual: {}", expected_length, packet.body().len())));
        }

        match Self::from_bytes(packet.body()).with_context(|| "Unable to convert packet body to Reply") {
            Ok(reply) => Ok(reply),
            Err(err) => Err(err),
        }
    }

    fn size_from_bytes(data : &[u8]) -> Result<usize, anyhow::Error> {       
        let mut cursor = Cursor::new(data);

        let server_msg_len = match cursor.read_u16::<BigEndian>().with_context(|| "Unable to read server_msg_len") {
            Ok(len) => len as usize,
            Err(err) => return Err(err),
        };

        let data_len = match cursor.read_u16::<BigEndian>().with_context(|| "Unable to read data_len") {
            Ok(len) => len as usize,
            Err(err) => return Err(err),
        };

        Ok(TACACS_ACCOUNTING_REPLY_MIN_LENGTH + server_msg_len + data_len)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        let mut cursor = Cursor::new(bytes);

        let server_msg_len = match cursor.read_u16::<BigEndian>().with_context(|| "Unable to read server_msg_len") {
            Ok(len) => len as usize,
            Err(err) => return Err(err),
        };

        let data_len = match cursor.read_u16::<BigEndian>().with_context(|| "Unable to read data_len") {
            Ok(len) => len as usize,
            Err(err) => return Err(err),
        };

        let status = match cursor.read_u8().with_context(|| "Unable to read status") {
            Ok(status) => TacacsAccountingStatus::try_from_primitive(status).with_context(|| "Unable to convert status to TacacsAccountingStatus")?,
            Err(err) => return Err(err),
        };

        let server_msg = match read_string(&mut cursor, server_msg_len).with_context(|| "Unable to read server_msg") {
            Ok(msg) => msg,
            Err(err) => return Err(err),
        };

        let data = match read_string(&mut cursor, data_len).with_context(|| "Unable to read data") {
            Ok(data) => data,
            Err(err) => return Err(err),
        };

        Ok(AccountingReply{status, server_msg, data})
    }

    
}


impl TacacsBodyTrait for AccountingReply
{
    fn to_bytes(&self) -> Vec<u8> {
        let bytes = vec![
            (self.server_msg.len() >> 8) as u8,
            self.server_msg.len() as u8,
            (self.data.len() >> 8) as u8,
            self.data.len() as u8,
            self.status as u8,
        ];

        let mut bytes = bytes;
        bytes.extend(self.server_msg.as_bytes());
        bytes.extend(self.data.as_bytes());
        bytes
    }
}


#[cfg(test)]
pub mod tests
{
    use crate::{
        enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType},
        header::Header
    };

    use super::*;

    fn generate_accounting_reply_data() -> Vec<u8> {
        let server_message_string = "server_msg";
        let data_string = "data";

        let mut data : Vec<u8> = Vec::new();
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
    fn test_read_bytes_incorrect_status() {
        let mut data = generate_accounting_reply_data();
        data[4] = 0xff; // status is set to 0xff

        let reply = AccountingReply::from_bytes(&data);

        assert!(reply.is_err());
        
        let error = reply.unwrap_err();
        assert!(
            error.to_string().contains("Unable to convert status to TacacsAccountingStatus"),
            "Actual Error: {}", error);
    }

    #[test]
    fn test_read_bytes_truncated() {
        let data = generate_accounting_reply_data();
        let reply = AccountingReply::from_bytes(&data[..data.len()-1]);

        assert!(reply.is_err());

        let error = reply.unwrap_err();
        assert!(
            error.to_string().contains("Unable to read data"),
            "Actual Error: {}", error);
    }

    #[test]
    fn test_reply_to_bytes() {
        let bytes = generate_accounting_reply_data();
        let reply = AccountingReply::from_bytes(&bytes).unwrap();

        assert_eq!(reply.to_bytes(), bytes);
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
    }

    #[test]
    fn test_reply_from_packet_invalid_length() {
        let mut data = generate_accounting_reply_data();
        data[0] = 0xff; // first byte of server_msg_len is set to 0xff

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
        assert!(reply.unwrap_err().to_string().contains("Packet body length does not match expected length"));
    }
}
