use crate::enumerations::{TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService, TacacsAuthenticationType};
use crate::packet::Packet;
use crate::traits::TacacsBodyTrait;
use std::io::{Cursor, Read};
use byteorder::ReadBytesExt;
use anyhow::{Context, Result};
use num_enum::TryFromPrimitive;
use crate::constants::{TACACS_ACCOUNTING_REQUEST_MIN_LENGTH, TACACS_ACCOUNTING_ARG_SIZE_OFFSET};

// 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
// +----------------+----------------+----------------+----------------+
// |      flags     |  authen_method |    priv_lvl    |  authen_type   |
// +----------------+----------------+----------------+----------------+
// | authen_service |    user_len    |    port_len    |  rem_addr_len  |
// +----------------+----------------+----------------+----------------+
// |    arg_cnt     |   arg_1_len    |   arg_2_len    |      ...       |
// +----------------+----------------+----------------+----------------+
// |   arg_N_len    |    user ...
// +----------------+----------------+----------------+----------------+
// |   port ...
// +----------------+----------------+----------------+----------------+
// |   rem_addr ...
// +----------------+----------------+----------------+----------------+
// |   arg_1 ...
// +----------------+----------------+----------------+----------------+
// |   arg_2 ...
// +----------------+----------------+----------------+----------------+
// |   ...
// +----------------+----------------+----------------+----------------+
// |   arg_N ...
// +----------------+----------------+----------------+----------------+

#[derive(Debug)]
pub struct AccountingRequest {
    pub flags: TacacsAccountingFlags,
    pub authen_method: TacacsAuthenticationMethod,
    pub priv_lvl: u8,
    pub authen_type: TacacsAuthenticationType,
    pub authen_service: TacacsAuthenticationService,
    pub user: String,
    pub port: String,
    pub rem_address: String,
    pub args: Vec<String>
}

impl AccountingRequest {
    pub fn from_packet(packet : &Packet) -> Result<Self, anyhow::Error> {
        // Check if the packet the correct length
        let expected_length = Self::size_from_bytes(packet.body());
        if packet.body().len() < expected_length {
            return Err(anyhow::Error::msg(format!("Invalid body length. Expected: {}, Actual: {}", expected_length, packet.body().len())));
        }

        let accounting_request = match Self::from_bytes(packet.body()) {
            Ok(accounting_request) => accounting_request,
            Err(err) => {
                let context = format!("Invalid TACACS+ AccountingRequest. Conversion failed with error: {}", err);
                return Err(err).with_context(|| context)
            },
        };

        Ok(accounting_request)
    }

    fn size_from_bytes(data : &[u8]) -> usize {
        let mut length = TACACS_ACCOUNTING_REQUEST_MIN_LENGTH;

        let user_len = data[5];
        let port_len = data[6];
        let rem_addr_len = data[7];

        length += user_len as usize;
        length += port_len as usize;
        length += rem_addr_len as usize;

        // Calculate the length of the variable length arguments
        // the sizes of the arguments are stored as an array in
        // the data starting at the 9th byte.
        let arg_cnt = data[8];
        for i in 0..arg_cnt {
            let arg_len = data[TACACS_ACCOUNTING_ARG_SIZE_OFFSET + i as usize];
            length += arg_len as usize;
        }

        length
    }

    fn read_string(cursor : &mut Cursor<&[u8]>, len: usize) -> Result<String, anyhow::Error> {
        let remaining_buffer = cursor.get_ref().len() - cursor.position() as usize;
        if remaining_buffer < len {
            return Err(anyhow::Error::msg("Not enough data to read string. Remaining buffer too short"));
        }

        let mut buffer = vec![0; len];
        cursor.read_exact(&mut buffer).with_context(|| format!("Unable to read {} bytes from cursor", len))?;

        let string = String::from_utf8(buffer).with_context(|| "Unable to read data into UTF8 formatted string")?;

        Ok(string)
    }

    pub fn from_bytes(data : &[u8]) -> Result<Self, anyhow::Error> {
        if data.len() < TACACS_ACCOUNTING_REQUEST_MIN_LENGTH {
            return Err(anyhow::Error::msg("Data too short"));
        }

        let mut cursor = Cursor::new(data);

        let flags = match cursor.read_u8().with_context(|| "Invalid flags. Unable to read data") {
            Ok(a) => TacacsAccountingFlags::from_bits(a).with_context(|| "Invalid flags. Conversion failed with error")?,
            Err(err) => return Err(err),
        };

        let authen_method = match cursor.read_u8().with_context(|| "Invalid authen_method. Unable to read data") {
            Ok(data) => TacacsAuthenticationMethod::try_from_primitive(data).with_context(|| "Invalid authen_method. Conversion failed with error")?,
            Err(err) => return Err(err),
        };

        let priv_lvl = match cursor.read_u8().with_context(|| "Invalid priv_lvl. Unable to read data") {
            Ok(data) => data,
            Err(err) => return Err(err),
        };

        let authen_type = match cursor.read_u8().with_context(|| "Invalid authen_type. Unable to read data: {}") {
            Ok(data) => TacacsAuthenticationType::try_from_primitive(data).with_context(|| "Invalid authen_type. Conversion failed with error")?,
            Err(err) => return Err(err),
        };

        let authen_service = match cursor.read_u8().with_context(|| "Invalid authen_service. Unable to read data") {
            Ok(a) => TacacsAuthenticationService::try_from_primitive(a).with_context(|| "Invalid authen_service. Conversion failed with error")?,
            Err(err) => return Err(err),
        };

        let user_len = match cursor.read_u8().with_context(|| "Invalid user_len. Unable to read data") {
            Ok(a) => a,
            Err(err) => return Err(err),
        };

        let port_len = match cursor.read_u8().with_context(|| "Invalid port_len. Unable to read data") {
            Ok(a) => a,
            Err(err) => return Err(err),
        };

        let rem_addr_len = match cursor.read_u8().with_context(|| "Invalid rem_addr_len. Unable to read data") {
            Ok(a) => a,
            Err(err) => return Err(err),
        };

        let arg_cnt = match cursor.read_u8().with_context(|| "Invalid arg_cnt. Unable to read data") {
            Ok(a) => a,
            Err(err) => return Err(err),
        };

        let mut arg_sizes : Vec<u8> = Vec::new();
        for _ in 0..arg_cnt {
            let arg_size = match cursor.read_u8().with_context(|| "Invalid arg_size. Unable to read data") {
                Ok(a) => a,
                Err(err) => return Err(err),
            };

            arg_sizes.push(arg_size);
        }

        let user = match Self::read_string(&mut cursor, user_len as usize).with_context(|| "Invalid user. Unable to read data") {
            Ok(a) => a,
            Err(err) => return Err(err),
        };

        let port = match Self::read_string(&mut cursor, port_len as usize).with_context(|| "Invalid port. Unable to read data") {
            Ok(a) => a,
            Err(err) => return Err(err),
        };

        let rem_address = match Self::read_string(&mut cursor, rem_addr_len as usize).with_context(|| "Invalid rem_address. Unable to read data") {
            Ok(a) => a,
            Err(err) => return Err(err),
        };

        let mut args : Vec<String> = Vec::new();
        for arg_size in arg_sizes {
            let arg = match Self::read_string(&mut cursor, arg_size as usize).with_context(|| "Invalid arg. Unable to read data") {
                Ok(a) => a,
                Err(err) => return Err(err),
            };

            args.push(arg);
        }


        Ok(AccountingRequest {
            flags,
            authen_method,
            priv_lvl,
            authen_type,
            authen_service,
            user,
            port,
            rem_address,
            args
        })
    }
}


impl TacacsBodyTrait for AccountingRequest
{
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = vec![
            self.flags.bits(),
            self.authen_method as u8,
            self.priv_lvl,
            self.authen_type as u8,
            self.authen_service as u8,
            self.user.len() as u8,
            self.port.len() as u8,
            self.rem_address.len() as u8,
            self.args.len() as u8,
        ];

        for arg in &self.args {
            data.push(arg.len() as u8);
        }

        data.extend(self.user.as_bytes());
        data.extend(self.port.as_bytes());
        data.extend(self.rem_address.as_bytes());
        for arg in &self.args {
            data.extend(arg.as_bytes());
        }

        data
    }
}

#[cfg(test)]
mod tests
{
    use crate::enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType};
    use crate::header::Header;

    use super::*;

    fn generate_accounting_request_data() -> Vec<u8>
    {
        let mut data : Vec<u8> = Vec::new();
        data.push(TacacsAccountingFlags::empty().bits()); // 0: flags
        data.push(TacacsAuthenticationMethod::TacPlusAuthenMethodTacacsplus as u8); // 1: authen_method
        data.push(0); // 2: priv_lvl
        data.push(TacacsAuthenticationType::TacPlusAuthenTypePap as u8); // 3: authen_type
        data.push(TacacsAuthenticationService::TacPlusAuthenSvcNone as u8); // 4: authen_service

        data.push(1); // 5: user_len
        data.push(1); // 6: port_len
        data.push(1); // 7: rem_addr_len
        data.push(3); // 8: arg_cnt
        data.push(1); // 9+0: arg_1_len
        data.push(1); // 9+1: arg_2_len
        data.push(1); // 9+2: arg_3_len

        data.push(b'A'); // 12: user
        data.push(b'B'); // 13: port
        data.push(b'C'); // 14: rem_addr
        data.push(b'D'); // 15: arg_1
        data.push(b'E'); // 16: arg_2
        data.push(b'F'); // 17: arg_3

        data
    }

    #[test]
    fn test_size_from_bytes() {
        let data : Vec<u8> = vec![0; TACACS_ACCOUNTING_REQUEST_MIN_LENGTH];
        let size = AccountingRequest::size_from_bytes(&data);
        assert_eq!(size, TACACS_ACCOUNTING_REQUEST_MIN_LENGTH);
    }

    #[test]
    fn test_size_from_bytes_with_args() {
        let mut data : Vec<u8> = Vec::new();
        data.push(0); // 0: flags
        data.push(0); // 1: authen_method
        data.push(0); // 2: priv_lvl
        data.push(0); // 3: authen_type
        data.push(0); // 4: authen_service

        data.push(1); // 5: user_len
        data.push(2); // 6: port_len
        data.push(3); // 7: rem_addr_len
        data.push(3); // 8: arg_cnt
        data.push(4); // 9+0: arg_1_len
        data.push(5); // 9+1: arg_2_len
        data.push(6); // 9+2: arg_3_len

        let size = AccountingRequest::size_from_bytes(&data);
        assert_eq!(size, TACACS_ACCOUNTING_REQUEST_MIN_LENGTH + 1 + 2 + 3 + 4 + 5 + 6);
    }

    #[test]
    fn test_read_string() {
        let data = vec![65_u8, 66, 67, 68, 69, 70];
        let mut cursor = Cursor::new(data.as_slice());
        let string = AccountingRequest::read_string(&mut cursor, 6).unwrap();
        assert_eq!(string, "ABCDEF");
    }

    #[test]
    fn test_from_data() {
        let data = generate_accounting_request_data();
        let accounting_request = AccountingRequest::from_bytes(data.as_slice()).unwrap();

        assert_eq!(accounting_request.flags.bits(), 0);
        assert_eq!(accounting_request.authen_method, TacacsAuthenticationMethod::TacPlusAuthenMethodTacacsplus);
        assert_eq!(accounting_request.priv_lvl, 0);
        assert_eq!(accounting_request.authen_type, TacacsAuthenticationType::TacPlusAuthenTypePap);
        assert_eq!(accounting_request.authen_service, TacacsAuthenticationService::TacPlusAuthenSvcNone);
        assert_eq!(accounting_request.user, "A");
        assert_eq!(accounting_request.port, "B");
        assert_eq!(accounting_request.rem_address, "C");
        assert_eq!(accounting_request.args.len(), 3);
        assert_eq!(accounting_request.args[0], "D");
        assert_eq!(accounting_request.args[1], "E");
        assert_eq!(accounting_request.args[2], "F");
    }

    #[test]
    fn test_to_data() {
        let data = generate_accounting_request_data();
        let accounting_request = AccountingRequest::from_bytes(data.as_slice()).unwrap();
        let new_data = accounting_request.to_bytes();

        assert_eq!(data, new_data);
    }

    
    #[test]
    fn test_read_string_exception_not_enough_data() {
        let data = vec![65_u8, 66, 67, 68, 69, 70];
        let mut cursor = Cursor::new(data.as_slice());
        let _s = match AccountingRequest::read_string(&mut cursor, 700) {
            Ok(_) => assert!(false),
            Err(err) => {
                assert!(err.to_string().contains("Remaining buffer too short"), "Error actual: {}", err);
                return;
            },
        };

        assert!(false, "Remaining buffer too short. Conversion should have failed with error.");
    }

    #[test]
    fn test_read_bytes_not_enough_data() {
        let data = vec![65_u8, 66, 67, 68, 69, 70];
        let _s = match AccountingRequest::from_bytes(data.as_slice()) {
            Ok(_) => assert!(false),
            Err(err) => {
                assert!(err.to_string().contains("Data too short"), "Error actual: {}", err);
                return;
            },
        };

        assert!(false, "Data too short. from_bytes should have failed with error.");
    }

    #[test]
    fn test_read_bytes_incorrect_accounting_flags() {
        let mut data = generate_accounting_request_data();
        data[0] = 0b11111111;
        let _s = match AccountingRequest::from_bytes(data.as_slice()) {
            Ok(_) => assert!(false),
            Err(err) => {
                assert!(err.to_string().contains("Invalid flags. Conversion failed with error"), "Error actual: {}", err);
                return;
            },
        };

        assert!(false, "Invalid flags. from_bytes should have failed with error.");
    }

    #[test]
    fn test_read_bytes_incorrect_authen_method() {
        let mut data = generate_accounting_request_data();
        data[1] = 0b11111111;
        let _s = match AccountingRequest::from_bytes(data.as_slice()) {
            Ok(_) => assert!(false),
            Err(err) => {
                assert!(err.to_string().contains("Invalid authen_method. Conversion failed with error"), "Error actual: {}", err);
                return;
            },
        };

        assert!(false, "Invalid authen_method. from_bytes should have failed with error.");
    }

    #[test]
    fn test_read_bytes_incorrect_authen_type() {
        let mut data = generate_accounting_request_data();
        data[3] = 0b11111111;
        let _s = match AccountingRequest::from_bytes(data.as_slice()) {
            Ok(_) => assert!(false),
            Err(err) => {
                assert!(err.to_string().contains("Invalid authen_type. Conversion failed with error"), "Error actual: {}", err);
                return;
            },
        };

        assert!(false, "Invalid authen_type. from_bytes should have failed with error.");
    }

    #[test]
    fn test_read_bytes_incorrect_authen_service() {
        let mut data = generate_accounting_request_data();
        data[4] = 0b11111111;
        let _s = match AccountingRequest::from_bytes(data.as_slice()) {
            Ok(_) => assert!(false),
            Err(err) => {
                assert!(err.to_string().contains("Invalid authen_service. Conversion failed with error"), "Error actual: {}", err);
                return;
            },
        };

        assert!(false, "Invalid authen_service. from_bytes should have failed with error.");
    }

    #[test]
    fn test_packet_has_nonzero_argcount_but_missing_arg_sizes_data() {
        let mut data = generate_accounting_request_data();
        data.truncate(TACACS_ACCOUNTING_REQUEST_MIN_LENGTH);
        let _s = match AccountingRequest::from_bytes(data.as_slice()) {
            Ok(_) => assert!(false),
            Err(err) => {
                assert!(err.to_string().contains("Invalid arg_size"), "Error actual: {}", err);
                return;
            },
        };

        assert!(false, "Invalid arg_size. Packet parsing should have failed.");
    }

    #[test]
    fn test_from_packet()
    {
        let data = generate_accounting_request_data();
        let header = Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAccounting,
            seq_no: 0,
            flags: TacacsFlags::empty(),
            session_id: 0,
            length: data.len() as u32,
        };

        let packet = Packet::new(header, data).unwrap();

        let accounting_request = AccountingRequest::from_packet(&packet).unwrap();

        assert_eq!(accounting_request.to_bytes(), packet.body_copy());
    }

    #[test]
    fn test_correct_packet_size_with_invalid_size_based_on_parameters()
    {
        let mut data = generate_accounting_request_data();
        data[5] = 255; // Set user_len to 255

        let header = Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAccounting,
            seq_no: 0,
            flags: TacacsFlags::empty(),
            session_id: 0,
            length: data.len() as u32,
        };

        let packet = Packet::new(header, data).unwrap();

        let _accounting_request = match AccountingRequest::from_packet(&packet) {
            Ok(_) => assert!(false),
            Err(err) => {
                assert!(err.to_string().contains("Invalid body length"), "Error actual: {}", err);
                return;
            },
        };

        assert!(false, "Invalid body length. Packet parsing should have failed.");
    }
}