use crate::enumerations::{TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService, TacacsAuthenticationType};
use crate::packet::{Packet};
use std::io::{Cursor, Read};
use byteorder::{ReadBytesExt};
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
    pub fn from_packet(packet : Packet) -> Result<Self, String> {
        // Check if the packet the correct length
        let expected_length = Self::size_from_bytes(packet.body());
        if packet.body().len() < expected_length {
            return Err(format!("Invalid body length. Expected: {}, Actual: {}", expected_length, packet.body().len()));
        }

        let accounting_request = match Self::from_bytes(packet.body()) {
            Ok(accounting_request) => accounting_request,
            Err(err) => return Err(format!("Invalid TACACS+ AccountingRequest. Conversion failed with error: {}", err)),
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
        // the data starting at the 5th byte.
        let arg_cnt = data[8];
        for i in 0..arg_cnt {
            let arg_len = data[TACACS_ACCOUNTING_ARG_SIZE_OFFSET + i as usize];
            length += arg_len as usize;
        }

        length
    }


    fn read_string(cursor : &mut Cursor<&[u8]>, len: usize) -> Result<String, std::io::Error> {
        let mut buffer = vec![0; len];
        cursor.read_exact(&mut buffer)?;

        let string = String::from_utf8(buffer)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(string)
    }

    pub fn from_bytes(data : &[u8]) -> Result<Self, String> {
        if data.len() < TACACS_ACCOUNTING_REQUEST_MIN_LENGTH {
            return Err("Data too short".to_string());
        }

        let mut cursor = Cursor::new(data);

        let flags = match cursor.read_u8() {
            Ok(a) => TacacsAccountingFlags::from_bits(a).ok_or("Invalid flags. Conversion failed with error")?,
            Err(err) => return Err(format!("Invalid flags. Unable to read data: {}", err)),
        };

        let authen_method = match cursor.read_u8() {
            Ok(a) => TacacsAuthenticationMethod::try_from_primitive(a)
                        .map_err(|err| format!("Invalid authen_method. Conversion failed with error: {}", err))?,
            Err(err) => return Err(format!("Invalid authen_method. Unable to read data: {}", err)),
        };

        let priv_lvl = match cursor.read_u8() {
            Ok(a) => a,
            Err(err) => return Err(format!("Invalid priv_lvl. Unable to read data: {}", err)),
        };

        let authen_type = match cursor.read_u8() {
            Ok(a) => TacacsAuthenticationType::try_from_primitive(a)
                        .map_err(|err| format!("Invalid authen_type. Conversion failed with error: {}", err))?,
            Err(err) => return Err(format!("Invalid authen_type. Unable to read data: {}", err)),
        };

        let authen_service = match cursor.read_u8() {
            Ok(a) => TacacsAuthenticationService::try_from_primitive(a)
                        .map_err(|err| format!("Invalid authen_service. Conversion failed with error: {}", err))?,
            Err(err) => return Err(format!("Invalid authen_service. Unable to read data: {}", err)),
        };

        let user_len = match cursor.read_u8() {
            Ok(a) => a,
            Err(err) => return Err(format!("Invalid user_len. Unable to read data: {}", err)),
        };

        let port_len = match cursor.read_u8() {
            Ok(a) => a,
            Err(err) => return Err(format!("Invalid port_len. Unable to read data: {}", err)),
        };

        let rem_addr_len = match cursor.read_u8() {
            Ok(a) => a,
            Err(err) => return Err(format!("Invalid rem_addr_len. Unable to read data: {}", err)),
        };

        let arg_cnt = match cursor.read_u8() {
            Ok(a) => a,
            Err(err) => return Err(format!("Invalid arg_cnt. Unable to read data: {}", err)),
        };

        let mut arg_sizes : Vec<u8> = Vec::new();
        for _ in 0..arg_cnt {
            let arg_size = match cursor.read_u8() {
                Ok(a) => a,
                Err(err) => return Err(format!("Invalid arg_size. Unable to read data: {}", err)),
            };

            arg_sizes.push(arg_size);
        }

        let user = match Self::read_string(&mut cursor, user_len as usize) {
            Ok(a) => a,
            Err(err) => return Err(format!("Invalid user. Unable to read data: {}", err)),
        };

        let port = match Self::read_string(&mut cursor, port_len as usize) {
            Ok(a) => a,
            Err(err) => return Err(format!("Invalid port. Unable to read data: {}", err)),
        };

        let rem_address = match Self::read_string(&mut cursor, rem_addr_len as usize) {
            Ok(a) => a,
            Err(err) => return Err(format!("Invalid rem_address. Unable to read data: {}", err)),
        };

        let mut args : Vec<String> = Vec::new();
        for arg_size in arg_sizes {
            let arg = match Self::read_string(&mut cursor, arg_size as usize) {
                Ok(a) => a,
                Err(err) => return Err(format!("Invalid arg. Unable to read data: {}", err)),
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

#[cfg(test)]
mod tests
{
    use super::*;
    // use crate::header::{Header};
    // use crate::enumerations::{TacacsMajorVersion, TacacsMinorVersion, TacacsType, TacacsFlags};
    // use crate::packet::{Packet};
    // use std::io::{Cursor, Read};
    // use byteorder::{ReadBytesExt};
    // use num_enum::TryFromPrimitive;
    // use crate::constants::{TACACS_HEADER_LENGTH};

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
}