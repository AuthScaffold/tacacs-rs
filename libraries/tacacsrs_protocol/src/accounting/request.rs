use crate::enumerations::{
    TacacsAccountingFlags, TacacsAuthenticationMethod, TacacsAuthenticationService,
    TacacsAuthenticationType,
};
use crate::packet::{Packet, PacketTrait};
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
    pub args: Vec<String>,
}

impl AccountingRequest {
    /// # Errors
    /// Returns an error if the packet body is too short or contains invalid fields.
    pub fn from_packet(packet: &Packet) -> Result<Self, anyhow::Error> {
        // Make sure that the packet body has the expected length.
        let expected_length = Self::size_from_bytes(packet.body())
            .with_context(|| "failed to determine the expected accounting request length")?;
        if packet.body().len() < expected_length {
            return Err(anyhow::Error::msg(format!(
                "invalid accounting request body length: expected {}, actual {}",
                expected_length,
                packet.body().len()
            )));
        }

        let accounting_request = match Self::from_bytes(packet.body()) {
            Ok(accounting_request) => accounting_request,
            Err(err) => {
                let context = format!("invalid TACACS+ accounting request: {err}");
                return Err(err).with_context(|| context);
            }
        };

        Ok(accounting_request)
    }

    fn size_from_bytes(data: &[u8]) -> Result<usize, anyhow::Error> {
        if data.len() < TACACS_ACCOUNTING_REQUEST_MIN_LENGTH {
            return Err(anyhow::Error::msg(format!(
                "accounting request body is too short for fixed fields: expected at least {}, actual {}",
                TACACS_ACCOUNTING_REQUEST_MIN_LENGTH,
                data.len()
            )));
        }

        let mut length = TACACS_ACCOUNTING_REQUEST_MIN_LENGTH;

        let user_len = data[5];
        let port_len = data[6];
        let rem_addr_len = data[7];

        length += user_len as usize;
        length += port_len as usize;
        length += rem_addr_len as usize;

        // Add the lengths of the variable-length arguments. Their length
        // octets start at TACACS_ACCOUNTING_ARG_SIZE_OFFSET.
        let arg_cnt = data[8];
        let arg_sizes_end = TACACS_ACCOUNTING_ARG_SIZE_OFFSET + arg_cnt as usize;
        if data.len() < arg_sizes_end {
            return Err(anyhow::Error::msg(format!(
                "accounting request body is too short for argument length fields: expected at least {arg_sizes_end}, actual {}",
                data.len()
            )));
        }
        for i in 0..arg_cnt {
            let arg_len = data[TACACS_ACCOUNTING_ARG_SIZE_OFFSET + i as usize];
            length += arg_len as usize;
        }

        Ok(length)
    }

    fn read_string(cursor: &mut Cursor<&[u8]>, len: usize) -> Result<String, anyhow::Error> {
        // The packet data length bounds the cursor position. The length fits in usize.
        #[allow(clippy::cast_possible_truncation)]
        let remaining_buffer = cursor.get_ref().len() - cursor.position() as usize;
        if remaining_buffer < len {
            return Err(anyhow::Error::msg(
                "cannot read the string: the remaining buffer is too short",
            ));
        }

        let mut buffer = vec![0; len];
        cursor
            .read_exact(&mut buffer)
            .with_context(|| format!("failed to read {len} bytes from the cursor"))?;

        let string =
            String::from_utf8(buffer).with_context(|| "data is not a valid UTF-8 string")?;

        Ok(string)
    }

    /// # Errors
    /// Returns an error if the data is too short or contains invalid field values.
    pub fn from_bytes(data: &[u8]) -> Result<Self, anyhow::Error> {
        if data.len() < TACACS_ACCOUNTING_REQUEST_MIN_LENGTH {
            return Err(anyhow::Error::msg("data is too short for an accounting request"));
        }

        let mut cursor = Cursor::new(data);

        let flags = {
            let a = cursor
                .read_u8()
                .with_context(|| "failed to read accounting flags")?;
            TacacsAccountingFlags::from_bits(a).with_context(|| "invalid accounting flags")?
        };

        let authen_method = {
            let data = cursor
                .read_u8()
                .with_context(|| "failed to read authen_method")?;
            TacacsAuthenticationMethod::try_from_primitive(data)
                .with_context(|| "invalid authen_method")?
        };

        let priv_lvl = cursor
            .read_u8()
            .with_context(|| "failed to read priv_lvl")?;

        let authen_type = {
            let data = cursor
                .read_u8()
                .with_context(|| "failed to read authen_type")?;
            TacacsAuthenticationType::try_from_primitive(data)
                .with_context(|| "invalid authen_type")?
        };

        let authen_service = {
            let a = cursor
                .read_u8()
                .with_context(|| "failed to read authen_service")?;
            TacacsAuthenticationService::try_from_primitive(a)
                .with_context(|| "invalid authen_service")?
        };

        let user_len = cursor
            .read_u8()
            .with_context(|| "failed to read user_len")?;

        let port_len = cursor
            .read_u8()
            .with_context(|| "failed to read port_len")?;

        let rem_addr_len = cursor
            .read_u8()
            .with_context(|| "failed to read rem_addr_len")?;

        let arg_cnt = cursor.read_u8().with_context(|| "failed to read arg_cnt")?;

        let mut arg_sizes: Vec<u8> = Vec::new();
        for _ in 0..arg_cnt {
            let arg_size = cursor
                .read_u8()
                .with_context(|| "failed to read arg_size")?;

            arg_sizes.push(arg_size);
        }

        let user = Self::read_string(&mut cursor, user_len as usize)
            .with_context(|| "failed to read user")?;

        let port = Self::read_string(&mut cursor, port_len as usize)
            .with_context(|| "failed to read port")?;

        let rem_address = Self::read_string(&mut cursor, rem_addr_len as usize)
            .with_context(|| "failed to read rem_address")?;

        let mut args: Vec<String> = Vec::new();
        for arg_size in arg_sizes {
            let arg = Self::read_string(&mut cursor, arg_size as usize)
                .with_context(|| "failed to read arg")?;

            args.push(arg);
        }

        Ok(Self {
            flags,
            authen_method,
            priv_lvl,
            authen_type,
            authen_service,
            user,
            port,
            rem_address,
            args,
        })
    }
}

impl TacacsBodyTrait for AccountingRequest {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let user_len = u8::try_from(self.user.len())
            .context("accounting request user field exceeds 255 bytes")?;
        let port_len = u8::try_from(self.port.len())
            .context("accounting request port field exceeds 255 bytes")?;
        let rem_addr_len = u8::try_from(self.rem_address.len())
            .context("accounting request rem_address field exceeds 255 bytes")?;
        let arg_cnt =
            u8::try_from(self.args.len()).context("accounting request args count exceeds 255")?;

        let total = TACACS_ACCOUNTING_REQUEST_MIN_LENGTH
            + self.args.len()
            + self.user.len()
            + self.port.len()
            + self.rem_address.len()
            + self.args.iter().map(String::len).sum::<usize>();

        let mut data = Vec::with_capacity(total);
        data.push(self.flags.bits());
        data.push(self.authen_method as u8);
        data.push(self.priv_lvl);
        data.push(self.authen_type as u8);
        data.push(self.authen_service as u8);
        data.push(user_len);
        data.push(port_len);
        data.push(rem_addr_len);
        data.push(arg_cnt);

        for arg in &self.args {
            let arg_len = u8::try_from(arg.len())
                .context("accounting request arg field exceeds 255 bytes")?;
            data.push(arg_len);
        }

        data.extend(self.user.as_bytes());
        data.extend(self.port.as_bytes());
        data.extend(self.rem_address.as_bytes());
        for arg in &self.args {
            data.extend(arg.as_bytes());
        }

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use crate::enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType};
    use crate::header::Header;
    use crate::packet::PacketTrait;

    use super::*;

    fn generate_accounting_request_data() -> Vec<u8> {
        vec![
            TacacsAccountingFlags::empty().bits(), // 0: flags
            TacacsAuthenticationMethod::TacPlusAuthenMethodTacacsplus as u8, // 1: authen_method
            0,                                     // 2: priv_lvl
            TacacsAuthenticationType::TacPlusAuthenTypePap as u8, // 3: authen_type
            TacacsAuthenticationService::TacPlusAuthenSvcNone as u8, // 4: authen_service
            1,                                     // 5: user_len
            1,                                     // 6: port_len
            1,                                     // 7: rem_addr_len
            3,                                     // 8: arg_cnt
            1,                                     // 9+0: arg_1_len
            1,                                     // 9+1: arg_2_len
            1,                                     // 9+2: arg_3_len
            b'A',                                  // 12: user
            b'B',                                  // 13: port
            b'C',                                  // 14: rem_addr
            b'D',                                  // 15: arg_1
            b'E',                                  // 16: arg_2
            b'F',                                  // 17: arg_3
        ]
    }

    #[test]
    fn test_size_from_bytes_too_short() {
        let data: Vec<u8> = vec![0; TACACS_ACCOUNTING_REQUEST_MIN_LENGTH - 1];
        let err = AccountingRequest::size_from_bytes(&data)
            .expect_err("a short body must cause the length calculation to fail");
        assert!(err.to_string().contains("body is too short"), "Actual error: {err}");
    }

    #[test]
    fn test_size_from_bytes_missing_arg_size_fields() {
        // arg_cnt is 3, but no argument length octets follow.
        let data: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0, 3]; // 9 octets with no argument lengths
        let err = AccountingRequest::size_from_bytes(&data)
            .expect_err("missing argument lengths must cause the length calculation to fail");
        assert!(err.to_string().contains("body is too short"), "Actual error: {err}");
    }

    #[test]
    fn test_from_packet_short_body_does_not_panic() {
        // A body shorter than TACACS_ACCOUNTING_REQUEST_MIN_LENGTH must return
        // an error. It must not cause a panic.
        let header = Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAccounting,
            seq_no: 1,
            flags: TacacsFlags::empty(),
            session_id: 1,
            length: 3,
        };
        let packet = Packet::new(header, vec![0x00, 0x00, 0x00]).unwrap();
        let result = AccountingRequest::from_packet(&packet);
        assert!(result.is_err(), "a packet with a short body must fail");
    }

    #[test]
    fn test_size_from_bytes() {
        let data: Vec<u8> = vec![0; TACACS_ACCOUNTING_REQUEST_MIN_LENGTH];
        let size = AccountingRequest::size_from_bytes(&data).unwrap();
        assert_eq!(size, TACACS_ACCOUNTING_REQUEST_MIN_LENGTH);
    }

    #[test]
    fn test_size_from_bytes_with_args() {
        let data: Vec<u8> = vec![
            0, // 0: flags
            0, // 1: authen_method
            0, // 2: priv_lvl
            0, // 3: authen_type
            0, // 4: authen_service
            1, // 5: user_len
            2, // 6: port_len
            3, // 7: rem_addr_len
            3, // 8: arg_cnt
            4, // 9+0: arg_1_len
            5, // 9+1: arg_2_len
            6, // 9+2: arg_3_len
        ];

        let size = AccountingRequest::size_from_bytes(&data).unwrap();
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
        assert_eq!(
            accounting_request.authen_method,
            TacacsAuthenticationMethod::TacPlusAuthenMethodTacacsplus
        );
        assert_eq!(accounting_request.priv_lvl, 0);
        assert_eq!(accounting_request.authen_type, TacacsAuthenticationType::TacPlusAuthenTypePap);
        assert_eq!(
            accounting_request.authen_service,
            TacacsAuthenticationService::TacPlusAuthenSvcNone
        );
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
        let new_data = accounting_request.to_bytes().unwrap();

        assert_eq!(data, new_data);
    }

    #[test]
    fn test_read_string_exception_not_enough_data() {
        let data = vec![65_u8, 66, 67, 68, 69, 70];
        let mut cursor = Cursor::new(data.as_slice());
        let err = AccountingRequest::read_string(&mut cursor, 700)
            .expect_err("a short remaining buffer must cause string conversion to fail");
        assert!(err.to_string().contains("remaining buffer is too short"), "Actual error: {err}");
    }

    #[test]
    fn test_read_bytes_not_enough_data() {
        let data = vec![65_u8, 66, 67, 68, 69, 70];
        let err = AccountingRequest::from_bytes(data.as_slice())
            .expect_err("short data must cause from_bytes to fail");
        assert!(
            err.to_string()
                .contains("data is too short for an accounting request"),
            "Actual error: {err}"
        );
    }

    #[test]
    fn test_read_bytes_incorrect_accounting_flags() {
        let mut data = generate_accounting_request_data();
        data[0] = 0b1111_1111;
        let err = AccountingRequest::from_bytes(data.as_slice())
            .expect_err("invalid flags must cause from_bytes to fail");
        assert!(err.to_string().contains("invalid accounting flags"), "Actual error: {err}");
    }

    #[test]
    fn test_read_bytes_incorrect_authen_method() {
        let mut data = generate_accounting_request_data();
        data[1] = 0b1111_1111;
        let err = AccountingRequest::from_bytes(data.as_slice())
            .expect_err("an invalid authen_method must cause from_bytes to fail");
        assert!(err.to_string().contains("invalid authen_method"), "Actual error: {err}");
    }

    #[test]
    fn test_read_bytes_incorrect_authen_type() {
        let mut data = generate_accounting_request_data();
        data[3] = 0b1111_1111;
        let err = AccountingRequest::from_bytes(data.as_slice())
            .expect_err("an invalid authen_type must cause from_bytes to fail");
        assert!(err.to_string().contains("invalid authen_type"), "Actual error: {err}");
    }

    #[test]
    fn test_read_bytes_incorrect_authen_service() {
        let mut data = generate_accounting_request_data();
        data[4] = 0b1111_1111;
        let err = AccountingRequest::from_bytes(data.as_slice())
            .expect_err("an invalid authen_service must cause from_bytes to fail");
        assert!(err.to_string().contains("invalid authen_service"), "Actual error: {err}");
    }

    #[test]
    fn test_packet_has_nonzero_argcount_but_missing_arg_sizes_data() {
        let mut data = generate_accounting_request_data();
        data.truncate(TACACS_ACCOUNTING_REQUEST_MIN_LENGTH);
        let err = AccountingRequest::from_bytes(data.as_slice())
            .expect_err("a missing arg_size must cause packet parsing to fail");
        assert!(err.to_string().contains("arg_size"), "Actual error: {err}");
    }

    #[test]
    fn test_from_packet() {
        let data = generate_accounting_request_data();
        #[allow(clippy::cast_possible_truncation)] // test data is small
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

        assert_eq!(accounting_request.to_bytes().unwrap(), packet.body());
    }

    #[test]
    fn test_correct_packet_size_with_invalid_size_based_on_parameters() {
        let mut data = generate_accounting_request_data();
        data[5] = 255; // Set user_len to 255.

        #[allow(clippy::cast_possible_truncation)] // test data is small
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

        let err = AccountingRequest::from_packet(&packet)
            .expect_err("an invalid body length must cause packet parsing to fail");
        assert!(
            err.to_string()
                .contains("invalid accounting request body length"),
            "Actual error: {err}"
        );
    }
}
