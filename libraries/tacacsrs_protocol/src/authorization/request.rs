use std::io::Cursor;

use anyhow::Context;
use byteorder::ReadBytesExt;
use num_enum::TryFromPrimitive;

use crate::enumerations::{
    TacacsAuthenticationMethod, TacacsAuthenticationService, TacacsAuthenticationType,
};
use crate::helpers::read_string;
use crate::packet::{Packet, PacketTrait};
use crate::traits::TacacsBodyTrait;

const AUTHORIZATION_REQUEST_MIN_LENGTH: usize = 8;
const AUTHORIZATION_ARG_SIZE_OFFSET: usize = 8;

//  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
// +----------------+----------------+----------------+----------------+
// | authen_method  |    priv_lvl    |  authen_type   | authen_service |
// +----------------+----------------+----------------+----------------+
// |    user_len    |    port_len    |  rem_addr_len  |    arg_cnt     |
// +----------------+----------------+----------------+----------------+
// |   arg_1_len    |   arg_2_len    |      ...       |   arg_N_len    |
// +----------------+----------------+----------------+----------------+
// |   user ...
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub authen_method: TacacsAuthenticationMethod,
    pub priv_lvl: u8,
    pub authen_type: TacacsAuthenticationType,
    pub authen_service: TacacsAuthenticationService,
    pub user: String,
    pub port: String,
    pub rem_address: String,
    pub args: Vec<String>,
}

impl AuthorizationRequest {
    /// # Errors
    /// Returns an error if the packet body is too short or contains invalid fields.
    pub fn from_packet(packet: &Packet) -> anyhow::Result<Self> {
        let expected_length = Self::size_from_bytes(packet.body())
            .context("failed to determine the expected authorization request length")?;
        if packet.body().len() < expected_length {
            anyhow::bail!(
                "invalid authorization request body length: expected {expected_length}, actual {}",
                packet.body().len()
            );
        }

        Self::from_bytes(packet.body()).context("invalid TACACS+ authorization request")
    }

    fn size_from_bytes(data: &[u8]) -> anyhow::Result<usize> {
        if data.len() < AUTHORIZATION_REQUEST_MIN_LENGTH {
            anyhow::bail!(
                "authorization request body is too short for fixed fields: expected at least {}, actual {}",
                AUTHORIZATION_REQUEST_MIN_LENGTH,
                data.len()
            );
        }

        let arg_cnt = data[7] as usize;
        let arg_sizes_end = AUTHORIZATION_ARG_SIZE_OFFSET + arg_cnt;
        if data.len() < arg_sizes_end {
            anyhow::bail!(
                "authorization request body is too short for argument length fields: expected at least {arg_sizes_end}, actual {}",
                data.len()
            );
        }

        let fixed_and_sizes = AUTHORIZATION_REQUEST_MIN_LENGTH + arg_cnt;
        let string_lengths = usize::from(data[4])
            + usize::from(data[5])
            + usize::from(data[6])
            + data[AUTHORIZATION_ARG_SIZE_OFFSET..arg_sizes_end]
                .iter()
                .map(|length| usize::from(*length))
                .sum::<usize>();

        Ok(fixed_and_sizes + string_lengths)
    }

    /// # Errors
    /// Returns an error if the data is too short or contains invalid field values.
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        let expected_length = Self::size_from_bytes(data)?;
        if data.len() < expected_length {
            anyhow::bail!(
                "authorization request data is too short: expected {expected_length}, actual {}",
                data.len()
            );
        }

        let mut cursor = Cursor::new(data);
        let authen_method = TacacsAuthenticationMethod::try_from_primitive(
            cursor.read_u8().context("failed to read authen_method")?,
        )
        .context("invalid authorization authen_method")?;
        let priv_lvl = cursor.read_u8().context("failed to read priv_lvl")?;
        let authen_type = TacacsAuthenticationType::try_from_primitive(
            cursor.read_u8().context("failed to read authen_type")?,
        )
        .context("invalid authorization authen_type")?;
        let authen_service = TacacsAuthenticationService::try_from_primitive(
            cursor.read_u8().context("failed to read authen_service")?,
        )
        .context("invalid authorization authen_service")?;
        let user_len = cursor.read_u8().context("failed to read user_len")?;
        let port_len = cursor.read_u8().context("failed to read port_len")?;
        let rem_addr_len = cursor.read_u8().context("failed to read rem_addr_len")?;
        let arg_cnt = cursor.read_u8().context("failed to read arg_cnt")?;

        let mut arg_sizes = Vec::with_capacity(usize::from(arg_cnt));
        for _ in 0..arg_cnt {
            arg_sizes.push(cursor.read_u8().context("failed to read argument length")?);
        }

        let user = read_string(&mut cursor, usize::from(user_len))?;
        let port = read_string(&mut cursor, usize::from(port_len))?;
        let rem_address = read_string(&mut cursor, usize::from(rem_addr_len))?;
        let mut args = Vec::with_capacity(arg_sizes.len());
        for arg_size in arg_sizes {
            args.push(read_string(&mut cursor, usize::from(arg_size))?);
        }

        Ok(Self {
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

impl TacacsBodyTrait for AuthorizationRequest {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let user_len = u8::try_from(self.user.len())
            .context("authorization request user field exceeds 255 bytes")?;
        let port_len = u8::try_from(self.port.len())
            .context("authorization request port field exceeds 255 bytes")?;
        let rem_addr_len = u8::try_from(self.rem_address.len())
            .context("authorization request rem_address field exceeds 255 bytes")?;
        let arg_cnt = u8::try_from(self.args.len())
            .context("authorization request args count exceeds 255")?;

        let total = AUTHORIZATION_REQUEST_MIN_LENGTH
            + self.args.len()
            + self.user.len()
            + self.port.len()
            + self.rem_address.len()
            + self.args.iter().map(String::len).sum::<usize>();

        let mut data = Vec::with_capacity(total);
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
                .context("authorization request arg field exceeds 255 bytes")?;
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
    use super::*;

    #[test]
    fn authorization_request_round_trips() {
        let request = AuthorizationRequest {
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodTacacsplus,
            priv_lvl: 15,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeAscii,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcLogin,
            user: "admin".to_owned(),
            port: "pts/0".to_owned(),
            rem_address: "192.0.2.10".to_owned(),
            args: vec!["service=shell".to_owned(), "cmd=show".to_owned()],
        };

        let decoded = AuthorizationRequest::from_bytes(&request.to_bytes().unwrap()).unwrap();

        assert_eq!(decoded, request);
    }
}
