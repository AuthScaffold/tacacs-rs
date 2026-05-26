use std::io::Cursor;

use anyhow::Context;
use byteorder::{BigEndian, ReadBytesExt};
use num_enum::TryFromPrimitive;

use crate::enumerations::TacacsAuthorizationStatus;
use crate::helpers::read_string;
use crate::traits::TacacsBodyTrait;

const AUTHORIZATION_REPLY_MIN_LENGTH: usize = 6;
const AUTHORIZATION_REPLY_ARG_SIZE_OFFSET: usize = 6;

//  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
// +----------------+----------------+----------------+----------------+
// |    status      |     arg_cnt    |         server_msg len          |
// +----------------+----------------+----------------+----------------+
// +            data_len             |    arg_1_len   |    arg_2_len   |
// +----------------+----------------+----------------+----------------+
// |      ...       |   arg_N_len    |         server_msg ...
// +----------------+----------------+----------------+----------------+
// |   data ...
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
pub struct AuthorizationReply {
    pub status: TacacsAuthorizationStatus,
    pub server_msg: String,
    pub data: String,
    pub args: Vec<String>,
}

impl AuthorizationReply {
    fn size_from_bytes(data: &[u8]) -> anyhow::Result<usize> {
        if data.len() < AUTHORIZATION_REPLY_MIN_LENGTH {
            anyhow::bail!(
                "body too short for authorization reply fixed fields: expected at least {}, actual {}",
                AUTHORIZATION_REPLY_MIN_LENGTH,
                data.len()
            );
        }

        let arg_cnt = data[1] as usize;
        let arg_sizes_end = AUTHORIZATION_REPLY_ARG_SIZE_OFFSET + arg_cnt;
        if data.len() < arg_sizes_end {
            anyhow::bail!(
                "body too short for authorization reply argument size fields: expected at least {arg_sizes_end}, actual {}",
                data.len()
            );
        }

        let msg_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
        let data_len = usize::from(u16::from_be_bytes([data[4], data[5]]));
        let arg_lengths = data[AUTHORIZATION_REPLY_ARG_SIZE_OFFSET..arg_sizes_end]
            .iter()
            .map(|length| usize::from(*length))
            .sum::<usize>();

        Ok(AUTHORIZATION_REPLY_MIN_LENGTH + arg_cnt + msg_len + data_len + arg_lengths)
    }

    /// # Errors
    /// Returns an error if the data is too short or contains invalid field values.
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        let expected_length = Self::size_from_bytes(data)?;
        if data.len() < expected_length {
            anyhow::bail!(
                "data too short for authorization reply: expected {expected_length}, actual {}",
                data.len()
            );
        }

        let mut cursor = Cursor::new(data);
        let status = TacacsAuthorizationStatus::try_from_primitive(
            cursor
                .read_u8()
                .context("unable to read authorization status")?,
        )
        .context("invalid authorization status")?;
        let arg_cnt = cursor.read_u8().context("unable to read arg_cnt")?;
        let msg_len = cursor
            .read_u16::<BigEndian>()
            .context("unable to read msg_len")?;
        let data_len = cursor
            .read_u16::<BigEndian>()
            .context("unable to read data_len")?;

        let mut arg_sizes = Vec::with_capacity(usize::from(arg_cnt));
        for _ in 0..arg_cnt {
            arg_sizes.push(cursor.read_u8().context("unable to read arg size")?);
        }

        let server_msg = read_string(&mut cursor, usize::from(msg_len))?;
        let data = read_string(&mut cursor, usize::from(data_len))?;
        let mut args = Vec::with_capacity(arg_sizes.len());
        for arg_size in arg_sizes {
            args.push(read_string(&mut cursor, usize::from(arg_size))?);
        }

        Ok(Self {
            status,
            server_msg,
            data,
            args,
        })
    }
}

impl TacacsBodyTrait for AuthorizationReply {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let arg_cnt =
            u8::try_from(self.args.len()).context("authorization reply args count exceeds 255")?;
        let msg_len = u16::try_from(self.server_msg.len())
            .context("authorization reply server_msg exceeds 65535 bytes")?;
        let data_len = u16::try_from(self.data.len())
            .context("authorization reply data exceeds 65535 bytes")?;

        let total = AUTHORIZATION_REPLY_MIN_LENGTH
            + self.args.len()
            + self.server_msg.len()
            + self.data.len()
            + self.args.iter().map(String::len).sum::<usize>();

        let mut bytes = Vec::with_capacity(total);
        bytes.push(self.status as u8);
        bytes.push(arg_cnt);
        bytes.extend(msg_len.to_be_bytes());
        bytes.extend(data_len.to_be_bytes());

        for arg in &self.args {
            let arg_len = u8::try_from(arg.len())
                .context("authorization reply arg field exceeds 255 bytes")?;
            bytes.push(arg_len);
        }

        bytes.extend(self.server_msg.as_bytes());
        bytes.extend(self.data.as_bytes());
        for arg in &self.args {
            bytes.extend(arg.as_bytes());
        }

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_reply_round_trips() {
        let reply = AuthorizationReply {
            status: TacacsAuthorizationStatus::TacPlusPassAdd,
            server_msg: "ok".to_owned(),
            data: "display".to_owned(),
            args: vec!["priv-lvl=15".to_owned()],
        };

        let decoded = AuthorizationReply::from_bytes(&reply.to_bytes().unwrap()).unwrap();

        assert_eq!(decoded, reply);
    }
}
