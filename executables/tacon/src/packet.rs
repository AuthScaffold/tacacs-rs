use anyhow::Error;
use byteorder::{BigEndian, ReadBytesExt};
use std::{
    io::{Cursor, Read},
    str::{from_utf8, Utf8Error},
};

#[derive(Debug)]
struct TacacsHeader {
    version: u8,
    type_: u8,
    sequence_number: u8,
    flags: u8,
    session_id: u32,
    length: u32,
}

#[derive(Debug)]
struct TacacsAccountingPacket {
    header: TacacsHeader,
    flags: u8,
    authen_method: u8,
    priv_lvl: u8,
    authen_type: u8,
    service: u8,
    user_len: u8,
    port_len: u8,
    rem_addr_len: u8,
    arg_cnt: u8,
    user: String,
    port: String,
    rem_addr: String,
    args: Vec<String>,
}

const TACACS_HEADER_SIZE: usize = 12;

impl TacacsHeader {
    pub fn from_bytes(bytes: &[u8]) -> Result<TacacsHeader, anyhow::Error> {
        if bytes.len() < TACACS_HEADER_SIZE {
            return Err(Error::msg("Not enough bytes to parse the header"));
        }
        let mut cursor = Cursor::new(bytes);
        let header = TacacsHeader {
            version: cursor.read_u8()?,
            type_: cursor.read_u8()?,
            sequence_number: cursor.read_u8()?,
            flags: cursor.read_u8()?,
            session_id: cursor.read_u32::<BigEndian>()?,
            length: cursor.read_u32::<BigEndian>()?,
        };
        header.validate()?;
        Ok(header)
    }

    pub fn validate(&self) -> Result<(), anyhow::Error> {
        if self.version != 0xc {
            return Err(Error::msg(format!(
                "Invalid version: 0x{:02X}",
                self.version
            )));
        }

        if self.type_ != 0x1 {
            return Err(Error::msg(format!("Invalid type: 0x{:02X}", self.type_)));
        }

        Ok(())
    }
}

impl TacacsAccountingPacket {
    fn from_bytes(bytes: &[u8]) -> Result<TacacsAccountingPacket, anyhow::Error> {
        let header = TacacsHeader::from_bytes(&bytes[0..TACACS_HEADER_SIZE])?;

        if bytes[TACACS_HEADER_SIZE..].len() < header.length as usize {
            return Err(Error::msg(format!(
                "Not enough bytes ({}) to parse the packet",
                bytes[TACACS_HEADER_SIZE..].len()
            )));
        }

        let mut cursor = Cursor::new(&bytes[12..]);
        let flags = cursor.read_u8()?;
        let authen_method = cursor.read_u8()?;
        let priv_lvl = cursor.read_u8()?;
        let authen_type = cursor.read_u8()?;
        let service = cursor.read_u8()?;
        let user_len = cursor.read_u8()?;
        let port_len = cursor.read_u8()?;
        let rem_addr_len = cursor.read_u8()?;
        let arg_cnt = cursor.read_u8()?;

        let mut args_lens = Vec::with_capacity(arg_cnt as usize);
        for _ in 0..arg_cnt {
            args_lens.push(cursor.read_u8()?);
        }

        let user = if user_len > 0 {
            let current_index = cursor.position() as usize;
            if TACACS_HEADER_SIZE + current_index + user_len as usize > header.length as usize {
                return Err(Error::msg(format!(
                    "User length ({}) is greater than the length of the remaining packet body ({})",
                    user_len, header.length
                )));
            }

            let mut buf = vec![0_u8; user_len as usize];
            cursor.read_exact(&mut buf)?;
            from_utf8(&buf)?.to_string()
        } else {
            String::new()
        };

        let port = if port_len > 0 {
            let current_index = cursor.position() as usize;
            if TACACS_HEADER_SIZE + current_index + port_len as usize > header.length as usize {
                return Err(Error::msg(format!(
                    "Port length ({}) is greater than the length of the remaining packet body ({})",
                    port_len, header.length
                )));
            }

            let mut buf = vec![0_u8; port_len as usize];
            cursor.read_exact(&mut buf)?;
            from_utf8(&buf)?.to_string()
        } else {
            String::new()
        };

        let rem_addr = if rem_addr_len > 0 {
            let current_index = cursor.position() as usize;
            if TACACS_HEADER_SIZE + current_index + rem_addr_len as usize > header.length as usize {
                return Err(Error::msg(format!("Remote address length ({}) is greater than the length of the remaining packet body ({})", rem_addr_len, header.length)));
            }

            let mut buf = vec![0_u8; rem_addr_len as usize];
            cursor.read_exact(&mut buf)?;
            from_utf8(&buf)?.to_string()
        } else {
            String::new()
        };

        let args: Result<Vec<String>, Utf8Error> = args_lens
            .into_iter()
            .filter_map(|arg_len| {
                if arg_len > 0 {
                    let mut buffer = vec![0_u8; arg_len as usize];
                    match cursor.read_exact(&mut buffer) {
                        Ok(_) => match from_utf8(&buffer) {
                            Ok(s) => Some(Ok(s.to_string())),
                            Err(e) => Some(Err(e)),
                        },
                        Err(_) => None,
                    }
                } else {
                    None
                }
            })
            .collect();

        let packet = TacacsAccountingPacket {
            header,
            flags,
            authen_method,
            priv_lvl,
            authen_type,
            service,
            user_len,
            port_len,
            rem_addr_len,
            arg_cnt,
            user,
            port,
            rem_addr,
            args: args?,
        };
        packet.validate()?;
        Ok(packet)
    }

    pub fn validate(&self) -> Result<(), anyhow::Error> {
        if self.header.length as usize
            != TACACS_HEADER_SIZE
                + self.user.len()
                + self.port.len()
                + self.rem_addr.len()
                + self.args.iter().map(|arg| arg.len()).sum::<usize>()
        {
            return Err(Error::msg("Invalid length"));
        }

        Ok(())
    }
}
