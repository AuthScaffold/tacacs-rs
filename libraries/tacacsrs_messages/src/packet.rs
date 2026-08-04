use std::fmt;

use zeroize::Zeroize;

use crate::{constants::TACACS_HEADER_LENGTH, header::Header};
use crate::obfuscation::{convert, convert_inplace};

pub trait PacketTrait {
    fn header(&self) -> &Header;
    fn body(&self) -> &[u8];
}

#[derive(Clone)]
pub struct Packet {
    header: Header,
    body: Vec<u8>,
}

impl Packet {
    /// # Errors
    /// Returns an error if the body is shorter than the length declared in the header.
    pub fn new(header: Header, body: Vec<u8>) -> anyhow::Result<Self> {
        if body.len() < (header.length as usize) {
            let expected_length = header.length as usize;
            let actual_length = body.len();
            let error_message = format!(
                "Invalid body length. Expected: {expected_length}, Actual: {actual_length}"
            );
            return Err(anyhow::Error::msg(error_message));
        }

        Ok(Self { header, body })
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.header.length as usize);
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.body);
        bytes
    }

    /// # Errors
    /// Returns an error if the header cannot be parsed.
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        let header = Header::from_bytes(data)?;
        let body = data[TACACS_HEADER_LENGTH..].to_vec();
        Ok(Self { header, body })
    }

    /// Replaces the packet session identifier without copying its body.
    #[must_use]
    pub fn with_session_id(mut self, session_id: u32) -> Self {
        self.header.session_id = session_id;
        self
    }

    /// # Panics
    /// Panics if the obfuscated body length is inconsistent with the header.
    #[must_use]
    pub fn as_obfuscated(&self, obfuscation_key: &[u8]) -> Option<Self> {
        let is_obfuscated = !self
            .header
            .flags
            .contains(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
        if is_obfuscated {
            return None;
        }

        let mut cloned_header = self.header.clone();
        cloned_header
            .flags
            .remove(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);

        let obfuscated_body = convert(&self.header, &self.body, obfuscation_key);
        Some(Self::new(cloned_header, obfuscated_body).unwrap())
    }

    /// # Panics
    /// Panics if the deobfuscated body length is inconsistent with the header.
    #[must_use]
    pub fn as_deobfuscated(&self, obfuscation_key: &[u8]) -> Option<Self> {
        let is_deobfuscated = self
            .header
            .flags
            .contains(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
        if is_deobfuscated {
            return None;
        }

        let mut cloned_header = self.header.clone();
        cloned_header
            .flags
            .insert(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);

        let deobfuscated_body = convert(&self.header, &self.body, obfuscation_key);
        Some(Self::new(cloned_header, deobfuscated_body).unwrap())
    }

    #[must_use]
    pub fn to_obfuscated(mut self, obfuscation_key: &[u8]) -> Self {
        let is_obfuscated = !self
            .header
            .flags
            .contains(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
        if !is_obfuscated {
            self.header
                .flags
                .set(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG, false);
            convert_inplace(&self.header, &mut self.body, obfuscation_key);
        }
        self
    }

    #[must_use]
    pub fn to_deobfuscated(mut self, obfuscation_key: &[u8]) -> Self {
        let is_deobfuscated = self
            .header
            .flags
            .contains(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
        if !is_deobfuscated {
            self.header
                .flags
                .set(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG, true);
            convert_inplace(&self.header, &mut self.body, obfuscation_key);
        }
        self
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Packet")
            .field("header", &self.header)
            .field("body_length", &self.body.len())
            .field("body", &"<redacted>")
            .finish()
    }
}

impl Drop for Packet {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

impl PacketTrait for Packet {
    fn header(&self) -> &Header {
        &self.header
    }

    fn body(&self) -> &[u8] {
        self.body.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use crate::enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType};

    use super::*;

    #[test]
    fn packet_debug_redacts_body() {
        let secret = b"not-in-packet-debug";
        let packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerOne,
                tacacs_type: TacacsType::TacPlusAuthentication,
                seq_no: 1,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                session_id: 1,
                length: u32::try_from(secret.len()).unwrap(),
            },
            secret.to_vec(),
        )
        .unwrap();

        let debug = format!("{packet:?}");
        assert!(!debug.contains("not-in-packet-debug"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("body_length: 19"));
    }

    #[test]
    fn with_session_id_preserves_body_without_reconstruction() {
        let packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no: 2,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                session_id: 1,
                length: 4,
            },
            b"body".to_vec(),
        )
        .unwrap()
        .with_session_id(2);

        assert_eq!(packet.header().session_id, 2);
        assert_eq!(packet.body(), b"body");
    }
}
