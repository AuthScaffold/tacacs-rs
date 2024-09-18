

use crate::{constants::TACACS_HEADER_LENGTH, header::Header};
use crate::obfuscation::{convert, convert_inplace};

pub trait PacketTrait {
    fn header(&self) -> &Header;
    fn body(&self) -> &Vec<u8>;
}

#[derive(Debug, Clone)]
pub struct Packet {
    header: Header,
    body: Vec<u8>,
}

impl Packet {
    pub fn new(header: Header, body: Vec<u8>) -> anyhow::Result<Self> {
        if body.len() < (header.length as usize) {
            let expected_length = header.length as usize;
            let actual_length = body.len();
            let error_message = format!("Invalid body length. Expected: {}, Actual: {}", expected_length, actual_length);
            return Err(anyhow::Error::msg(error_message));
        }
        
        Ok(Packet { header, body })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.header.length as usize);
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.body);
        bytes
    }

    pub fn from_bytes(data : &[u8]) -> anyhow::Result<Self> {
        let header = Header::from_bytes(data)?;
        let body = data[TACACS_HEADER_LENGTH..].to_vec();
        Ok(Packet { header, body })
    }

    
    pub fn as_obfuscated(&self, obfuscation_key : &[u8]) -> Option<Self> {
        let is_unencrypted = self.header.flags.contains(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);

        if is_unencrypted == false {
            return None;
        }

        let mut cloned_header = self.header.clone();
        cloned_header.flags.remove(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);

        let obfuscated_body = convert(&self.header, &self.body, obfuscation_key);
        return Some(Packet::new(cloned_header, obfuscated_body).unwrap());
    }

    pub fn as_deobfuscated(&self, obfuscation_key : &[u8]) -> Option<Self> {
        let is_encrypted = self.header.flags.contains(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG) == false;
        if is_encrypted == false {
            return None;
        }

        let mut cloned_header = self.header.clone();
        cloned_header.flags.insert(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);

        let deobfuscated_body = convert(&self.header, &self.body, obfuscation_key);
        return Some(Packet::new(cloned_header, deobfuscated_body).unwrap());
    }

    pub fn to_obfuscated(mut self, obfuscation_key : &[u8]) -> Self {
        let is_encrypted = self.header.flags.contains(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG) == false;
        match is_encrypted {
            true => self,
            false => {
                self.header.flags.set(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG, true);
                convert_inplace(&self.header, &mut self.body, obfuscation_key);
                self
            }
        }
    }

    pub fn to_deobfuscated(mut self, obfuscation_key : &[u8]) -> Self {
        let is_encrypted = self.header.flags.contains(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG) == false;

        match is_encrypted {
            true => {
                self.header.flags.set(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG, true);
                convert_inplace(&self.header, &mut self.body, obfuscation_key);
                self
            },
            false => self
        }
    }

}



impl PacketTrait for Packet {
    fn header(&self) -> &Header {
        &self.header
    }

    fn body(&self) -> &Vec<u8> {
        &self.body
    }
}
