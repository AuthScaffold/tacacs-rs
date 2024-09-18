use md5::{Md5, Digest};

use crate::header::Header;

pub trait PacketTrait {
    fn header(&self) -> &Header;
    fn body(&self) -> &Vec<u8>;
}

#[derive(Debug)]
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

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn body(&self) -> &Vec<u8> {
        &self.body
    }

    pub fn body_copy(&self) -> Vec<u8> {
        self.body.clone()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.header.length as usize);
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.body);
        bytes
    }

    pub fn obfuscate_body(&mut self, obfuscation_key: &[u8]) {
        let pad = self.generate_pad(obfuscation_key);

        // self.body.iter_mut()
        //     .zip(pad.iter())
        //     .for_each(|(body_byte, pad_byte)| *body_byte ^= pad_byte);

        for (i, b) in self.body.iter_mut().enumerate() {
            *b ^= pad[i];
        }
    }

    fn generate_pad(&mut self, obfuscation_key: &[u8]) -> Vec::<u8>
    {
        let mut pad : Vec<u8> = Vec::new();

        let iv = self.get_first_block(obfuscation_key);
        let mut hashed = self.hash_block(&iv);

        while pad.len() < self.body.len() {
            let mut rolling_hash : Vec::<u8> = Vec::new();
            rolling_hash.extend(&iv);
            rolling_hash.extend(&hashed);

            hashed = self.hash_block(&iv);
            pad.extend(hashed);
        }

        pad.truncate(self.body.len());
        pad
    }

    fn hash_block(&self, block: &[u8]) -> [u8; 16] {
        let mut hasher = Md5::new();
        hasher.update(block);
        hasher.finalize().into()
    }

    fn get_first_block(&self, obfuscation_key: &[u8]) -> Vec::<u8> {
        let mut pad : Vec<u8> = Vec::new();
        pad.extend(self.header.session_id.to_be_bytes());
        pad.extend_from_slice(obfuscation_key);
        pad.push(self.header.version());
        pad.push(self.header.seq_no);

        pad
    }
}



impl PacketTrait for Packet {
    fn header(&self) -> &Header {
        self.header()
    }

    fn body(&self) -> &Vec<u8> {
        self.body()
    }
}
