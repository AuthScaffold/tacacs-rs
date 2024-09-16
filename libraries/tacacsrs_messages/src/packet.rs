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
    pub fn new(header: Header, body: Vec<u8>) -> Result<Self, String> {
        if body.len() < (header.length as usize) {
            let expected_length = header.length as usize;
            let actual_length = body.len();
            let error_message = format!("Invalid body length. Expected: {}, Actual: {}", expected_length, actual_length);
            return Err(error_message);
        }
        Ok(Packet { header, body })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn body(&self) -> &Vec<u8> {
        &self.body
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