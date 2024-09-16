use crate::constants::TACACS_HEADER_LENGTH;
use crate::enumerations::{TacacsMajorVersion, TacacsMinorVersion, TacacsType, TacacsFlags};
use num_enum::TryFromPrimitive;

#[derive(Debug)]
pub struct Header {
    pub major_version : TacacsMajorVersion,
    pub minor_version : TacacsMinorVersion,
    pub tacacs_type : TacacsType,
    pub seq_no : u8,
    pub flags : TacacsFlags,
    pub session_id : u32,
    pub length : u32
}

impl Header {
    pub fn new(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < TACACS_HEADER_LENGTH {
            return Err("Data too short");
        }

        let major_version = match TacacsMajorVersion::try_from_primitive((data[0] >> 4) & 0x0f) {
            Ok(version) => version,
            Err(_) => return Err("Invalid major version"),
        };
        
        
        // let minor_version = data[0] & 0x0f;
        // let packet_type = data[1];
        // let seq_no = data[2];
        // let flags = data[3];
        // let session_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        // let length = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        Ok(Header {
            major_version: major_version,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAccounting,
            seq_no: 0,
            flags: TacacsFlags::empty(),
            session_id: 0,
            length: 0,
        })
    }
}
