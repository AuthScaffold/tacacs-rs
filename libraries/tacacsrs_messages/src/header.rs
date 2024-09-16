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

// 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
// +----------------+----------------+----------------+----------------+
// |major  | minor  |                |                |                |
// |version| version|      type      |     seq_no     |   flags        |
// +----------------+----------------+----------------+----------------+
// |                                                                   |
// |                            session_id                             |
// +----------------+----------------+----------------+----------------+
// |                                                                   |
// |                              length                               |
// +----------------+----------------+----------------+----------------+


impl Header {
    pub fn new(data: &[u8]) -> Result<Self, String> {
        if data.len() < TACACS_HEADER_LENGTH {
            return Err("Data too short".to_string());
        }

        let major_version = match TacacsMajorVersion::try_from_primitive((data[0] >> 4) & 0x0f) {
            Ok(version) => version,
            Err(err) => return Err(format!("Invalid major version. Conversion failed with error: {}", err)),
        };

        let minor_version = match TacacsMinorVersion::try_from_primitive(data[0] & 0x0f) {
            Ok(version) => version,
            Err(err) => return Err(format!("Invalid minor version. Conversion failed with error: {}", err)),
        };

        let tacacs_type = match TacacsType::try_from_primitive(data[1]) {
                Ok(tacacs_type) => tacacs_type,
                Err(err) => return Err(format!("Invalid TACACS+ type. Conversion failed with error: {}", err)),
        };
     
        let seq_no = data[2];

        let flags = TacacsFlags::from_bits(data[3]).ok_or("Invalid flags")?;

        let session_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        let length = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        

        Ok(Header {
            major_version: major_version,
            minor_version: minor_version,
            tacacs_type: tacacs_type,
            seq_no: seq_no,
            flags: flags,
            session_id: session_id,
            length: length,
        })
    }
}






#[cfg(test)]
mod tests {
    use super::*;
    use crate::enumerations::{TacacsMajorVersion, TacacsMinorVersion, TacacsType, TacacsFlags};

    #[test]
    fn deserialisation() {
        let major_version = TacacsMajorVersion::TacacsPlusMajor1;
        let minor_version = TacacsMinorVersion::TacacsPlusMinorVerDefault;
        let tacacs_type = TacacsType::TacPlusAccounting;
        let sequence_number = 0x01 as u8;
        let tacacs_flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG;
        let session_id = 0xdeadbeef as u32;
        let length = 1 as u32;

        let session_id_bytes = session_id.to_be_bytes();
        let length_bytes = length.to_be_bytes();
    
        let binary_data: [u8; 12] = [
            (major_version as u8) << 4 | (minor_version as u8),
            tacacs_type as u8,
            sequence_number,
            tacacs_flags.bits(),
            session_id_bytes[0], session_id_bytes[1], session_id_bytes[2], session_id_bytes[3],
            length_bytes[0], length_bytes[1], length_bytes[2], length_bytes[3]
        ];
    
        let header = match Header::new(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                println!("Failed to create TacacsPacket: {}", e);
                return;
            },
        };

        assert_eq!(header.major_version, major_version);
        assert_eq!(header.minor_version, minor_version);
        assert_eq!(header.tacacs_type, tacacs_type);
        assert_eq!(header.seq_no, sequence_number);
        assert_eq!(header.flags, tacacs_flags);
        assert_eq!(header.session_id, session_id);
        assert_eq!(header.length, length);
    }

    #[test]
    fn deserialisation_short_data() {
        let binary_data: [u8; 11] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
        ];
    
        let _header = match Header::new(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                assert!(e.contains("Data too short"), "Error: {}", e);
                return;
            },
        };

        assert!(false);
    }

    #[test]
    fn deserialisation_invalid_major_version() {
        let binary_data: [u8; 12] = [
            0x0f, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
        ];
    
        let _header = match Header::new(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                assert!(e.contains("Invalid major version"), "Error: {}", e);
                return;
            },
        };

        assert!(false, "Invalid major version. Conversion should have failed with error.");
    }

    #[test]
    fn deserialisation_invalid_minor_version() {
        let binary_data: [u8; 12] = [
            0xc7, 0x0f, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
        ];
    
        let _header = match Header::new(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                assert!(e.contains("Invalid minor version"), "Error: {}", e);
                return;
            },
        };

        assert!(false, "Invalid minor version. Conversion should have failed with error.");
    }

    #[test]
    fn deserialisation_invalid_tacacs_type() {
        let binary_data: [u8; 12] = [
            0xc0, 0x0f, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
        ];
    
        let _header = match Header::new(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                assert!(e.contains("Invalid TACACS+ type"), "Error: {}", e);
                return;
            },
        };

        assert!(false, "Invalid TACACS+ type. Conversion should have failed with error.");
    }
}