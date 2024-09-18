use crate::constants::TACACS_HEADER_LENGTH;
use crate::enumerations::{TacacsMajorVersion, TacacsMinorVersion, TacacsType, TacacsFlags};
use anyhow::Context;
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
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < TACACS_HEADER_LENGTH {
            return Err(anyhow::Error::msg("Data too short"));
        }

        let major_version = match TacacsMajorVersion::try_from_primitive((data[0] >> 4) & 0x0f).with_context(|| "Invalid major version. Conversion failed with error") {
            Ok(version) => version,
            Err(err) => return Err(err),
        };

        let minor_version = match TacacsMinorVersion::try_from_primitive(data[0] & 0x0f).with_context(|| "Invalid minor version. Conversion failed with error") {
            Ok(version) => version,
            Err(err) => return Err(err),
        };

        let tacacs_type = match TacacsType::try_from_primitive(data[1]).with_context(|| "Invalid TACACS+ type. Conversion failed with error") {
                Ok(tacacs_type) => tacacs_type,
                Err(err) => return Err(err),
        };
     
        let seq_no = data[2];

        let flags = TacacsFlags::from_bits(data[3]).ok_or(anyhow::Error::msg("Invalid flags"))?;

        let session_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        let length = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        

        Ok(Header {
            major_version,
            minor_version,
            tacacs_type,
            seq_no,
            flags,
            session_id,
            length
        })
    }

    pub fn to_bytes(&self) -> [u8; TACACS_HEADER_LENGTH] {
        let mut binary_data: [u8; TACACS_HEADER_LENGTH] = [0; TACACS_HEADER_LENGTH];
        binary_data[0] = (self.major_version as u8) << 4 | (self.minor_version as u8);
        binary_data[1] = self.tacacs_type as u8;
        binary_data[2] = self.seq_no;
        binary_data[3] = self.flags.bits();
        binary_data[4..8].copy_from_slice(&self.session_id.to_be_bytes());
        binary_data[8..12].copy_from_slice(&self.length.to_be_bytes());

        binary_data
    }
}






#[cfg(test)]
mod tests {
    use super::*;
    use crate::enumerations::{TacacsMajorVersion, TacacsMinorVersion, TacacsType, TacacsFlags};


    fn generate_packet(
        major_version_o : Option<TacacsMajorVersion>,
        minor_version_o : Option<TacacsMinorVersion>,
        tacacs_type_o : Option<TacacsType>,
        sequence_number_o : Option<u8>,
        tacacs_flags_o : Option<TacacsFlags>,
        session_id_o : Option<u32>,
        length_o : Option<u32>,
    ) -> [u8; 12]
    {
        let major_version = major_version_o.unwrap_or(TacacsMajorVersion::TacacsPlusMajor1);
        let minor_version = minor_version_o.unwrap_or(TacacsMinorVersion::TacacsPlusMinorVerOne);
        let tacacs_type = tacacs_type_o.unwrap_or(TacacsType::TacPlusAccounting);
        let tacacs_flags = tacacs_flags_o.unwrap_or(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);

        let sequence_number = sequence_number_o.unwrap_or(1 as u8);
        let session_id = session_id_o.unwrap_or(0xdeadbeef as u32);
        let length = length_o.unwrap_or(1 as u32);

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
        return binary_data;
    }

    fn generate_default_packet() -> [u8; 12] {
        return generate_packet(Option::None, Option::None, Option::None, Option::None, Option::None, Option::None, Option::None);
    }

    #[test]
    fn deserialisation_good_data() {
        let binary_data = generate_default_packet();
    
        let header = match Header::from_bytes(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                println!("Failed to create TacacsPacket: {}", e);
                return;
            },
        };

        assert_eq!(header.major_version as u8, 0xc as u8, "Major version mismatch");
        assert_eq!(header.minor_version as u8, 1 as u8, "Minor version mismatch");
        assert_eq!(header.tacacs_type as u8, 3 as u8, "TACACS+ type mismatch");
        assert_eq!(header.seq_no, 1, "Sequence number mismatch");
        assert_eq!(header.flags.bits(), (0xff & 0x01) as u8, "Flags mismatch");
        assert_eq!(header.session_id as u32, 0xdeadbeef as u32, "Session ID mismatch");
        assert_eq!(header.length, 1, "Length mismatch");
    }

    #[test]
    fn deserialisation_bad_short_data() {
        let binary_data_expected_length = generate_default_packet();
        let binary_data_short = &binary_data_expected_length[0..TACACS_HEADER_LENGTH-1];
    
        let _header = match Header::from_bytes(&binary_data_short) {
            Ok(data) => data,
            Err(e) => {
                assert!(e.to_string().contains("Data too short"), "Error: {}", e);
                return;
            },
        };

        assert!(false);
    }

    #[test]
    fn deserialisation_invalid_major_version() {
        let mut binary_data = generate_default_packet();
        binary_data[0] = 0x0f;
    
        let _header = match Header::from_bytes(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                assert!(e.to_string().contains("Invalid major version"), "Error: {}", e);
                return;
            },
        };

        assert!(false, "Invalid major version. Conversion should have failed with error.");
    }

    #[test]
    fn deserialisation_invalid_minor_version() {
        let mut binary_data = generate_default_packet();
        binary_data[0] = 0xc7;
    
        let _header = match Header::from_bytes(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                assert!(e.to_string().contains("Invalid minor version"), "Error: {}", e);
                return;
            },
        };

        assert!(false, "Invalid minor version. Conversion should have failed with error.");
    }

    #[test]
    fn deserialisation_invalid_tacacs_type() {
        let mut binary_data = generate_default_packet();
        binary_data[1] = 0xff;
    
        let _header = match Header::from_bytes(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                assert!(e.to_string().contains("Invalid TACACS+ type"), "Error: {}", e);
                return;
            },
        };

        assert!(false, "Invalid TACACS+ type. Conversion should have failed with error.");
    }

    #[test]
    fn deserialisation_invalid_flags() {
        let mut binary_data = generate_default_packet();
        let flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG;
        binary_data[3] = flags.bits() | 0x80;
    
        let _header = match Header::from_bytes(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                assert!(e.to_string().contains("Invalid flags"), "Error: {}", e);
                return;
            },
        };

        assert!(false, "Invalid flags. Conversion should have failed with error.");
    }

    #[test]
    fn serialisation() {
        let binary_data = generate_default_packet();
    
        let header = match Header::from_bytes(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                println!("Failed to create TacacsPacket: {}", e);
                return;
            },
        };

        let binary_data_serialised = header.to_bytes();
        assert_eq!(binary_data, binary_data_serialised, "Serialised data does not match original data");
    }
}