use crate::constants::TACACS_HEADER_LENGTH;
use crate::enumerations::{TacacsMajorVersion, TacacsMinorVersion, TacacsType, TacacsFlags};
use anyhow::Context;
use num_enum::TryFromPrimitive;

#[derive(Debug, Clone)]
pub struct Header {
    pub major_version: TacacsMajorVersion,
    pub minor_version: TacacsMinorVersion,
    pub tacacs_type: TacacsType,
    pub seq_no: u8,
    pub flags: TacacsFlags,
    pub session_id: u32,
    pub length: u32,
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
    /// # Errors
    /// Returns an error if `data` is too short or contains invalid field values.
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < TACACS_HEADER_LENGTH {
            return Err(anyhow::Error::msg("data is too short for a TACACS+ header"));
        }

        let major_version = TacacsMajorVersion::try_from_primitive((data[0] >> 4) & 0x0f)
            .with_context(|| "invalid TACACS+ major version")?;

        let minor_version = TacacsMinorVersion::try_from_primitive(data[0] & 0x0f)
            .with_context(|| "invalid TACACS+ minor version")?;

        let tacacs_type =
            TacacsType::try_from_primitive(data[1]).with_context(|| "invalid TACACS+ type")?;

        let seq_no = data[2];

        let flags =
            TacacsFlags::from_bits(data[3]).ok_or_else(|| anyhow::Error::msg("invalid flags"))?;

        let session_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        let length = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        Ok(Self {
            major_version,
            minor_version,
            tacacs_type,
            seq_no,
            flags,
            session_id,
            length,
        })
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; TACACS_HEADER_LENGTH] {
        let mut binary_data: [u8; TACACS_HEADER_LENGTH] = [0; TACACS_HEADER_LENGTH];
        binary_data[0] = self.version();
        binary_data[1] = self.tacacs_type as u8;
        binary_data[2] = self.seq_no;
        binary_data[3] = self.flags.bits();
        binary_data[4..8].copy_from_slice(&self.session_id.to_be_bytes());
        binary_data[8..12].copy_from_slice(&self.length.to_be_bytes());

        binary_data
    }

    #[must_use]
    pub const fn version(&self) -> u8 {
        (self.major_version as u8) << 4 | (self.minor_version as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enumerations::{TacacsMajorVersion, TacacsMinorVersion, TacacsType, TacacsFlags};

    fn generate_packet(
        major_version_o: Option<TacacsMajorVersion>,
        minor_version_o: Option<TacacsMinorVersion>,
        tacacs_type_o: Option<TacacsType>,
        sequence_number_o: Option<u8>,
        tacacs_flags_o: Option<TacacsFlags>,
        session_id_o: Option<u32>,
        length_o: Option<u32>,
    ) -> [u8; 12] {
        let major_version = major_version_o.unwrap_or(TacacsMajorVersion::TacacsPlusMajor1);
        let minor_version = minor_version_o.unwrap_or(TacacsMinorVersion::TacacsPlusMinorVerOne);
        let tacacs_type = tacacs_type_o.unwrap_or(TacacsType::TacPlusAccounting);
        let tacacs_flags = tacacs_flags_o.unwrap_or(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);

        let sequence_number = sequence_number_o.unwrap_or(1_u8);
        let session_id = session_id_o.unwrap_or(0xdead_beef_u32);
        let length = length_o.unwrap_or(1_u32);

        let session_id_bytes = session_id.to_be_bytes();
        let length_bytes = length.to_be_bytes();

        let binary_data: [u8; 12] = [
            (major_version as u8) << 4 | (minor_version as u8),
            tacacs_type as u8,
            sequence_number,
            tacacs_flags.bits(),
            session_id_bytes[0],
            session_id_bytes[1],
            session_id_bytes[2],
            session_id_bytes[3],
            length_bytes[0],
            length_bytes[1],
            length_bytes[2],
            length_bytes[3],
        ];
        binary_data
    }

    fn generate_default_packet() -> [u8; 12] {
        generate_packet(
            Option::None,
            Option::None,
            Option::None,
            Option::None,
            Option::None,
            Option::None,
            Option::None,
        )
    }

    #[test]
    fn deserialisation_good_data() {
        let binary_data = generate_default_packet();

        let header = match Header::from_bytes(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                println!("Failed to parse the TACACS+ header: {e}");
                return;
            }
        };

        assert_eq!(header.major_version as u8, 0xc_u8, "major versions differ");
        assert_eq!(header.minor_version as u8, 1_u8, "minor versions differ");
        assert_eq!(header.tacacs_type as u8, 3_u8, "TACACS+ types differ");
        assert_eq!(header.seq_no, 1, "sequence numbers differ");
        assert_eq!(header.flags.bits(), (0xff & 0x01) as u8, "flags differ");
        assert_eq!(header.session_id as u32, 0xdead_beef_u32, "session IDs differ");
        assert_eq!(header.length, 1, "lengths differ");
    }

    #[test]
    fn deserialisation_bad_short_data() {
        let binary_data_expected_length = generate_default_packet();
        let binary_data_short = &binary_data_expected_length[0..TACACS_HEADER_LENGTH - 1];

        let _header = match Header::from_bytes(binary_data_short) {
            Ok(data) => data,
            Err(e) => {
                assert!(
                    e.to_string()
                        .contains("data is too short for a TACACS+ header"),
                    "Actual error: {e}"
                );
                return;
            }
        };

        unreachable!();
    }

    #[test]
    fn deserialisation_invalid_major_version() {
        let mut binary_data = generate_default_packet();
        binary_data[0] = 0x0f;

        let _header = match Header::from_bytes(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                assert!(
                    e.to_string().contains("invalid TACACS+ major version"),
                    "Actual error: {e}"
                );
                return;
            }
        };

        unreachable!("an invalid major version must cause conversion to fail");
    }

    #[test]
    fn deserialisation_invalid_minor_version() {
        let mut binary_data = generate_default_packet();
        binary_data[0] = 0xc7;

        let _header = match Header::from_bytes(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                assert!(
                    e.to_string().contains("invalid TACACS+ minor version"),
                    "Actual error: {e}"
                );
                return;
            }
        };

        unreachable!("an invalid minor version must cause conversion to fail");
    }

    #[test]
    fn deserialisation_invalid_tacacs_type() {
        let mut binary_data = generate_default_packet();
        binary_data[1] = 0xff;

        let _header = match Header::from_bytes(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                assert!(e.to_string().contains("invalid TACACS+ type"), "Actual error: {e}");
                return;
            }
        };

        unreachable!("an invalid TACACS+ type must cause conversion to fail");
    }

    #[test]
    fn deserialisation_invalid_flags() {
        let mut binary_data = generate_default_packet();
        let flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG;
        // Use bits that are currently invalid. This keeps the test valid if new
        // flags use other bits.
        let invalid_bits = 0x02 | 0x08 | 0x10 | 0x20;
        binary_data[3] = flags.bits() | invalid_bits;

        let _header = match Header::from_bytes(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                assert!(e.to_string().contains("invalid flags"), "Actual error: {e}");
                return;
            }
        };

        unreachable!("invalid flags must cause conversion to fail");
    }

    #[test]
    fn serialisation() {
        let binary_data = generate_default_packet();

        let header = match Header::from_bytes(&binary_data) {
            Ok(data) => data,
            Err(e) => {
                println!("Failed to parse the TACACS+ header: {e}");
                return;
            }
        };

        let binary_data_serialised = header.to_bytes();
        assert_eq!(
            binary_data, binary_data_serialised,
            "serialized data differs from the original data"
        );
    }
}
