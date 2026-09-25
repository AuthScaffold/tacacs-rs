use crate::header::Header;
use md5::{Digest, Md5};

pub fn convert(header: &Header, data: &[u8], obfuscation_key: &[u8]) -> Vec<u8> {
    let output_length = data.len().min(header.length as usize);
    let mut output = data[..output_length].to_vec();
    convert_inplace(header, &mut output, obfuscation_key);

    output
}

pub fn convert_inplace(header: &Header, data: &mut [u8], obfuscation_key: &[u8]) {
    assert!(data.len() <= header.length as usize);
    if data.is_empty() {
        return;
    }

    let mut prefix = Md5::new();
    prefix.update(header.session_id.to_be_bytes());
    prefix.update(obfuscation_key);
    prefix.update([header.version(), header.seq_no]);

    let mut previous_hash = None;
    for chunk in data.chunks_mut(16) {
        let mut hasher = prefix.clone();
        if let Some(previous_hash) = previous_hash {
            hasher.update(previous_hash);
        }
        let hash: [u8; 16] = hasher.finalize().into();
        for (byte, pad_byte) in chunk.iter_mut().zip(hash) {
            *byte ^= pad_byte;
        }
        previous_hash = Some(hash);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enumerations::{TacacsMajorVersion, TacacsMinorVersion, TacacsType, TacacsFlags};
    use crate::header::Header;
    use crate::packet::{Packet, PacketTrait};

    fn header(body_length: usize) -> Header {
        Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerOne,
            tacacs_type: TacacsType::TacPlusAccounting,
            seq_no: 1,
            flags: TacacsFlags::empty(),
            session_id: 0xdead_beef,
            length: u32::try_from(body_length).unwrap(),
        }
    }

    fn reference_convert(header: &Header, data: &[u8], obfuscation_key: &[u8]) -> Vec<u8> {
        let pad_size = header.length as usize;
        let mut pad = Vec::with_capacity(pad_size);
        let mut prefix = Vec::with_capacity(obfuscation_key.len() + 6);
        prefix.extend(header.session_id.to_be_bytes());
        prefix.extend_from_slice(obfuscation_key);
        prefix.push(header.version());
        prefix.push(header.seq_no);

        let mut digest_hasher = Md5::new();
        digest_hasher.update(&prefix);
        let mut digest: [u8; 16] = digest_hasher.finalize().into();
        pad.extend(digest);

        while pad.len() < pad_size {
            let mut digest_hasher = Md5::new();
            digest_hasher.update(&prefix);
            digest_hasher.update(digest);
            digest = digest_hasher.finalize().into();
            pad.extend(digest);
        }

        data.iter()
            .zip(pad)
            .map(|(byte, pad_byte)| byte ^ pad_byte)
            .collect()
    }

    #[test]
    fn test_convert_matches_reference() {
        let obfuscation_key = b"tac_plus_key";
        for body_length in [0, 1, 15, 16, 17, 62, 4096, 65536] {
            let header = header(body_length);
            let data: Vec<_> = (0_u8..=u8::MAX).cycle().take(body_length).collect();

            let expected = reference_convert(&header, &data, obfuscation_key);
            let actual = convert(&header, &data, obfuscation_key);
            assert_eq!(actual, expected, "body length {body_length}");

            let mut in_place = data;
            convert_inplace(&header, &mut in_place, obfuscation_key);
            assert_eq!(in_place, expected, "in-place body length {body_length}");
        }
    }

    #[test]
    fn test_decrypt() {
        let encrypted_bytes = [
            0xc0_u8, 0x01, 0x01, 0x00, 0xc6, 0x03, 0xad, 0x17, 0x00, 0x00, 0x00, 0x22, 0xc0, 0x01,
            0x01, 0x00, 0xc6, 0x03, 0xad, 0x17, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x01, 0x01, 0x00,
            0xc6, 0x03, 0xad, 0x17, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x01, 0x01, 0x00, 0xc6, 0x03,
            0xad, 0x17, 0x00, 0x00,
        ];

        let decrypted_bytes = [
            0x46_u8, 0x2e, 0x48, 0x27, 0xb8, 0xfe, 0x61, 0xbc, 0x73, 0x54, 0x3c, 0xee, 0xb1, 0xa8,
            0x3c, 0xa7, 0x78, 0xd5, 0xf1, 0xc4, 0xb4, 0x6a, 0x8e, 0xc6, 0x9b, 0x71, 0xe7, 0x7a,
            0x8f, 0x3c, 0xd3, 0xf1, 0x98, 0x27,
        ];

        let packet = Packet::from_bytes(&encrypted_bytes).unwrap();
        assert!(!packet
            .header()
            .flags
            .contains(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG));
        assert_eq!(packet.header().length, 34);

        let obfuscation_key = b"XX";
        let body_data = convert(packet.header(), packet.body(), obfuscation_key);
        assert_eq!(body_data, decrypted_bytes);

        let decrypted_packet = packet.as_deobfuscated(obfuscation_key).unwrap();
        assert_eq!(decrypted_packet.body(), &decrypted_bytes);
        assert!(decrypted_packet
            .header()
            .flags
            .contains(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG));
    }
}
