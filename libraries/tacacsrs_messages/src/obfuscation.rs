use md5::{Md5, Digest};
use crate::header::Header;


pub fn convert(header : &Header, data : &[u8], obfuscation_key: &[u8]) -> Vec<u8> {
    let pad = generate_pad(header, obfuscation_key);
    let output : Vec<u8> = data.iter().zip(pad.iter()).map(|(a, b)| a ^ b).collect();

    output
}

pub fn convert_inplace(header : &Header, data : &mut [u8], obfuscation_key: &[u8]) {
    let pad = generate_pad(header, obfuscation_key);

    for (i, b) in data.iter_mut().enumerate() {
        *b ^= pad[i];
    }
}

fn generate_pad(header : &Header, obfuscation_key: &[u8]) -> Vec::<u8>
{
    let mut pad : Vec<u8> = Vec::new();
    let pad_size = header.length as usize;

    let iv = get_first_block(header, obfuscation_key);
    let mut hashed = hash_block(&iv);
    pad.extend(hashed);


    while pad.len() < pad_size {
        let mut rolling_hash : Vec::<u8> = Vec::new();
        rolling_hash.extend(&iv);
        rolling_hash.extend(&hashed);

        hashed = hash_block(&rolling_hash);
        pad.extend(hashed);
    }

    pad.truncate(pad_size);
    pad
}

fn hash_block(block: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(block);
    hasher.finalize().into()
}

fn get_first_block(header : &Header, obfuscation_key: &[u8]) -> Vec::<u8> {
    let mut pad : Vec<u8> = Vec::new();
    pad.extend(header.session_id.to_be_bytes());
    pad.extend_from_slice(obfuscation_key);
    pad.push(header.version());
    pad.push(header.seq_no);

    pad
}


#[cfg(test)]
mod tests
{
    use super::*;
    use crate::header::Header;
    use crate::enumerations::{TacacsMajorVersion, TacacsMinorVersion, TacacsType, TacacsFlags};
    use crate::packet::{Packet, PacketTrait};

    #[test]
    fn test_generate_pad()
    {
        let header = Header {
            major_version : TacacsMajorVersion::TacacsPlusMajor1,
            minor_version : TacacsMinorVersion::TacacsPlusMinorVerOne,
            tacacs_type : TacacsType::TacPlusAccounting,
            seq_no : 1,
            flags : TacacsFlags::empty(),
            session_id : 0xdeadbeef,
            length : 16
        };

        let obfuscation_key = b"tac_plus_key";
        let pad = generate_pad(&header, obfuscation_key);

        assert_eq!(pad.len(), 16);
    }

    #[test]
    fn test_convert()
    {
        let header = Header {
            major_version : TacacsMajorVersion::TacacsPlusMajor1,
            minor_version : TacacsMinorVersion::TacacsPlusMinorVerOne,
            tacacs_type : TacacsType::TacPlusAccounting,
            seq_no : 1,
            flags : TacacsFlags::empty(),
            session_id : 0xdeadbeef,
            length : 16
        };

        let obfuscation_key = b"tac_plus_key";

        let data = vec![0; 16];
        let output = convert(&header, &data, obfuscation_key);

        assert_eq!(output.len(), 16);
    }

    #[test]
    fn test_decrypt()
    {
        let encrypted_bytes = [
            0xc0_u8, 0x01, 0x01, 0x00, 0xc6, 0x03, 0xad, 0x17, 0x00, 0x00, 0x00, 0x22, 0xc0, 0x01,
            0x01, 0x00, 0xc6, 0x03, 0xad, 0x17, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x01, 0x01, 0x00,
            0xc6, 0x03, 0xad, 0x17, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x01, 0x01, 0x00, 0xc6, 0x03,
            0xad, 0x17, 0x00, 0x00
        ];

        let decrypted_bytes = [
            0x46_u8, 0x2e, 0x48, 0x27, 0xb8, 0xfe, 0x61, 0xbc, 0x73, 0x54, 0x3c, 0xee,
            0xb1, 0xa8, 0x3c, 0xa7, 0x78, 0xd5, 0xf1, 0xc4, 0xb4, 0x6a, 0x8e, 0xc6,
            0x9b, 0x71, 0xe7, 0x7a, 0x8f, 0x3c, 0xd3, 0xf1, 0x98, 0x27
        ];

        let packet = Packet::from_bytes(&encrypted_bytes).unwrap();
        assert!(!packet.header().flags.contains(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG));
        assert_eq!(packet.header().length, 34);

        let obfuscation_key = b"XX";
        let body_data = convert(packet.header(), packet.body(), obfuscation_key);
        assert_eq!(body_data, decrypted_bytes);

        let decrypted_packet = packet.as_deobfuscated(obfuscation_key).unwrap();
        assert_eq!(decrypted_packet.body(), &decrypted_bytes);
        assert!(decrypted_packet.header().flags.contains(crate::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG));
    }
}