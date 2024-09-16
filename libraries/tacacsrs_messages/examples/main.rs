use tacacsrs_messages::enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::Packet;

fn main() {
    let major_version = TacacsMajorVersion::TacacsPlusMajor1;
    let minor_version = TacacsMinorVersion::TacacsPlusMinorVerDefault;
    let version = (major_version as u8) << 4 | (minor_version as u8);

    let tacacs_flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG;

    let session_id = 0xdeadbeef as u32;
    let session_id_bytes = session_id.to_be_bytes();

    let length = 1 as u32;
    let length_bytes = length.to_be_bytes();

    let binary_data: [u8; 12] = [
        version,
        TacacsType::TacPlusAccounting as u8,
        0x01,
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

    println!("TacacsPacket created: {:?}", header);

    match Packet::new(header, vec![0x01, 0x02, 0x03, 0x04]) {
        Ok(packet) => println!("TacacsPacket created: {:?}", packet),
        Err(e) => println!("Failed to create TacacsPacket: {}", e),
    }
}
