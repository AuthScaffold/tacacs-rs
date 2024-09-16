use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::Packet;

fn main() {
    let binary_data: [u8; 12] = [0xc0, 0x01, 0x01, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x10];
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
