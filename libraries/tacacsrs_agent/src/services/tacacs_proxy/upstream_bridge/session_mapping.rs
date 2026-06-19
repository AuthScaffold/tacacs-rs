//! TACACS+ session-id mapping helpers for the raw proxy.

use tacacsrs_messages::packet::{Packet, PacketTrait};

pub(super) fn rewrite_session_id(packet: &Packet, session_id: u32) -> anyhow::Result<Packet> {
    let mut header = packet.header().clone();
    header.session_id = session_id;
    Packet::new(header, packet.body().clone())
}

#[cfg(test)]
mod tests {
    use tacacsrs_messages::enumerations::{
        TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType,
    };
    use tacacsrs_messages::header::Header;
    use tacacsrs_messages::packet::{Packet, PacketTrait};

    use super::rewrite_session_id;

    fn test_packet(tacacs_type: TacacsType, session_id: u32, body: Vec<u8>) -> Packet {
        Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type,
                seq_no: 2,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                session_id,
                length: u32::try_from(body.len()).unwrap(),
            },
            body,
        )
        .unwrap()
    }

    #[test]
    fn rewrite_session_id_preserves_body_and_header_fields() {
        let packet = test_packet(TacacsType::TacPlusAccounting, 0x1111_2222, b"body".to_vec());

        let rewritten = rewrite_session_id(&packet, 0x3333_4444).unwrap();

        assert_eq!(rewritten.header().session_id, 0x3333_4444);
        assert_eq!(rewritten.header().tacacs_type, packet.header().tacacs_type);
        assert_eq!(rewritten.header().seq_no, packet.header().seq_no);
        assert_eq!(rewritten.header().flags, packet.header().flags);
        assert_eq!(rewritten.body(), packet.body());
    }
}
