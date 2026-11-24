//! Packet single-connection flag inspection for TACACS+ connections.

use tacacsrs_protocol::enumerations::TacacsFlags;
use tacacsrs_protocol::packet::PacketTrait;

/// Represents whether the `TAC_PLUS_SINGLE_CONNECT_FLAG` is set in a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SingleConnectFlag {
    /// The `TAC_PLUS_SINGLE_CONNECT_FLAG` is set.
    Set,
    /// The `TAC_PLUS_SINGLE_CONNECT_FLAG` is not set.
    NotSet,
}

impl SingleConnectFlag {
    /// Returns the single-connect flag state from a packet.
    pub(crate) fn from_packet(packet: &impl PacketTrait) -> Self {
        if packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG)
        {
            Self::Set
        } else {
            Self::NotSet
        }
    }

    /// Returns `true` when `TAC_PLUS_SINGLE_CONNECT_FLAG` is set.
    pub(crate) const fn is_set(self) -> bool {
        matches!(self, Self::Set)
    }
}

#[cfg(test)]
mod tests {
    use tacacsrs_protocol::enumerations::{TacacsMajorVersion, TacacsMinorVersion, TacacsType};
    use tacacsrs_protocol::header::Header;
    use tacacsrs_protocol::packet::Packet;

    use super::*;

    fn packet_with_flags(flags: TacacsFlags) -> Packet {
        Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no: 2,
                flags,
                session_id: 1,
                length: 0,
            },
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn from_packet_detects_single_connect_flag() {
        let with_flag = packet_with_flags(
            TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG | TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
        );
        let flag = SingleConnectFlag::from_packet(&with_flag);
        assert_eq!(flag, SingleConnectFlag::Set);
        assert!(flag.is_set());

        let without_flag = packet_with_flags(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
        let flag = SingleConnectFlag::from_packet(&without_flag);
        assert_eq!(flag, SingleConnectFlag::NotSet);
        assert!(!flag.is_set());
    }
}
