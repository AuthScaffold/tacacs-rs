pub const TACACS_HEADER_LENGTH: usize = 12;
pub const TACACS_ACCOUNTING_REQUEST_MIN_LENGTH: usize = 9;
pub const TACACS_ACCOUNTING_ARG_SIZE_OFFSET: usize = 9;
pub const TACACS_ACCOUNTING_REPLY_MIN_LENGTH: usize = 5;

/// Maximum allowed body length for TACACS+ packets in bytes.
///
/// While RFC 8907 technically allows up to 4GB (u32::MAX), this is impractical
/// and poses security risks. Industry implementations typically limit packets to
/// around 4KB, with real-world packets usually being just a few hundred bytes.
///
/// This limit of 64KB (65536 bytes) provides:
/// - Protection against memory exhaustion DoS attacks
/// - Safe casting from u32 to usize on 32-bit platforms
/// - Sufficient space for any legitimate TACACS+ packet
/// - Compatibility with typical network MTU constraints
pub const TACACS_MAX_BODY_LENGTH: u32 = 65536;
