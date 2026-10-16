pub const TACACS_HEADER_LENGTH: usize = 12;
pub const TACACS_ACCOUNTING_REQUEST_MIN_LENGTH: usize = 9;
pub const TACACS_ACCOUNTING_ARG_SIZE_OFFSET: usize = 9;
pub const TACACS_ACCOUNTING_REPLY_MIN_LENGTH: usize = 5;

/// Maximum TACACS+ packet body length, in bytes.
///
/// RFC 8907 permits a body length of up to `u32::MAX` bytes. A body of that
/// size can exhaust memory. TACACS+ implementations typically limit packets to
/// approximately 4 KB.
///
/// This 64 KiB (65536-byte) limit:
/// - reduces the risk of memory exhaustion attacks;
/// - permits safe conversion from `u32` to `usize` on 32-bit platforms;
/// - provides sufficient space for typical TACACS+ packets.
pub const TACACS_MAX_BODY_LENGTH: u32 = 65536;
