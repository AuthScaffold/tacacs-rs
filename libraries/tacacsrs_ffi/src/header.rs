//! FFI bindings for TACACS+ header operations

use std::os::raw::c_uint;
use std::ptr;

use tacacsrs_messages::header::Header as RustHeader;
use tacacsrs_messages::enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType};

use crate::error::{TacacsError, TacacsResult};

/// Opaque type for TACACS+ header
#[repr(C)]
pub struct TacacsHeader {
    _private: [u8; 0],
}

/// TACACS+ flags
pub const TACACS_FLAG_UNENCRYPTED: u8 = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG.bits();
pub const TACACS_FLAG_SINGLE_CONNECTION: u8 = TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG.bits();

/// Create a new TACACS+ header
///
/// # Safety
///
/// Returns a pointer to a newly allocated header that must be freed with `tacacs_header_free()`.
/// Returns null on allocation failure.
#[no_mangle]
pub unsafe extern "C" fn tacacs_header_new(
    major_version: TacacsMajorVersion,
    minor_version: TacacsMinorVersion,
    tacacs_type: TacacsType,
    seq_no: u8,
    flags: u8,
    session_id: c_uint,
    length: c_uint,
    error: *mut TacacsError,
) -> *mut TacacsHeader {
    let rust_flags = match TacacsFlags::from_bits(flags) {
        Some(f) => f,
        None => {
            if !error.is_null() {
                *error = TacacsError::new(TacacsResult::InvalidInput, "Invalid flags value");
            }
            return ptr::null_mut();
        }
    };

    let header = RustHeader {
        major_version,
        minor_version,
        tacacs_type,
        seq_no,
        flags: rust_flags,
        session_id,
        length,
    };

    if !error.is_null() {
        *error = TacacsError::success();
    }

    Box::into_raw(Box::new(header)) as *mut TacacsHeader
}

/// Parse a TACACS+ header from bytes
///
/// # Safety
///
/// The `data` pointer must point to at least `data_len` bytes of valid memory.
/// Returns a pointer to a newly allocated header that must be freed with `tacacs_header_free()`.
/// Returns null on parse failure or allocation failure.
#[no_mangle]
pub unsafe extern "C" fn tacacs_header_from_bytes(
    data: *const u8,
    data_len: usize,
    error: *mut TacacsError,
) -> *mut TacacsHeader {
    if data.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Data pointer is null");
        }
        return ptr::null_mut();
    }

    let slice = std::slice::from_raw_parts(data, data_len);

    match RustHeader::from_bytes(slice) {
        Ok(header) => {
            if !error.is_null() {
                *error = TacacsError::success();
            }
            Box::into_raw(Box::new(header)) as *mut TacacsHeader
        }
        Err(e) => {
            if !error.is_null() {
                *error = TacacsError::new(
                    TacacsResult::InvalidHeader,
                    &format!("Failed to parse header: {}", e),
                );
            }
            ptr::null_mut()
        }
    }
}

/// Serialize a TACACS+ header to bytes
///
/// # Safety
///
/// The `header` pointer must be valid and point to a header created by this library.
/// The `buffer` pointer must point to at least 12 bytes of writable memory.
/// Returns the number of bytes written (always 12 for a valid header), or 0 on error.
#[no_mangle]
pub unsafe extern "C" fn tacacs_header_to_bytes(
    header: *const TacacsHeader,
    buffer: *mut u8,
    buffer_len: usize,
    error: *mut TacacsError,
) -> usize {
    if header.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Header pointer is null");
        }
        return 0;
    }

    if buffer.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Buffer pointer is null");
        }
        return 0;
    }

    const HEADER_SIZE: usize = 12;
    if buffer_len < HEADER_SIZE {
        if !error.is_null() {
            *error = TacacsError::new(
                TacacsResult::BufferTooSmall,
                &format!("Buffer too small: need {} bytes, have {}", HEADER_SIZE, buffer_len),
            );
        }
        return 0;
    }

    let header_ref = &*(header as *const RustHeader);
    let bytes = header_ref.to_bytes();

    let buffer_slice = std::slice::from_raw_parts_mut(buffer, HEADER_SIZE);
    buffer_slice.copy_from_slice(&bytes);

    if !error.is_null() {
        *error = TacacsError::success();
    }

    HEADER_SIZE
}

/// Get the session ID from a header
///
/// # Safety
///
/// The `header` pointer must be valid and point to a header created by this library.
/// Returns 0 if the pointer is null.
#[no_mangle]
pub unsafe extern "C" fn tacacs_header_get_session_id(header: *const TacacsHeader) -> c_uint {
    if header.is_null() {
        return 0;
    }
    (*(header as *const RustHeader)).session_id
}

/// Get the sequence number from a header
///
/// # Safety
///
/// The `header` pointer must be valid and point to a header created by this library.
/// Returns 0 if the pointer is null.
#[no_mangle]
pub unsafe extern "C" fn tacacs_header_get_seq_no(header: *const TacacsHeader) -> u8 {
    if header.is_null() {
        return 0;
    }
    (*(header as *const RustHeader)).seq_no
}

/// Get the length from a header
///
/// # Safety
///
/// The `header` pointer must be valid and point to a header created by this library.
/// Returns 0 if the pointer is null.
#[no_mangle]
pub unsafe extern "C" fn tacacs_header_get_length(header: *const TacacsHeader) -> c_uint {
    if header.is_null() {
        return 0;
    }
    (*(header as *const RustHeader)).length
}

/// Free a TACACS+ header
///
/// # Safety
///
/// The `header` pointer must be valid and must have been allocated by this library.
/// After calling this function, the pointer is invalid.
#[no_mangle]
pub unsafe extern "C" fn tacacs_header_free(header: *mut TacacsHeader) {
    if !header.is_null() {
        let _ = Box::from_raw(header as *mut RustHeader);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_creation() {
        unsafe {
            let mut error = TacacsError::success();
            let header = tacacs_header_new(
                TacacsMajorVersion::TacacsPlusMajor1,
                TacacsMinorVersion::TacacsPlusMinorVerOne,
                TacacsType::TacPlusAuthentication,
                1,
                TACACS_FLAG_UNENCRYPTED,
                12345,
                100,
                &mut error,
            );

            assert!(!header.is_null());
            assert_eq!(error.code, TacacsResult::Success);
            assert_eq!(tacacs_header_get_session_id(header), 12345);
            assert_eq!(tacacs_header_get_seq_no(header), 1);
            assert_eq!(tacacs_header_get_length(header), 100);

            tacacs_header_free(header);
        }
    }

    #[test]
    fn test_header_serialization() {
        unsafe {
            let mut error = TacacsError::success();
            let header = tacacs_header_new(
                TacacsMajorVersion::TacacsPlusMajor1,
                TacacsMinorVersion::TacacsPlusMinorVerOne,
                TacacsType::TacPlusAuthentication,
                1,
                TACACS_FLAG_UNENCRYPTED,
                12345,
                100,
                &mut error,
            );

            let mut buffer = [0u8; 12];
            let written =
                tacacs_header_to_bytes(header, buffer.as_mut_ptr(), buffer.len(), &mut error);

            assert_eq!(written, 12);
            assert_eq!(error.code, TacacsResult::Success);

            tacacs_header_free(header);
        }
    }
}
