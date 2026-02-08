//! FFI bindings for TACACS+ packet operations

use std::ptr;
use std::slice;

use tacacsrs_messages::packet::Packet as RustPacket;

use crate::error::{TacacsError, TacacsResult};
use crate::header::TacacsHeader;

/// Opaque pointer to a TACACS+ packet
pub type TacacsPacket = RustPacket;

/// Create a new TACACS+ packet from a header and body
///
/// # Safety
///
/// - The `header` pointer must be valid and point to a header created by this library
/// - The `body` pointer must point to at least `body_len` bytes of valid memory
/// - Returns a pointer to a newly allocated packet that must be freed with `tacacs_packet_free()`
/// - Returns null on error
#[no_mangle]
pub unsafe extern "C" fn tacacs_packet_new(
    header: *const TacacsHeader,
    body: *const u8,
    body_len: usize,
    error: *mut TacacsError,
) -> *mut TacacsPacket {
    if header.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Header pointer is null");
        }
        return ptr::null_mut();
    }
    
    if body.is_null() && body_len > 0 {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Body pointer is null");
        }
        return ptr::null_mut();
    }
    
    let header_ref = &*header;
    let body_slice = if body_len > 0 {
        slice::from_raw_parts(body, body_len)
    } else {
        &[]
    };
    
    match RustPacket::new(header_ref.clone(), body_slice.to_vec()) {
        Ok(packet) => {
            if !error.is_null() {
                *error = TacacsError::success();
            }
            Box::into_raw(Box::new(packet))
        }
        Err(e) => {
            if !error.is_null() {
                *error = TacacsError::new(
                    TacacsResult::InvalidPacket,
                    &format!("Failed to create packet: {}", e),
                );
            }
            ptr::null_mut()
        }
    }
}

/// Parse a TACACS+ packet from bytes
///
/// # Safety
///
/// - The `data` pointer must point to at least `data_len` bytes of valid memory
/// - Returns a pointer to a newly allocated packet that must be freed with `tacacs_packet_free()`
/// - Returns null on parse failure or allocation failure
#[no_mangle]
pub unsafe extern "C" fn tacacs_packet_from_bytes(
    data: *const u8,
    data_len: usize,
    error: *mut TacacsError,
) -> *mut TacacsPacket {
    if data.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Data pointer is null");
        }
        return ptr::null_mut();
    }
    
    let slice = slice::from_raw_parts(data, data_len);
    
    match RustPacket::from_bytes(slice) {
        Ok(packet) => {
            if !error.is_null() {
                *error = TacacsError::success();
            }
            Box::into_raw(Box::new(packet))
        }
        Err(e) => {
            if !error.is_null() {
                *error = TacacsError::new(
                    TacacsResult::InvalidPacket,
                    &format!("Failed to parse packet: {}", e),
                );
            }
            ptr::null_mut()
        }
    }
}

/// Serialize a TACACS+ packet to bytes
///
/// This function returns the serialized bytes in a newly allocated buffer.
/// The caller must free the buffer using `tacacs_free_bytes()`.
///
/// # Safety
///
/// - The `packet` pointer must be valid and point to a packet created by this library
/// - The `out_len` pointer must be valid and will be set to the length of the output buffer
/// - Returns a pointer to the allocated buffer, or null on error
#[no_mangle]
pub unsafe extern "C" fn tacacs_packet_to_bytes(
    packet: *const TacacsPacket,
    out_len: *mut usize,
    error: *mut TacacsError,
) -> *mut u8 {
    if packet.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Packet pointer is null");
        }
        return ptr::null_mut();
    }
    
    if out_len.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Output length pointer is null");
        }
        return ptr::null_mut();
    }
    
    let packet_ref = &*packet;
    let bytes = packet_ref.to_bytes();
    
    *out_len = bytes.len();
    
    if !error.is_null() {
        *error = TacacsError::success();
    }
    
    // Allocate a new buffer and copy the bytes
    let buffer = libc::malloc(bytes.len()) as *mut u8;
    if buffer.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::MemoryAllocation, "Failed to allocate memory");
        }
        return ptr::null_mut();
    }
    
    ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len());
    buffer
}

/// Obfuscate a TACACS+ packet
///
/// Creates a new obfuscated packet from an unobfuscated packet.
///
/// # Safety
///
/// - The `packet` pointer must be valid and point to a packet created by this library
/// - The `key` pointer must point to at least `key_len` bytes of valid memory
/// - Returns a pointer to a newly allocated obfuscated packet, or null if already obfuscated
/// - The returned packet must be freed with `tacacs_packet_free()`
#[no_mangle]
pub unsafe extern "C" fn tacacs_packet_obfuscate(
    packet: *const TacacsPacket,
    key: *const u8,
    key_len: usize,
    error: *mut TacacsError,
) -> *mut TacacsPacket {
    if packet.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Packet pointer is null");
        }
        return ptr::null_mut();
    }
    
    if key.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Key pointer is null");
        }
        return ptr::null_mut();
    }
    
    let packet_ref = &*packet;
    let key_slice = slice::from_raw_parts(key, key_len);
    
    match packet_ref.as_obfuscated(key_slice) {
        Some(obfuscated) => {
            if !error.is_null() {
                *error = TacacsError::success();
            }
            Box::into_raw(Box::new(obfuscated))
        }
        None => {
            if !error.is_null() {
                *error = TacacsError::new(
                    TacacsResult::InvalidInput,
                    "Packet is already obfuscated",
                );
            }
            ptr::null_mut()
        }
    }
}

/// Deobfuscate a TACACS+ packet
///
/// Creates a new deobfuscated packet from an obfuscated packet.
///
/// # Safety
///
/// - The `packet` pointer must be valid and point to a packet created by this library
/// - The `key` pointer must point to at least `key_len` bytes of valid memory
/// - Returns a pointer to a newly allocated deobfuscated packet, or null if already deobfuscated
/// - The returned packet must be freed with `tacacs_packet_free()`
#[no_mangle]
pub unsafe extern "C" fn tacacs_packet_deobfuscate(
    packet: *const TacacsPacket,
    key: *const u8,
    key_len: usize,
    error: *mut TacacsError,
) -> *mut TacacsPacket {
    if packet.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Packet pointer is null");
        }
        return ptr::null_mut();
    }
    
    if key.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Key pointer is null");
        }
        return ptr::null_mut();
    }
    
    let packet_ref = &*packet;
    let key_slice = slice::from_raw_parts(key, key_len);
    
    match packet_ref.as_deobfuscated(key_slice) {
        Some(deobfuscated) => {
            if !error.is_null() {
                *error = TacacsError::success();
            }
            Box::into_raw(Box::new(deobfuscated))
        }
        None => {
            if !error.is_null() {
                *error = TacacsError::new(
                    TacacsResult::InvalidInput,
                    "Packet is already deobfuscated",
                );
            }
            ptr::null_mut()
        }
    }
}

/// Free a byte buffer allocated by the library
///
/// # Safety
///
/// The buffer pointer must have been returned by a TACACS FFI function.
/// After calling this function, the pointer is invalid.
#[no_mangle]
pub unsafe extern "C" fn tacacs_free_bytes(buffer: *mut u8) {
    if !buffer.is_null() {
        libc::free(buffer as *mut libc::c_void);
    }
}

/// Free a TACACS+ packet
///
/// # Safety
///
/// The `packet` pointer must be valid and must have been allocated by this library.
/// After calling this function, the pointer is invalid.
#[no_mangle]
pub unsafe extern "C" fn tacacs_packet_free(packet: *mut TacacsPacket) {
    if !packet.is_null() {
        let _ = Box::from_raw(packet);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::*;
    
    #[test]
    fn test_packet_creation() {
        unsafe {
            let mut error = TacacsError::success();
            let header = tacacs_header_new(
                CTacacsMajorVersion::TacacsPlusMajor1,
                CTacacsMinorVersion::TacacsPlusMinorVerOne,
                CTacacsType::TacPlusAuthentication,
                1,
                TACACS_FLAG_UNENCRYPTED,
                12345,
                5,
                &mut error,
            );
            
            let body = b"hello";
            let packet = tacacs_packet_new(header, body.as_ptr(), body.len(), &mut error);
            
            assert!(!packet.is_null());
            assert_eq!(error.code, TacacsResult::Success);
            
            tacacs_packet_free(packet);
            tacacs_header_free(header);
        }
    }
    
    #[test]
    fn test_packet_serialization() {
        unsafe {
            let mut error = TacacsError::success();
            let header = tacacs_header_new(
                CTacacsMajorVersion::TacacsPlusMajor1,
                CTacacsMinorVersion::TacacsPlusMinorVerOne,
                CTacacsType::TacPlusAuthentication,
                1,
                TACACS_FLAG_UNENCRYPTED,
                12345,
                5,
                &mut error,
            );
            
            let body = b"hello";
            let packet = tacacs_packet_new(header, body.as_ptr(), body.len(), &mut error);
            
            let mut out_len = 0;
            let buffer = tacacs_packet_to_bytes(packet, &mut out_len, &mut error);
            
            assert!(!buffer.is_null());
            assert_eq!(out_len, 12 + 5); // header + body
            assert_eq!(error.code, TacacsResult::Success);
            
            tacacs_free_bytes(buffer);
            tacacs_packet_free(packet);
            tacacs_header_free(header);
        }
    }
}
