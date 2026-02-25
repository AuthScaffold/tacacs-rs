//! FFI bindings for TACACS+ accounting operations

use std::os::raw::c_char;
use std::ptr;
use std::slice;

use tacacsrs_messages::accounting::reply::AccountingReply as RustAccountingReply;
use tacacsrs_messages::accounting::request::AccountingRequest as RustAccountingRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationMethod,
    TacacsAuthenticationService, TacacsAuthenticationType,
};
use tacacsrs_messages::packet::Packet as RustPacket;
use tacacsrs_messages::traits::TacacsBodyTrait;

use crate::error::{TacacsError, TacacsResult};
use crate::packet::TacacsPacket;
use crate::string_utils::{c_str_to_rust, rust_str_to_c};

/// Opaque type for TACACS+ accounting request
#[repr(C)]
pub struct TacacsAccountingRequest {
    _private: [u8; 0],
}

/// Opaque type for TACACS+ accounting reply
#[repr(C)]
pub struct TacacsAccountingReply {
    _private: [u8; 0],
}

/// TACACS+ accounting flags
pub const TACACS_ACCOUNTING_FLAG_START: u8 = TacacsAccountingFlags::START.bits();
pub const TACACS_ACCOUNTING_FLAG_STOP: u8 = TacacsAccountingFlags::STOP.bits();
pub const TACACS_ACCOUNTING_FLAG_WATCHDOG: u8 = TacacsAccountingFlags::WATCHDOG.bits();

/// Create a new TACACS+ accounting request
///
/// # Safety
///
/// - All string pointers must be valid null-terminated UTF-8 strings
/// - The `args` array must contain `args_count` valid string pointers
/// - Returns a pointer to a newly allocated request that must be freed with `tacacs_accounting_request_free()`
/// - Returns null on error
#[no_mangle]
pub unsafe extern "C" fn tacacs_accounting_request_new(
    flags: u8,
    authen_method: TacacsAuthenticationMethod,
    priv_lvl: u8,
    authen_type: TacacsAuthenticationType,
    authen_service: TacacsAuthenticationService,
    user: *const c_char,
    port: *const c_char,
    rem_address: *const c_char,
    args: *const *const c_char,
    args_count: usize,
    error: *mut TacacsError,
) -> *mut TacacsAccountingRequest {
    // Convert strings
    let user_str = match c_str_to_rust(user) {
        Ok(s) => s.to_string(),
        Err(e) => {
            if !error.is_null() {
                *error = e;
            }
            return ptr::null_mut();
        }
    };

    let port_str = match c_str_to_rust(port) {
        Ok(s) => s.to_string(),
        Err(e) => {
            if !error.is_null() {
                *error = e;
            }
            return ptr::null_mut();
        }
    };

    let rem_address_str = match c_str_to_rust(rem_address) {
        Ok(s) => s.to_string(),
        Err(e) => {
            if !error.is_null() {
                *error = e;
            }
            return ptr::null_mut();
        }
    };

    // Convert args array
    let mut args_vec = Vec::new();
    if !args.is_null() && args_count > 0 {
        let args_slice = slice::from_raw_parts(args, args_count);
        for arg_ptr in args_slice {
            match c_str_to_rust(*arg_ptr) {
                Ok(s) => args_vec.push(s.to_string()),
                Err(e) => {
                    if !error.is_null() {
                        *error = e;
                    }
                    return ptr::null_mut();
                }
            }
        }
    }

    // Convert flags
    let rust_flags = match TacacsAccountingFlags::from_bits(flags) {
        Some(f) => f,
        None => {
            if !error.is_null() {
                *error = TacacsError::new(TacacsResult::InvalidInput, "Invalid accounting flags");
            }
            return ptr::null_mut();
        }
    };

    let request = RustAccountingRequest {
        flags: rust_flags,
        authen_method,
        priv_lvl,
        authen_type,
        authen_service,
        user: user_str,
        port: port_str,
        rem_address: rem_address_str,
        args: args_vec,
    };

    if !error.is_null() {
        *error = TacacsError::success();
    }

    Box::into_raw(Box::new(request)) as *mut TacacsAccountingRequest
}

/// Parse a TACACS+ accounting request from a packet
///
/// # Safety
///
/// - The `packet` pointer must be valid and point to a packet created by this library
/// - Returns a pointer to a newly allocated request that must be freed with `tacacs_accounting_request_free()`
/// - Returns null on parse failure or allocation failure
#[no_mangle]
pub unsafe extern "C" fn tacacs_accounting_request_from_packet(
    packet: *const TacacsPacket,
    error: *mut TacacsError,
) -> *mut TacacsAccountingRequest {
    if packet.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Packet pointer is null");
        }
        return ptr::null_mut();
    }

    let packet_ref = &*(packet as *const RustPacket);

    match RustAccountingRequest::from_packet(packet_ref) {
        Ok(request) => {
            if !error.is_null() {
                *error = TacacsError::success();
            }
            Box::into_raw(Box::new(request)) as *mut TacacsAccountingRequest
        }
        Err(e) => {
            if !error.is_null() {
                *error = TacacsError::new(
                    TacacsResult::InvalidPacket,
                    &format!("Failed to parse accounting request: {}", e),
                );
            }
            ptr::null_mut()
        }
    }
}

/// Convert a TACACS+ accounting request to bytes
///
/// # Safety
///
/// - The `request` pointer must be valid and point to a request created by this library
/// - Returns a pointer to an allocated byte buffer, or null on error
/// - The returned buffer must be freed with `tacacs_free_bytes()`
#[no_mangle]
pub unsafe extern "C" fn tacacs_accounting_request_to_bytes(
    request: *const TacacsAccountingRequest,
    out_len: *mut usize,
    error: *mut TacacsError,
) -> *mut u8 {
    if request.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Request pointer is null");
        }
        return ptr::null_mut();
    }

    if out_len.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Output length pointer is null");
        }
        return ptr::null_mut();
    }

    let request_ref = &*(request as *const RustAccountingRequest);
    let bytes = request_ref.to_bytes();

    *out_len = bytes.len();

    if !error.is_null() {
        *error = TacacsError::success();
    }

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

/// Get the user field from an accounting request
///
/// # Safety
///
/// - The `request` pointer must be valid and point to a request created by this library
/// - Returns an allocated string that must be freed with `tacacs_free_string()`
/// - Returns null if the pointer is null
#[no_mangle]
pub unsafe extern "C" fn tacacs_accounting_request_get_user(
    request: *const TacacsAccountingRequest,
) -> *mut c_char {
    if request.is_null() {
        return ptr::null_mut();
    }

    let request_ref = &*(request as *const RustAccountingRequest);
    rust_str_to_c(&request_ref.user)
}

/// Get the port field from an accounting request
///
/// # Safety
///
/// - The `request` pointer must be valid and point to a request created by this library
/// - Returns an allocated string that must be freed with `tacacs_free_string()`
/// - Returns null if the pointer is null
#[no_mangle]
pub unsafe extern "C" fn tacacs_accounting_request_get_port(
    request: *const TacacsAccountingRequest,
) -> *mut c_char {
    if request.is_null() {
        return ptr::null_mut();
    }

    let request_ref = &*(request as *const RustAccountingRequest);
    rust_str_to_c(&request_ref.port)
}

/// Get the remote address field from an accounting request
///
/// # Safety
///
/// - The `request` pointer must be valid and point to a request created by this library
/// - Returns an allocated string that must be freed with `tacacs_free_string()`
/// - Returns null if the pointer is null
#[no_mangle]
pub unsafe extern "C" fn tacacs_accounting_request_get_rem_address(
    request: *const TacacsAccountingRequest,
) -> *mut c_char {
    if request.is_null() {
        return ptr::null_mut();
    }

    let request_ref = &*(request as *const RustAccountingRequest);
    rust_str_to_c(&request_ref.rem_address)
}

/// Get the privilege level from an accounting request
///
/// # Safety
///
/// - The `request` pointer must be valid and point to a request created by this library
/// - Returns 0 if the pointer is null
#[no_mangle]
pub unsafe extern "C" fn tacacs_accounting_request_get_priv_lvl(
    request: *const TacacsAccountingRequest,
) -> u8 {
    if request.is_null() {
        return 0;
    }

    let request_ref = &*(request as *const RustAccountingRequest);
    request_ref.priv_lvl
}

/// Get the flags from an accounting request
///
/// # Safety
///
/// - The `request` pointer must be valid and point to a request created by this library
/// - Returns 0 if the pointer is null
#[no_mangle]
pub unsafe extern "C" fn tacacs_accounting_request_get_flags(
    request: *const TacacsAccountingRequest,
) -> u8 {
    if request.is_null() {
        return 0;
    }

    let request_ref = &*(request as *const RustAccountingRequest);
    request_ref.flags.bits()
}

/// Free a TACACS+ accounting request
///
/// # Safety
///
/// - The `request` pointer must be valid and must have been allocated by this library
/// - After calling this function, the pointer is invalid
#[no_mangle]
pub unsafe extern "C" fn tacacs_accounting_request_free(request: *mut TacacsAccountingRequest) {
    if !request.is_null() {
        let _ = Box::from_raw(request as *mut RustAccountingRequest);
    }
}

/// Create a new TACACS+ accounting reply
///
/// # Safety
///
/// - All string pointers must be valid null-terminated UTF-8 strings
/// - Returns a pointer to a newly allocated reply that must be freed with `tacacs_accounting_reply_free()`
/// - Returns null on error
#[no_mangle]
pub unsafe extern "C" fn tacacs_accounting_reply_new(
    status: TacacsAccountingStatus,
    server_msg: *const c_char,
    data: *const c_char,
    error: *mut TacacsError,
) -> *mut TacacsAccountingReply {
    let server_msg_str = match c_str_to_rust(server_msg) {
        Ok(s) => s.to_string(),
        Err(e) => {
            if !error.is_null() {
                *error = e;
            }
            return ptr::null_mut();
        }
    };

    let data_str = match c_str_to_rust(data) {
        Ok(s) => s.to_string(),
        Err(e) => {
            if !error.is_null() {
                *error = e;
            }
            return ptr::null_mut();
        }
    };

    let reply = RustAccountingReply {
        status,
        server_msg: server_msg_str,
        data: data_str,
    };

    if !error.is_null() {
        *error = TacacsError::success();
    }

    Box::into_raw(Box::new(reply)) as *mut TacacsAccountingReply
}

/// Parse a TACACS+ accounting reply from a packet
///
/// # Safety
///
/// - The `packet` pointer must be valid and point to a packet created by this library
/// - Returns a pointer to a newly allocated reply that must be freed with `tacacs_accounting_reply_free()`
/// - Returns null on parse failure or allocation failure
#[no_mangle]
pub unsafe extern "C" fn tacacs_accounting_reply_from_packet(
    packet: *const TacacsPacket,
    error: *mut TacacsError,
) -> *mut TacacsAccountingReply {
    if packet.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Packet pointer is null");
        }
        return ptr::null_mut();
    }

    let packet_ref = &*(packet as *const RustPacket);

    match RustAccountingReply::from_packet(packet_ref) {
        Ok(reply) => {
            if !error.is_null() {
                *error = TacacsError::success();
            }
            Box::into_raw(Box::new(reply)) as *mut TacacsAccountingReply
        }
        Err(e) => {
            if !error.is_null() {
                *error = TacacsError::new(
                    TacacsResult::InvalidPacket,
                    &format!("Failed to parse accounting reply: {}", e),
                );
            }
            ptr::null_mut()
        }
    }
}

/// Convert a TACACS+ accounting reply to bytes
///
/// # Safety
///
/// - The `reply` pointer must be valid and point to a reply created by this library
/// - Returns a pointer to an allocated byte buffer, or null on error
/// - The returned buffer must be freed with `tacacs_free_bytes()`
#[no_mangle]
pub unsafe extern "C" fn tacacs_accounting_reply_to_bytes(
    reply: *const TacacsAccountingReply,
    out_len: *mut usize,
    error: *mut TacacsError,
) -> *mut u8 {
    if reply.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Reply pointer is null");
        }
        return ptr::null_mut();
    }

    if out_len.is_null() {
        if !error.is_null() {
            *error = TacacsError::new(TacacsResult::NullPointer, "Output length pointer is null");
        }
        return ptr::null_mut();
    }

    let reply_ref = &*(reply as *const RustAccountingReply);
    let bytes = reply_ref.to_bytes();

    *out_len = bytes.len();

    if !error.is_null() {
        *error = TacacsError::success();
    }

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

/// Get the server message from an accounting reply
///
/// # Safety
///
/// - The `reply` pointer must be valid and point to a reply created by this library
/// - Returns an allocated string that must be freed with `tacacs_free_string()`
/// - Returns null if the pointer is null
#[no_mangle]
pub unsafe extern "C" fn tacacs_accounting_reply_get_server_msg(
    reply: *const TacacsAccountingReply,
) -> *mut c_char {
    if reply.is_null() {
        return ptr::null_mut();
    }

    let reply_ref = &*(reply as *const RustAccountingReply);
    rust_str_to_c(&reply_ref.server_msg)
}

/// Get the data field from an accounting reply
///
/// # Safety
///
/// - The `reply` pointer must be valid and point to a reply created by this library
/// - Returns an allocated string that must be freed with `tacacs_free_string()`
/// - Returns null if the pointer is null
#[no_mangle]
pub unsafe extern "C" fn tacacs_accounting_reply_get_data(
    reply: *const TacacsAccountingReply,
) -> *mut c_char {
    if reply.is_null() {
        return ptr::null_mut();
    }

    let reply_ref = &*(reply as *const RustAccountingReply);
    rust_str_to_c(&reply_ref.data)
}

/// Get the status from an accounting reply
///
/// # Safety
///
/// - The `reply` pointer must be valid and point to a reply created by this library
/// - Returns the status code, or TacPlusAcctStatusError if the pointer is null
#[no_mangle]
pub unsafe extern "C" fn tacacs_accounting_reply_get_status(
    reply: *const TacacsAccountingReply,
) -> TacacsAccountingStatus {
    if reply.is_null() {
        return TacacsAccountingStatus::TacPlusAcctStatusError;
    }

    let reply_ref = &*(reply as *const RustAccountingReply);
    reply_ref.status
}

/// Free a TACACS+ accounting reply
///
/// # Safety
///
/// - The `reply` pointer must be valid and must have been allocated by this library
/// - After calling this function, the pointer is invalid
#[no_mangle]
pub unsafe extern "C" fn tacacs_accounting_reply_free(reply: *mut TacacsAccountingReply) {
    if !reply.is_null() {
        let _ = Box::from_raw(reply as *mut RustAccountingReply);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accounting_request_creation() {
        unsafe {
            let mut error = TacacsError::success();

            let user = std::ffi::CString::new("testuser").unwrap();
            let port = std::ffi::CString::new("tty1").unwrap();
            let rem_addr = std::ffi::CString::new("192.168.1.1").unwrap();

            let request = tacacs_accounting_request_new(
                TACACS_ACCOUNTING_FLAG_START,
                TacacsAuthenticationMethod::TacPlusAuthenMethodLocal,
                15,
                TacacsAuthenticationType::TacPlusAuthenTypeAscii,
                TacacsAuthenticationService::TacPlusAuthenSvcLogin,
                user.as_ptr(),
                port.as_ptr(),
                rem_addr.as_ptr(),
                ptr::null(),
                0,
                &mut error,
            );

            assert!(!request.is_null());
            assert_eq!(error.code, TacacsResult::Success);

            let priv_lvl = tacacs_accounting_request_get_priv_lvl(request);
            assert_eq!(priv_lvl, 15);

            tacacs_accounting_request_free(request);
        }
    }

    #[test]
    fn test_accounting_reply_creation() {
        unsafe {
            let mut error = TacacsError::success();

            let server_msg = std::ffi::CString::new("Success").unwrap();
            let data = std::ffi::CString::new("").unwrap();

            let reply = tacacs_accounting_reply_new(
                TacacsAccountingStatus::TacPlusAcctStatusSuccess,
                server_msg.as_ptr(),
                data.as_ptr(),
                &mut error,
            );

            assert!(!reply.is_null());
            assert_eq!(error.code, TacacsResult::Success);

            let status = tacacs_accounting_reply_get_status(reply);
            assert_eq!(status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);

            tacacs_accounting_reply_free(reply);
        }
    }
}
