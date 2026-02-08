//! Error handling for FFI
//!
//! This module defines error codes and error structures for passing errors
//! across the FFI boundary.

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

/// Result codes for TACACS FFI operations
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TacacsResult {
    /// Operation completed successfully
    Success = 0,
    /// Invalid input parameter
    InvalidInput = 1,
    /// Network failure
    NetworkFailure = 2,
    /// TACACS+ protocol error
    ProtocolError = 3,
    /// Memory allocation failure
    MemoryAllocation = 4,
    /// Null pointer error
    NullPointer = 5,
    /// Invalid UTF-8 string
    InvalidUtf8 = 6,
    /// Buffer too small
    BufferTooSmall = 7,
    /// Invalid header data
    InvalidHeader = 8,
    /// Invalid packet data
    InvalidPacket = 9,
    /// Unknown error
    Unknown = 255,
}

/// Error information structure
///
/// Contains an error code and an optional error message.
/// The message is allocated by Rust and must be freed using `tacacs_free_error_message()`.
#[repr(C)]
#[derive(Debug)]
pub struct TacacsError {
    /// Error code
    pub code: TacacsResult,
    /// Error message (may be null)
    pub message: *mut c_char,
}

impl TacacsError {
    /// Create a new error with a code and message
    pub fn new(code: TacacsResult, message: &str) -> Self {
        let c_message = CString::new(message).unwrap_or_else(|_| {
            CString::new("Failed to create error message").unwrap()
        });
        
        TacacsError {
            code,
            message: c_message.into_raw(),
        }
    }
    
    /// Create a success error (no error)
    pub fn success() -> Self {
        TacacsError {
            code: TacacsResult::Success,
            message: ptr::null_mut(),
        }
    }
    
    /// Create an error from an anyhow::Error
    pub fn from_anyhow(error: anyhow::Error) -> Self {
        let message = format!("{:#}", error);
        TacacsError::new(TacacsResult::Unknown, &message)
    }
}

/// Free an error message allocated by the library
///
/// # Safety
///
/// The message pointer must have been returned by a TACACS FFI function
/// and must not be null. After calling this function, the pointer is invalid.
#[no_mangle]
pub unsafe extern "C" fn tacacs_free_error_message(message: *mut c_char) {
    if !message.is_null() {
        let _ = CString::from_raw(message);
    }
}

/// Free a TacacsError structure
///
/// # Safety
///
/// The error pointer must be valid and must have been allocated by this library.
#[no_mangle]
pub unsafe extern "C" fn tacacs_free_error(error: *mut TacacsError) {
    if !error.is_null() {
        let error = Box::from_raw(error);
        if !error.message.is_null() {
            let _ = CString::from_raw(error.message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_creation() {
        let error = TacacsError::new(TacacsResult::InvalidInput, "Test error");
        assert_eq!(error.code, TacacsResult::InvalidInput);
        assert!(!error.message.is_null());
        unsafe {
            tacacs_free_error_message(error.message);
        }
    }
    
    #[test]
    fn test_success_error() {
        let error = TacacsError::success();
        assert_eq!(error.code, TacacsResult::Success);
        assert!(error.message.is_null());
    }
}
