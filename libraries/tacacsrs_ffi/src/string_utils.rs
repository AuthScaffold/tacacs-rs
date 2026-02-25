//! String handling utilities for FFI
//!
//! This module provides utilities for converting between Rust strings and C strings.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use crate::error::{TacacsError, TacacsResult};

/// Convert a C string to a Rust string slice
///
/// # Safety
///
/// The pointer must be non-null and point to a valid null-terminated UTF-8 string.
pub unsafe fn c_str_to_rust<'a>(c_str: *const c_char) -> Result<&'a str, TacacsError> {
    if c_str.is_null() {
        return Err(TacacsError::new(TacacsResult::NullPointer, "Null pointer passed as string"));
    }

    let c_str = CStr::from_ptr(c_str);
    c_str
        .to_str()
        .map_err(|_| TacacsError::new(TacacsResult::InvalidUtf8, "Invalid UTF-8 in string"))
}

/// Convert a Rust string to a C string (allocated)
///
/// The returned pointer must be freed using `tacacs_free_string()`.
pub fn rust_str_to_c(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a string allocated by the library
///
/// # Safety
///
/// The string pointer must have been returned by a TACACS FFI function
/// and must not be null. After calling this function, the pointer is invalid.
#[no_mangle]
pub unsafe extern "C" fn tacacs_free_string(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_to_c_string() {
        let c_str = rust_str_to_c("test");
        assert!(!c_str.is_null());
        unsafe {
            let rust_str = c_str_to_rust(c_str).unwrap();
            assert_eq!(rust_str, "test");
            tacacs_free_string(c_str);
        }
    }
}
