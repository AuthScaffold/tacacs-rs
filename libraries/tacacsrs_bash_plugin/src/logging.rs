#[cfg(unix)]
use std::ffi::CString;
use std::os::raw::c_int;

use crate::config::DEBUG_FLAG;

pub(crate) fn debug_log(flags: c_int, message: &str) {
    if flags & DEBUG_FLAG == 0 {
        return;
    }
    eprintln!("TACACS+: {message}");
    syslog_debug(message);
}

#[cfg(unix)]
fn syslog_debug(message: &str) {
    let sanitized = message.replace('\0', " ");
    let Ok(format) = CString::new("TACACS+: %s") else {
        return;
    };
    let Ok(message) = CString::new(sanitized) else {
        return;
    };
    unsafe {
        libc::syslog(libc::LOG_DEBUG, format.as_ptr(), message.as_ptr());
    }
}

#[cfg(not(unix))]
fn syslog_debug(_message: &str) {}
