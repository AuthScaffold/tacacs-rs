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

fn syslog_debug(message: &str) {
    let sanitized = message.replace('\0', " ");
    let Ok(format) = CString::new("TACACS+: %s") else {
        return;
    };
    let Ok(message) = CString::new(sanitized) else {
        return;
    };
    // SAFETY: `format` and `message` are valid NUL-terminated C strings for
    // this call. The fixed format has one `%s` conversion, which matches the
    // message pointer argument.
    unsafe {
        libc::syslog(libc::LOG_DEBUG, format.as_ptr(), message.as_ptr());
    }
}
