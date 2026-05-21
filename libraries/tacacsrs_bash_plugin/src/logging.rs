use std::os::raw::c_int;

use super::config::DEBUG_FLAG;
use super::pal;

pub(crate) fn debug_log(flags: c_int, message: &str) {
    if flags & DEBUG_FLAG == 0 {
        return;
    }
    eprintln!("TACACS+: {message}");
    pal::active().syslog_debug(message);
}
