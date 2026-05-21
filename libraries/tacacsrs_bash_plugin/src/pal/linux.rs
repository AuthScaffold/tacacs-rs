//! Linux GNU platform implementation for the SONiC bash plugin.

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use super::Platform;
use crate::c_strings::c_string;

const REMOTE_USER_GECOS_PREFIX: &str = "remote_user";

pub(crate) static PLATFORM: LinuxPlatform = LinuxPlatform;

pub(crate) struct LinuxPlatform;

impl Platform for LinuxPlatform {
    fn current_user_name(&self) -> String {
        user_name_from_uid(unsafe { libc::getuid() })
            .or_else(|| user_name_from_uid(unsafe { libc::geteuid() }))
            .unwrap_or_else(|| "UNKNOWN".to_owned())
    }

    fn is_remote_user(&self, user: &str) -> bool {
        unsafe {
            libc::setpwent();
            let mut passwd: libc::passwd = std::mem::zeroed();
            let mut result: *mut libc::passwd = ptr::null_mut();
            let mut buffer = vec![0_u8; 4096];

            while libc::getpwent_r(
                &mut passwd,
                buffer.as_mut_ptr().cast::<c_char>(),
                buffer.len(),
                &mut result,
            ) == 0
                && !result.is_null()
            {
                if c_string(passwd.pw_name) == user {
                    let gecos = c_string(passwd.pw_gecos);
                    libc::endpwent();
                    return gecos.starts_with(REMOTE_USER_GECOS_PREFIX);
                }
            }
            libc::endpwent();
        }
        false
    }

    fn tty_name(&self) -> String {
        for fd in 0..3 {
            if unsafe { libc::isatty(fd) } != 0 {
                let mut buffer = [0_i8; 64];
                if unsafe { libc::ttyname_r(fd, buffer.as_mut_ptr(), buffer.len()) } == 0 {
                    return c_string(buffer.as_ptr());
                }
            }
        }
        "UNK".to_owned()
    }

    fn task_id(&self) -> u16 {
        u16::try_from(unsafe { libc::getpid() }).unwrap_or(u16::MAX)
    }

    fn syslog_debug(&self, message: &str) {
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
}

fn user_name_from_uid(uid: libc::uid_t) -> Option<String> {
    let passwd = unsafe { libc::getpwuid(uid) };
    if passwd.is_null() {
        return None;
    }
    let name = unsafe { (*passwd).pw_name };
    if name.is_null() {
        None
    } else {
        Some(c_string(name))
    }
}
