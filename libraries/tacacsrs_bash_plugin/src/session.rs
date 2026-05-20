use std::env;
use std::os::raw::c_char;
#[cfg(all(unix, not(target_env = "musl")))]
use std::ptr;

use crate::c_strings::c_string;

#[cfg(unix)]
const REMOTE_USER_GECOS_PREFIX: &str = "remote_user";

#[cfg(all(unix, target_env = "musl"))]
static PASSWD_ITERATION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) fn get_user_name(user: *mut c_char) -> String {
    let user = c_string(user);
    if !user.is_empty() {
        return user;
    }

    #[cfg(unix)]
    {
        user_name_from_uid(unsafe { libc::getuid() })
            .or_else(|| user_name_from_uid(unsafe { libc::geteuid() }))
            .unwrap_or_else(|| "UNKNOWN".to_owned())
    }

    #[cfg(not(unix))]
    {
        "UNKNOWN".to_owned()
    }
}

pub(crate) fn is_remote_user(user: &str) -> bool {
    if user == "UNKNOWN" {
        return true;
    }

    #[cfg(unix)]
    {
        unix_is_remote_user(user)
    }

    #[cfg(not(unix))]
    {
        let _ = user;
        true
    }
}

pub(crate) fn remote_address() -> String {
    first_env_token("SSH_CONNECTION")
        .or_else(|| first_env_token("SSH_CLIENT_IPADDR_PORT"))
        .unwrap_or_else(|| "UNK".to_owned())
}

pub(crate) fn tty_name() -> String {
    #[cfg(unix)]
    {
        for fd in 0..3 {
            if unsafe { libc::isatty(fd) } != 0 {
                let mut buffer = [0_i8; 64];
                if unsafe { libc::ttyname_r(fd, buffer.as_mut_ptr(), buffer.len()) } == 0 {
                    return c_string(buffer.as_ptr());
                }
            }
        }
    }
    "UNK".to_owned()
}

pub(crate) fn task_id() -> u16 {
    #[cfg(unix)]
    {
        u16::try_from(unsafe { libc::getpid() }).unwrap_or(u16::MAX)
    }

    #[cfg(not(unix))]
    {
        0
    }
}

fn first_env_token(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .and_then(|value| value.split_whitespace().next().map(ToOwned::to_owned))
}

#[cfg(unix)]
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

#[cfg(all(unix, not(target_env = "musl")))]
fn unix_is_remote_user(user: &str) -> bool {
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

#[cfg(all(unix, target_env = "musl"))]
fn unix_is_remote_user(user: &str) -> bool {
    let _guard = PASSWD_ITERATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut is_remote = false;

    unsafe {
        libc::setpwent();
        loop {
            let passwd = libc::getpwent();
            if passwd.is_null() {
                break;
            }

            if c_string((*passwd).pw_name) == user {
                let gecos = c_string((*passwd).pw_gecos);
                is_remote = gecos.starts_with(REMOTE_USER_GECOS_PREFIX);
                break;
            }
        }
        libc::endpwent();
    }

    is_remote
}
