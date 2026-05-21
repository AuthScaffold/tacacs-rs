use std::env;
use std::os::raw::c_char;

use super::c_strings::c_string;
use super::pal;

pub(crate) fn get_user_name(user: *mut c_char) -> String {
    let user = c_string(user);
    if !user.is_empty() {
        return user;
    }

    pal::active().current_user_name()
}

pub(crate) fn is_remote_user(user: &str) -> bool {
    if user == "UNKNOWN" {
        return true;
    }

    pal::active().is_remote_user(user)
}

pub(crate) fn remote_address() -> String {
    first_env_token("SSH_CONNECTION")
        .or_else(|| first_env_token("SSH_CLIENT_IPADDR_PORT"))
        .unwrap_or_else(|| "UNK".to_owned())
}

pub(crate) fn tty_name() -> String {
    pal::active().tty_name()
}

pub(crate) fn task_id() -> u16 {
    pal::active().task_id()
}

fn first_env_token(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .and_then(|value| value.split_whitespace().next().map(ToOwned::to_owned))
}
