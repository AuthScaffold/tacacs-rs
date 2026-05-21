use std::os::raw::{c_char, c_int};

use super::authorization::{AuthorizationDecision, authorize_command};
use super::c_strings::{argv_strings, c_string};
use super::config::{LOCAL_AUTHORIZATION_FLAG, TACACS_AUTHORIZATION_FLAG, current_flags, reload_config};
use super::logging::debug_log;
use super::session::{get_user_name, is_remote_user, remote_address, tty_name};

#[no_mangle]
pub unsafe extern "C" fn plugin_init() -> c_int {
    let flags = reload_config(true);
    debug_log(flags, "tacacsrs bash plugin initialized");
    0
}

#[no_mangle]
pub unsafe extern "C" fn plugin_uninit() -> c_int {
    let flags = current_flags();
    debug_log(flags, "tacacsrs bash plugin uninitialized");
    0
}

#[no_mangle]
pub unsafe extern "C" fn on_shell_execve(
    user: *mut c_char,
    shell_level: c_int,
    cmd: *mut c_char,
    argv: *mut *mut c_char,
) -> c_int {
    if shell_level > 2 {
        return 0;
    }

    let flags = reload_config(false);
    if flags & TACACS_AUTHORIZATION_FLAG == 0 {
        debug_log(flags, "TACACS+ command authorization is disabled");
        return 0;
    }

    let user_name = get_user_name(user);
    if !is_remote_user(&user_name) {
        debug_log(flags, &format!("user {user_name} is local; allowing local authorization"));
        return 0;
    }

    let command = c_string(cmd);
    let args = argv_strings(argv);
    let port = tty_name();
    let remote_address = remote_address();

    debug_log(flags, &format!("authorizing command {command} for user {user_name}"));

    match authorize_command(&user_name, &port, &remote_address, &command, &args) {
        AuthorizationDecision::Allow => 0,
        AuthorizationDecision::Unavailable => {
            if flags & LOCAL_AUTHORIZATION_FLAG == 0 {
                println!("{command} not authorized by TACACS+ with given arguments, not executing");
                return -2;
            }
            debug_log(flags, "TACACS+ unavailable; falling back to local authorization");
            0
        }
        AuthorizationDecision::Deny => {
            println!("{command} authorize failed by TACACS+ with given arguments, not executing");
            1
        }
    }
}
