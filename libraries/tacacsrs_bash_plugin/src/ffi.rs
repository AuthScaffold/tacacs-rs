use std::os::raw::{c_char, c_int};

use crate::authorization::{AuthorizationDecision, authorize_command};
use crate::c_strings::{argv_strings, c_string};
use crate::config::{
    LOCAL_AUTHORIZATION_FLAG, TACACS_AUTHORIZATION_FLAG, current_flags, format_flags, reload_config,
};
use crate::logging::debug_log;
use crate::session::{get_user_name, is_remote_user, remote_address, tty_name};

#[no_mangle]
/// Initializes the Bash execve plugin.
///
/// # Safety
///
/// Bash must call this function through the plugin ABI.
pub unsafe extern "C" fn plugin_init() -> c_int {
    let flags = reload_config(true);
    debug_log(flags, &format!("tacacsrs bash plugin initialized; flags={}", format_flags(flags)));
    0
}

#[no_mangle]
/// Stops the Bash execve plugin.
///
/// # Safety
///
/// Bash must call this function through the plugin ABI after initialization.
pub unsafe extern "C" fn plugin_uninit() -> c_int {
    let flags = current_flags();
    debug_log(flags, "tacacsrs bash plugin uninitialized");
    0
}

#[no_mangle]
/// Authorizes a command before Bash calls `execve`.
///
/// # Safety
///
/// Bash must supply `user` and `cmd` as null pointers or pointers to valid,
/// NUL-terminated C strings. It must supply `argv` as a null pointer or a
/// readable, NUL-terminated pointer array. Each non-null array entry must point
/// to a valid, NUL-terminated C string. All pointers must remain valid for this
/// call.
pub unsafe extern "C" fn on_shell_execve(
    user: *mut c_char,
    shell_level: c_int,
    cmd: *mut c_char,
    argv: *mut *mut c_char,
) -> c_int {
    if shell_level > 2 {
        debug_log(current_flags(), &format!("not authorizing nested shell level {shell_level}"));
        return 0;
    }

    let flags = reload_config(false);
    if flags & TACACS_AUTHORIZATION_FLAG == 0 {
        debug_log(flags, "TACACS+ command authorization is disabled");
        return 0;
    }

    let user_name = get_user_name(user);
    if !is_remote_user(&user_name) {
        debug_log(flags, &format!("user {user_name} is local; allowing the command"));
        return 0;
    }

    let command = c_string(cmd);
    let args = argv_strings(argv);
    let port = tty_name();
    let remote_address = remote_address();

    debug_log(
        flags,
        &format!(
            "authorizing {command} for user {user_name} on tty {port} from {remote_address} with {} \
             arguments",
            args.len()
        ),
    );

    match authorize_command(flags, &user_name, &port, &remote_address, &command, &args) {
        AuthorizationDecision::Allow => {
            debug_log(flags, &format!("TACACS+ authorization allowed command {command}"));
            0
        }
        AuthorizationDecision::Unavailable => {
            if flags & LOCAL_AUTHORIZATION_FLAG == 0 {
                debug_log(
                    flags,
                    "TACACS+ is unavailable and local authorization is disabled; blocking the \
                     command",
                );
                println!(
                    "TACACS+ did not authorize {command} with the given arguments. The command will \
                     not run."
                );
                return -2;
            }
            debug_log(flags, "TACACS+ is unavailable; using local authorization");
            0
        }
        AuthorizationDecision::Deny => {
            debug_log(flags, &format!("TACACS+ authorization denied command {command}"));
            println!(
                "TACACS+ denied {command} with the given arguments. The command will not run."
            );
            1
        }
    }
}
