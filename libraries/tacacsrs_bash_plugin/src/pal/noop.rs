//! Mock platform implementation for targets without the SONiC bash plugin ABI.

use std::env;

use super::Platform;

const MOCK_USER_ENV: &str = "TACACSRS_BASH_PLUGIN_MOCK_USER";
const MOCK_TTY_ENV: &str = "TACACSRS_BASH_PLUGIN_MOCK_TTY";
const MOCK_TASK_ID_ENV: &str = "TACACSRS_BASH_PLUGIN_MOCK_TASK_ID";

pub(crate) static PLATFORM: MockPlatform = MockPlatform;

pub(crate) struct MockPlatform;

impl Platform for MockPlatform {
    fn current_user_name(&self) -> String {
        env::var(MOCK_USER_ENV).unwrap_or_else(|_| "UNKNOWN".to_owned())
    }

    fn is_remote_user(&self, _user: &str) -> bool {
        true
    }

    fn tty_name(&self) -> String {
        env::var(MOCK_TTY_ENV).unwrap_or_else(|_| "UNK".to_owned())
    }

    fn task_id(&self) -> u16 {
        env::var(MOCK_TASK_ID_ENV)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    }

    fn syslog_debug(&self, _message: &str) {}
}
