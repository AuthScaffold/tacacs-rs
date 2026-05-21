//! Platform abstraction layer for host facilities used by the bash plugin.

#[cfg_attr(all(target_os = "linux", target_env = "gnu"), path = "linux.rs")]
#[cfg_attr(not(all(target_os = "linux", target_env = "gnu")), path = "noop.rs")]
mod imp;

pub(crate) trait Platform {
    fn current_user_name(&self) -> String;

    fn is_remote_user(&self, user: &str) -> bool;

    fn tty_name(&self) -> String;

    fn task_id(&self) -> u16;

    fn syslog_debug(&self, message: &str);
}

pub(crate) fn active() -> &'static dyn Platform {
    &imp::PLATFORM
}
