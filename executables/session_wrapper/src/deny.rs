//! Denial UX helpers for user-facing stderr messages and command display formatting.

use std::fs::OpenOptions;
use std::io::Write;

use anyhow::{Context, Result};

/// Maximum number of characters shown for a command in user-facing deny messages.
const MAX_COMMAND_DISPLAY_CHARS: usize = 256;

/// Builds a user-facing command display string and truncates very long command lines.
pub(crate) fn command_display(exec_path: &str, exec_args: &[String]) -> String {
    let joined = if exec_args.is_empty() {
        exec_path.to_owned()
    } else if exec_args.first().is_some_and(|arg| arg == exec_path) {
        exec_args.join(" ")
    } else {
        format!("{exec_path} {}", exec_args.join(" "))
    };

    truncate_display(&joined, MAX_COMMAND_DISPLAY_CHARS)
}

/// Formats a user-facing deny message for TACACS+ authorization deny decisions.
pub(crate) fn authorization_denied_message(
    command: &str,
    user: &str,
    server: &str,
    server_message: Option<&str>,
) -> String {
    let mut message = format!(
        "tacacs: authorization denied for command '{command}' (user: {user}, server: {server})"
    );
    if let Some(server_message) = non_empty(server_message) {
        message.push_str(": ");
        message.push_str(server_message);
    }
    message
}

/// Formats a user-facing deny message for fail-closed IPC unavailability.
pub(crate) fn fail_closed_unavailable_message(command: &str) -> String {
    format!(
        "tacacs: authorization service unavailable, command '{command}' denied (fail-closed policy)"
    )
}

/// Writes a deny message to the target process's stderr (`/proc/[pid]/fd/2`).
pub(crate) fn write_process_stderr(pid: u32, message: &str) -> Result<()> {
    let stderr_path = format!("/proc/{pid}/fd/2");
    let mut stderr = OpenOptions::new()
        .write(true)
        .open(&stderr_path)
        .with_context(|| format!("failed to open {stderr_path} for writing deny message"))?;
    writeln!(stderr, "{message}")
        .with_context(|| format!("failed to write deny message to {stderr_path}"))?;
    Ok(())
}

fn truncate_display(input: &str, max_chars: usize) -> String {
    let total_chars = input.chars().count();
    if total_chars <= max_chars {
        return input.to_owned();
    }

    let take = max_chars.saturating_sub(1);
    let mut truncated: String = input.chars().take(take).collect();
    truncated.push('…');
    truncated
}

pub(crate) fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{authorization_denied_message, command_display, fail_closed_unavailable_message};

    #[test]
    fn command_display_truncates_very_long_lines() {
        let long = "x".repeat(400);
        let display = command_display("/bin/echo", &[long]);
        assert!(display.ends_with('…'));
        assert_eq!(display.chars().count(), 256);
    }

    #[test]
    fn authorization_message_includes_server_message_when_present() {
        let message = authorization_denied_message(
            "/bin/date",
            "alice",
            "198.51.100.10",
            Some("policy denied"),
        );
        assert!(message.contains("authorization denied for command '/bin/date'"));
        assert!(message.contains("user: alice, server: 198.51.100.10"));
        assert!(message.ends_with(": policy denied"));
    }

    #[test]
    fn fail_closed_message_matches_required_format() {
        let message = fail_closed_unavailable_message("/bin/rm -rf /");
        assert_eq!(
            message,
            "tacacs: authorization service unavailable, command '/bin/rm -rf /' denied (fail-closed policy)"
        );
    }
}
