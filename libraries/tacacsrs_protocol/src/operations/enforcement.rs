//! Authorization decisions for hosts that cannot apply response attributes.

use super::{AuthorizationArg, AuthorizationResponseStatus};

/// Result of interpreting authorization for an unchanged-command host adapter.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum UnchangedExecutionDecision {
    /// The adapter can execute the original command.
    Allow,
    /// The server did not grant authorization.
    Deny,
    /// The adapter cannot enforce the mandatory response arguments.
    UnsupportedMandatoryArguments,
    /// The server supplied malformed argument names.
    InvalidArguments,
}

impl AuthorizationResponseStatus {
    /// Interprets a reply for an adapter that cannot apply response attributes.
    ///
    /// Both pass statuses require valid arguments and no mandatory changes.
    /// This capability-specific decision never turns a denial into unavailability.
    #[must_use]
    pub fn unchanged_execution(self, args: &[AuthorizationArg]) -> UnchangedExecutionDecision {
        if !matches!(self, Self::PassAdd | Self::PassRepl) {
            return UnchangedExecutionDecision::Deny;
        }
        if args.iter().any(|argument| argument.validate().is_err()) {
            return UnchangedExecutionDecision::InvalidArguments;
        }
        if args.iter().any(|argument| argument.mandatory) {
            return UnchangedExecutionDecision::UnsupportedMandatoryArguments;
        }
        UnchangedExecutionDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_hosts_share_the_complete_status_and_argument_matrix() {
        for status in [
            AuthorizationResponseStatus::PassAdd,
            AuthorizationResponseStatus::PassRepl,
        ] {
            assert_eq!(status.unchanged_execution(&[]), UnchangedExecutionDecision::Allow);
            assert_eq!(
                status.unchanged_execution(&[AuthorizationArg::optional("protocol", "ssh")]),
                UnchangedExecutionDecision::Allow
            );
            assert_eq!(
                status.unchanged_execution(&[AuthorizationArg::mandatory("cmd", "show")]),
                UnchangedExecutionDecision::UnsupportedMandatoryArguments
            );
            assert_eq!(
                status.unchanged_execution(&[AuthorizationArg::optional("", "invalid")]),
                UnchangedExecutionDecision::InvalidArguments
            );
        }
        for status in [
            AuthorizationResponseStatus::Fail,
            AuthorizationResponseStatus::Error,
            AuthorizationResponseStatus::Follow,
        ] {
            assert_eq!(status.unchanged_execution(&[]), UnchangedExecutionDecision::Deny);
        }
    }
}
