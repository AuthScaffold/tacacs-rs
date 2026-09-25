//! Sequential request and reply validation without transport state.

use anyhow::Context;

use crate::enumerations::{TacacsMajorVersion, TacacsMinorVersion, TacacsType};
use crate::header::Header;

/// Validates the identity and sequence of one client-side TACACS+ conversation.
#[derive(Debug)]
pub struct ConversationState {
    session_id: u32,
    identity: Option<(TacacsType, TacacsMinorVersion)>,
    next_request: Option<u8>,
    pending_reply: Option<u8>,
}

impl ConversationState {
    /// Starts a conversation whose first client request has sequence number one.
    #[must_use]
    pub const fn new(session_id: u32) -> Self {
        Self {
            session_id,
            identity: None,
            next_request: Some(1),
            pending_reply: None,
        }
    }

    /// Records a valid request before its executor submits it to a transport.
    ///
    /// # Errors
    ///
    /// Rejects a closed conversation, overlapping request, exhausted sequence,
    /// or changed session identity. Rejected requests do not change state.
    pub fn validate_request(&mut self, header: &Header) -> anyhow::Result<()> {
        if self.pending_reply.is_some() {
            anyhow::bail!("TACACS+ conversation already awaits a reply");
        }
        let expected = self
            .next_request
            .context("TACACS+ conversation is complete or exhausted")?;
        if header.session_id != self.session_id
            || header.major_version != TacacsMajorVersion::TacacsPlusMajor1
            || header.seq_no != expected
        {
            anyhow::bail!("unexpected TACACS+ conversation request header");
        }
        let identity = (header.tacacs_type, header.minor_version);
        if self.identity.is_some_and(|previous| previous != identity) {
            anyhow::bail!("TACACS+ conversation packet type or minor version changed");
        }
        let reply_sequence = expected
            .checked_add(1)
            .context("TACACS+ conversation sequence exhausted")?;
        self.identity = Some(identity);
        self.pending_reply = Some(reply_sequence);
        Ok(())
    }

    /// Accepts the matching reply and advances to the next client sequence.
    ///
    /// # Errors
    ///
    /// Rejects an unsolicited reply or a header that differs from the pending request.
    pub fn validate_response(&mut self, header: &Header) -> anyhow::Result<()> {
        let expected = self
            .pending_reply
            .context("TACACS+ conversation has no pending request")?;
        if header.session_id != self.session_id
            || header.major_version != TacacsMajorVersion::TacacsPlusMajor1
            || header.seq_no != expected
            || Some((header.tacacs_type, header.minor_version)) != self.identity
        {
            anyhow::bail!("unexpected TACACS+ conversation response header");
        }
        self.pending_reply = None;
        self.next_request = expected
            .checked_add(1)
            .filter(|sequence| *sequence < u8::MAX);
        Ok(())
    }

    /// Permanently closes the conversation.
    pub const fn complete(&mut self) {
        self.next_request = None;
        self.pending_reply = None;
    }
}

#[cfg(test)]
mod tests {
    use crate::enumerations::TacacsFlags;

    use super::*;

    fn header(sequence: u8) -> Header {
        Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAuthentication,
            seq_no: sequence,
            flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            session_id: 17,
            length: 0,
        }
    }

    #[test]
    fn request_and_reply_order_is_enforced() {
        let mut state = ConversationState::new(17);
        assert!(state.validate_response(&header(2)).is_err());
        state.validate_request(&header(1)).unwrap();
        assert!(state.validate_request(&header(1)).is_err());
        assert!(state.validate_response(&header(4)).is_err());
        state.validate_response(&header(2)).unwrap();
        assert!(state.validate_response(&header(2)).is_err());
        state.validate_request(&header(3)).unwrap();
        state.validate_response(&header(4)).unwrap();
    }

    #[test]
    fn identity_changes_do_not_advance_the_conversation() {
        let mut state = ConversationState::new(17);
        state.validate_request(&header(1)).unwrap();
        let mut wrong = header(2);
        wrong.session_id = 18;
        assert!(state.validate_response(&wrong).is_err());
        state.validate_response(&header(2)).unwrap();
        let mut wrong = header(3);
        wrong.minor_version = TacacsMinorVersion::TacacsPlusMinorVerOne;
        assert!(state.validate_request(&wrong).is_err());
        wrong = header(3);
        wrong.tacacs_type = TacacsType::TacPlusAccounting;
        assert!(state.validate_request(&wrong).is_err());
        state.validate_request(&header(3)).unwrap();
    }

    #[test]
    fn sequence_exhaustion_never_wraps() {
        let mut state = ConversationState::new(17);
        for sequence in (1..=253).step_by(2) {
            state.validate_request(&header(sequence)).unwrap();
            state.validate_response(&header(sequence + 1)).unwrap();
        }
        assert!(state.validate_request(&header(255)).is_err());
        assert!(state.validate_request(&header(1)).is_err());
    }

    #[test]
    fn completion_rejects_all_further_packets() {
        let mut state = ConversationState::new(17);
        state.validate_request(&header(1)).unwrap();
        state.complete();
        assert!(state.validate_response(&header(2)).is_err());
        assert!(state.validate_request(&header(1)).is_err());
    }
}
