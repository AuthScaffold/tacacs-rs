//! Fixed TACACS+ request/reply execution and reply-header validation.
//!
//! These [`TacacsClient`] methods run one typed [`FixedExchange`] over a freshly
//! selected session. Networking assigns the session identifier and sequence
//! numbers, validates the complete reply header, and completes the session on
//! every success or error path.

use anyhow::Context;

use tacacsrs_protocol::enumerations::{TacacsFlags, TacacsMajorVersion};
use tacacsrs_protocol::exchange::FixedExchange;
use tacacsrs_protocol::header::Header;
use tacacsrs_protocol::packet::{Packet, PacketTrait};

use crate::exchange_error::FixedExchangeError;
use crate::session::{ClientSession, ExpectedResponseHeader};

use super::TacacsClient;

impl TacacsClient {
    /// Executes one fixed TACACS+ request/reply exchange.
    ///
    /// Networking assigns the session identifier and request sequence number,
    /// validates the complete reply header, and completes the underlying
    /// session on every success or error path.
    /// A configured client certificate bounds execution even without a caller deadline.
    ///
    /// # Errors
    ///
    /// Returns an error when session creation, request serialization, packet
    /// I/O, response validation, or reply parsing fails.
    pub async fn execute<Exchange>(&self, exchange: Exchange) -> anyhow::Result<Exchange::Reply>
    where
        Exchange: FixedExchange,
    {
        self.execute_classified(exchange)
            .await
            .map_err(FixedExchangeError::into_error)
    }

    /// Executes one fixed exchange and reports whether transmission started.
    ///
    /// # Errors
    ///
    /// Returns a classified error for session creation, request encoding,
    /// packet I/O, response validation, or reply parsing.
    pub async fn execute_classified<Exchange>(
        &self,
        exchange: Exchange,
    ) -> Result<Exchange::Reply, FixedExchangeError>
    where
        Exchange: FixedExchange,
    {
        if let Some(lifetime) = self.endpoint.prepared_credential_lifetime() {
            return self
                .execute_classified_until(exchange, lifetime.deadline)
                .await;
        }
        let expected =
            ExpectedResponseHeader::fixed(exchange.packet_type(), exchange.minor_version());
        let session = self
            .create_fixed_session(expected)
            .await
            .map_err(FixedExchangeError::not_sent)?;
        let result = execute_on_session(&session, exchange).await;
        session.complete().await;
        result
    }

    /// Executes a fixed exchange within one absolute request deadline.
    ///
    /// # Errors
    /// Returns a classified expiry before transmission or an unknown outcome
    /// after the exchange starts. The deadline includes session establishment.
    /// Client certificate expiry can shorten this deadline but cannot extend it.
    pub async fn execute_classified_until<Exchange>(
        &self,
        exchange: Exchange,
        deadline: crate::RequestDeadline,
    ) -> Result<Exchange::Reply, FixedExchangeError>
    where
        Exchange: FixedExchange,
    {
        let lifetime = self.endpoint.prepared_credential_lifetime();
        if let Some(lifetime) = lifetime {
            lifetime.check().map_err(FixedExchangeError::not_sent)?;
        }
        let deadline = lifetime.map_or(deadline, |lifetime| {
            crate::RequestDeadline::at(deadline.expires_at().min(lifetime.deadline.expires_at()))
        });
        let expected =
            ExpectedResponseHeader::fixed(exchange.packet_type(), exchange.minor_version());
        let session = deadline
            .run(self.create_fixed_session_until(expected, deadline))
            .await
            .map_err(FixedExchangeError::not_sent)?
            .map_err(FixedExchangeError::not_sent)?;
        deadline.check().map_err(FixedExchangeError::not_sent)?;
        let execution = deadline.run(execute_on_session(&session, exchange)).await;
        if execution.is_err() {
            session.record_timeout();
        }
        let result = execution
            .map_err(FixedExchangeError::outcome_unknown)
            .and_then(std::convert::identity);
        let _completed = deadline.run(session.complete()).await;
        if let Some(lifetime) = lifetime {
            lifetime
                .check()
                .map_err(FixedExchangeError::outcome_unknown)?;
        }
        result
    }
}

async fn execute_on_session<Exchange>(
    session: &ClientSession,
    exchange: Exchange,
) -> Result<Exchange::Reply, FixedExchangeError>
where
    Exchange: FixedExchange,
{
    const REQUEST_SEQUENCE_NUMBER: u8 = 1;
    const RESPONSE_SEQUENCE_NUMBER: u8 = 2;

    let session_id = session.session_id();
    let packet_type = exchange.packet_type();
    let minor_version = exchange.minor_version();
    let body = exchange
        .encode_request()
        .map_err(FixedExchangeError::not_sent)?;
    let length = u32::try_from(body.len())
        .context("fixed TACACS+ request body exceeds the protocol length field")
        .map_err(FixedExchangeError::not_sent)?;
    let request = Packet::new(
        Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version,
            tacacs_type: packet_type,
            seq_no: REQUEST_SEQUENCE_NUMBER,
            flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            session_id,
            length,
        },
        body,
    )
    .map_err(FixedExchangeError::not_sent)?;

    let _reply_wait = session.awaiting_reply(&request);
    let response = session
        .fixed_round_trip(request)
        .await
        .map_err(FixedExchangeError::outcome_unknown)?;
    let header = response.header();

    if header.session_id != session_id
        || header.seq_no != RESPONSE_SEQUENCE_NUMBER
        || header.tacacs_type != packet_type
        || header.major_version != TacacsMajorVersion::TacacsPlusMajor1
        || header.minor_version != minor_version
    {
        return Err(FixedExchangeError::outcome_unknown(anyhow::anyhow!(
            "unexpected fixed TACACS+ response header: session_id={:#x}, seq_no={}, type={}, version={:?}.{:?}; expected session_id={:#x}, seq_no={}, type={}, version={:?}.{:?}",
            header.session_id,
            header.seq_no,
            header.tacacs_type,
            header.major_version,
            header.minor_version,
            session_id,
            RESPONSE_SEQUENCE_NUMBER,
            packet_type,
            TacacsMajorVersion::TacacsPlusMajor1,
            minor_version,
        )));
    }

    let reply = exchange
        .decode_reply(response.body())
        .map_err(FixedExchangeError::outcome_unknown)?;
    session.record_terminal_reply(&response);
    Ok(reply)
}
