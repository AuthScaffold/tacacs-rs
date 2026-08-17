//! Mock transport for testing [`MultiplexedConnection`] without a network.
//!
//! # Overview
//!
//! [`MockTransport`] is an in-memory implementation of [`Transport`]. It acts as
//! a TACACS+ server. Configure reply packets, pass the transport to
//! [`MultiplexedConnection::run_with_halves`], and then inspect the requests.
//!
//! # Architecture
//!
//! ```text
//!  ┌─────────────────────────────────────────────────────────────────┐
//!  │                        Test code                                │
//!  │                                                                 │
//!  │  1. Create MockTransport                                        │
//!  │  2. Obtain a MockTransportCoordinator via .coordinator()        │
//!  │  3. Use the coordinator to pre-configure replies                │
//!  │  4. Pass MockTransport to MultiplexedConnection                 │
//!  │  5. After the connection finishes, use the coordinator to       │
//!  │     inspect captured requests                                   │
//!  └─────────────────────────────────────────────────────────────────┘
//!
//!  When MultiplexedConnection splits the transport, the mock
//!  produces two halves and a background processor task:
//!
//!  ┌──────────────┐  raw bytes   ┌───────────────────┐  reply bytes ┌──────────────┐
//!  │ MockWriteHalf│─────────────>│ Write Processor   │─────────────>│ MockReadHalf │
//!  │ (AsyncWrite) │  (channel)   │ (spawned task)    │  (channel)   │ (AsyncRead)  │
//!  └──────────────┘              │                   │              └──────────────┘
//!                                │ • accumulates     │
//!                                │   bytes into      │
//!                                │   complete packets│
//!                                │ • records requests│
//!                                │   in MockState    │
//!                                │ • looks up replies│
//!                                │   and sends them  │
//!                                └───────────────────┘
//!                                        ▲
//!                                        │ shared MockState
//!                                        │ (async Mutex)
//!                                ┌───────┴────────────┐
//!                                │MockTransport       │
//!                                │  Coordinator       │
//!                                │ (add/inspect)      │
//!                                └────────────────────┘
//! ```
//!
//! # Key types
//!
//! | Type | Role |
//! |------|------|
//! | [`MockTransport`] | Tests create this transport and pass it to `MultiplexedConnection`. |
//! | [`MockTransportCoordinator`] | [`MockTransport::coordinator()`] returns this handle. Use it to add replies and read captured requests while the connection runs. |
//!
//! # Example (simplified)
//!
//! ```rust,no_run
//! # use std::sync::Arc;
//! # use tacacsrs_networking::transport::mock::MockTransport;
//! # async fn example() {
//! // 1. Create the transport and coordinator.
//! let transport = MockTransport::new();
//! let coordinator = transport.coordinator();
//!
//! // 2. Configure a reply through the coordinator.
//! // coordinator.add_reply(some_reply_packet).await.unwrap();
//!
//! // 3. Pass the transport to a MultiplexedConnection.
//! // let conn = Arc::new(MultiplexedConnection::new(Some(b"secret")));
//! // conn.run(transport).await.unwrap();
//!
//! // 4. Inspect the sent requests.
//! // let reqs = coordinator.get_requests_for_session(session_id).await.unwrap();
//! # }
//! ```
//!
//! [`Transport`]: crate::transport::abstractions::Transport
//! [`MultiplexedConnection`]: crate::runtime::MultiplexedConnection
//! [`MultiplexedConnection::run_with_halves`]: crate::runtime::MultiplexedConnection::run_with_halves
//! [`MockTransport::coordinator()`]: MockTransport::coordinator

#![allow(dead_code)]

mod channel_reader;
mod mock_read_half;
mod mock_state;
mod mock_transport;
mod mock_transport_coordinator;
mod mock_write_half;

pub(crate) use mock_transport::MockTransport;
