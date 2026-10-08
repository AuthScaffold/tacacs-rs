//! Runs accounting failover against two local test peers without an agent.

use std::time::Duration;

use anyhow::{Context, bail, ensure};
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use tacacsrs_networking::{
    ConnectOptions, PacketReader, PacketReadResult, PreparedEndpoint, RequestDeadline,
    TransmissionState,
};
use tacacsrs_networking::retry::{
    Attempt, AttemptDisposition, FailoverAttempt, FailoverOutcome, FailoverPlan, run_with_failover,
};
use tacacsrs_networking::routed::{Endpoint, OperationKind, RoutedClient};
use tacacsrs_protocol::accounting::{reply::AccountingReply, request::AccountingRequest};
use tacacsrs_protocol::enumerations::{
    TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationMethod,
    TacacsAuthenticationService, TacacsAuthenticationType,
};
use tacacsrs_protocol::exchange::accounting::AccountingExchange;
use tacacsrs_protocol::packet::{Packet, PacketTrait};
use tacacsrs_protocol::traits::TacacsBodyTrait;

struct AccountingAttempt {
    client: RoutedClient,
    deadline: RequestDeadline,
}

#[async_trait]
impl FailoverAttempt for AccountingAttempt {
    type Value = (String, AccountingReply);
    type Error = anyhow::Error;

    async fn attempt(&mut self, _attempt_index: usize) -> Attempt<Self::Value, Self::Error> {
        let binding = match self
            .deadline
            .run(
                self.client
                    .bind(OperationKind::Accounting, Duration::from_secs(30)),
            )
            .await
            .map_err(anyhow::Error::from)
            .and_then(std::convert::identity)
        {
            Ok(binding) => binding,
            Err(error) => return Attempt::Aborted(error),
        };
        match binding
            .connection()
            .execute_classified_until(AccountingExchange::new(request()), self.deadline)
            .await
        {
            Ok(reply) if reply.status == TacacsAccountingStatus::TacPlusAcctStatusError => {
                let _reported = self.deadline.run(binding.note_failure()).await;
                Attempt::Rejected((binding.endpoint().name().to_owned(), reply))
            }
            Ok(reply) => {
                let _reported = self.deadline.run(binding.note_success()).await;
                Attempt::Accepted((binding.endpoint().name().to_owned(), reply))
            }
            Err(error) => {
                let disposition = match error.transmission_state() {
                    TransmissionState::NotSent => AttemptDisposition::NotSent,
                    TransmissionState::OutcomeUnknown => AttemptDisposition::OutcomeUnknown,
                };
                let _reported = self.deadline.run(binding.note_failure()).await;
                Attempt::Failed {
                    error: error.into_error(),
                    disposition,
                }
            }
        }
    }
}

fn request() -> AccountingRequest {
    AccountingRequest {
        flags: TacacsAccountingFlags::START,
        authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNotSet,
        priv_lvl: 1,
        authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
        authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
        user: "example".to_owned(),
        port: "example".to_owned(),
        rem_address: "127.0.0.1".to_owned(),
        args: vec!["task_id=routed-example".to_owned()],
    }
}

async fn peer(listener: TcpListener, status: TacacsAccountingStatus) -> anyhow::Result<()> {
    let (mut stream, _) = listener.accept().await?;
    let PacketReadResult::Success(packet) = PacketReader::new(None).read_packet(&mut stream).await
    else {
        bail!("The example peer did not receive a valid packet");
    };
    let _request = AccountingRequest::from_packet(&packet)?;
    let body = AccountingReply {
        status,
        server_msg: String::new(),
        data: String::new(),
    }
    .to_bytes()?;
    let mut header = packet.header().clone();
    header.seq_no = header.seq_no.wrapping_add(1);
    header.length = u32::try_from(body.len())?;
    stream
        .write_all(&Packet::new(header, body)?.to_bytes())
        .await?;
    Ok(())
}

async fn accounting(client: RoutedClient) -> anyhow::Result<()> {
    let plan = FailoverPlan::new(client.eligible_count(OperationKind::Accounting));
    let mut attempt = AccountingAttempt {
        client,
        deadline: RequestDeadline::after(Duration::from_secs(2))?,
    };
    match run_with_failover(plan, &mut attempt).await {
        FailoverOutcome::Accepted((name, reply)) => {
            ensure!(
                name == "backup"
                    && reply.status == TacacsAccountingStatus::TacPlusAcctStatusSuccess,
                "The example must complete on the backup endpoint"
            );
            println!(
                "Accounting accepted by {name}; no agent or configuration source was required."
            );
            Ok(())
        }
        FailoverOutcome::Failed(error) | FailoverOutcome::Aborted(error) => Err(error),
        _ => bail!("No endpoint accepted the example accounting request"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let primary = TcpListener::bind("127.0.0.1:0").await?;
        let backup = TcpListener::bind("127.0.0.1:0").await?;
        let endpoints = [("primary", &primary), ("backup", &backup)]
            .into_iter()
            .map(|(name, listener)| {
                Ok(Endpoint::new(
                    name,
                    PreparedEndpoint::tcp(
                        listener.local_addr()?.to_string(),
                        false,
                        None,
                        ConnectOptions::default(),
                    ),
                    [OperationKind::Accounting],
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        tokio::try_join!(
            peer(primary, TacacsAccountingStatus::TacPlusAcctStatusError),
            peer(backup, TacacsAccountingStatus::TacPlusAcctStatusSuccess),
            accounting(RoutedClient::new(endpoints)),
        )?;
        Ok(())
    })
    .await
    .context("The routed-client example exceeded its time limit")?
}
