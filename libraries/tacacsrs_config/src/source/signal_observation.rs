//! Signal-driven snapshot observation with burst coalescing and reconciliation.
//!
//! Store adapters such as SONiC and KubeSONiC subscribe to an asynchronous
//! invalidation stream before they read their baseline snapshot. [`SignalObservation`]
//! owns the background notification pump, coalesces bursts of notifications,
//! retains an in-flight snapshot read across `next()` cancellations, aborts
//! the read when the notification stream disconnects, and suppresses duplicate
//! snapshots unless the source is recovering from a rejected candidate.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use futures_core::Stream;
use tokio::sync::watch;
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::Instant;
use tokio_stream::StreamExt;

use crate::TacacsPlus;
use crate::tacacsrs::{LocalServices, RuntimePolicy};

use super::{ConfigChange, ConfigChangeEvent, ConfigDelta, ConfigObservation};

/// Boxed snapshot future retained across `next()` cancellations.
pub type SnapshotFuture = Pin<Box<dyn Future<Output = Result<ObservedSnapshot, ()>> + Send>>;

/// Timing policy for [`SignalObservation`].
#[derive(Debug, Clone, Copy)]
pub struct ObservationSchedule {
    /// Quiet period after a notification before reading a snapshot.
    pub debounce: Duration,
    /// Optional cap on total delay during a continuous burst of notifications.
    pub max_delay: Option<Duration>,
    /// Optional interval between full-read reconciliations without notifications.
    pub reconcile_interval: Option<Duration>,
    /// Optional delay before retrying after a rejected candidate.
    pub retry_interval: Option<Duration>,
}

impl ObservationSchedule {
    /// Creates a schedule that debounces notifications without periodic timers.
    #[must_use]
    pub const fn debounced(debounce: Duration) -> Self {
        Self {
            debounce,
            max_delay: None,
            reconcile_interval: None,
            retry_interval: None,
        }
    }
}

/// Validated candidate sections produced by one snapshot read.
#[derive(Debug, Clone)]
pub struct ObservedSnapshot {
    /// Validated canonical server and credential configuration.
    pub config: Arc<TacacsPlus>,
    /// Optional source-owned local listener configuration.
    pub local_services: Option<Arc<LocalServices>>,
    /// Optional source-owned runtime policy.
    pub runtime_policy: Option<Arc<RuntimePolicy>>,
}

impl ObservedSnapshot {
    /// Wraps a canonical configuration snapshot without extra owned sections.
    #[must_use]
    pub const fn config_only(config: Arc<TacacsPlus>) -> Self {
        Self {
            config,
            local_services: None,
            runtime_policy: None,
        }
    }
}

/// Cancellation-safe [`ConfigObservation`] driven by an invalidation stream.
pub struct SignalObservation {
    schedule: ObservationSchedule,
    disconnect_message: &'static str,
    signals: watch::Receiver<()>,
    pump: JoinHandle<()>,
    load: Box<dyn FnMut() -> SnapshotFuture + Send>,
    previous: Option<Arc<TacacsPlus>>,
    previous_local_services: Option<Arc<LocalServices>>,
    previous_runtime_policy: Option<Arc<RuntimePolicy>>,
    rejected: bool,
    read: Option<SnapshotFuture>,
    due: Option<Instant>,
    burst: Option<Instant>,
    quiet: Option<Instant>,
}

impl SignalObservation {
    /// Spawns a notification pump over `notifications` and schedules an immediate baseline read.
    #[must_use]
    pub fn spawn<S, F>(
        notifications: S,
        schedule: ObservationSchedule,
        disconnect_message: &'static str,
        load: F,
    ) -> Self
    where
        S: Stream<Item = ()> + Send + 'static,
        F: FnMut() -> SnapshotFuture + Send + 'static,
    {
        let (sender, mut signals) = watch::channel(());
        signals.borrow_and_update();
        let pump = tokio::spawn(async move {
            tokio::pin!(notifications);
            loop {
                tokio::select! {
                    biased;
                    () = sender.closed() => break,
                    item = notifications.next() => {
                        if item.is_none() {
                            break;
                        }
                        sender.send_replace(());
                    }
                }
            }
        });
        Self {
            schedule,
            disconnect_message,
            signals,
            pump,
            load: Box::new(load),
            previous: None,
            previous_local_services: None,
            previous_runtime_policy: None,
            rejected: false,
            read: None,
            due: Some(Instant::now()),
            burst: None,
            quiet: None,
        }
    }

    /// Replaces the pending snapshot read in white-box cancellation tests.
    #[doc(hidden)]
    pub fn replace_pending_read(&mut self, read: SnapshotFuture) {
        self.signals.borrow_and_update();
        self.due = None;
        self.burst = None;
        self.quiet = None;
        self.read = Some(read);
    }

    /// Reports whether an unseen notification arrived while a read is pending.
    ///
    /// # Errors
    /// Returns an error if the notification pump stopped.
    #[doc(hidden)]
    pub fn has_pending_signal(&self) -> anyhow::Result<bool> {
        self.signals.has_changed().context(self.disconnect_message)
    }

    /// Returns an abort handle for the owned notification pump.
    #[doc(hidden)]
    #[must_use]
    pub fn pump_abort_handle(&self) -> AbortHandle {
        self.pump.abort_handle()
    }

    /// Marks the latest emitted snapshot as rejected by a downstream consumer.
    ///
    /// The next successful read emits [`ConfigChangeEvent::Changed`] even when
    /// the snapshot is unchanged, and schedules
    /// [`ObservationSchedule::retry_interval`] when no read or earlier timer
    /// is armed.
    pub fn record_rejection(&mut self) {
        self.rejected = true;
        if self.read.is_none() {
            if let Some(interval) = self.schedule.retry_interval {
                if let Some(retry_at) = Instant::now().checked_add(interval) {
                    self.due = Some(match self.due {
                        Some(due) => due.min(retry_at),
                        None => retry_at,
                    });
                }
            }
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        match (self.quiet, self.due) {
            (Some(quiet), Some(due)) => Some(quiet.min(due)),
            (Some(quiet), None) => Some(quiet),
            (None, Some(due)) => Some(due),
            (None, None) => None,
        }
    }

    fn record_signal(&mut self) -> anyhow::Result<()> {
        let now = Instant::now();
        let start = *self.burst.get_or_insert(now);
        let debounced = now
            .checked_add(self.schedule.debounce)
            .context("observation debounce exceeds the clock range")?;
        self.quiet = Some(match self.schedule.max_delay {
            Some(max_delay) => debounced.min(
                start
                    .checked_add(max_delay)
                    .context("observation max delay exceeds the clock range")?,
            ),
            None => debounced,
        });
        Ok(())
    }
}

impl Drop for SignalObservation {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

#[async_trait]
impl ConfigObservation for SignalObservation {
    async fn next(&mut self) -> anyhow::Result<Option<ConfigChangeEvent>> {
        loop {
            self.signals
                .has_changed()
                .context(self.disconnect_message)?;
            if self.read.is_none() {
                if let Some(deadline) = self.next_deadline() {
                    if Instant::now() < deadline {
                        tokio::select! {
                            biased;
                            signal = self.signals.changed() => {
                                signal.context(self.disconnect_message)?;
                                self.record_signal()?;
                                continue;
                            }
                            () = tokio::time::sleep_until(deadline) => {}
                        }
                    }
                } else {
                    self.signals
                        .changed()
                        .await
                        .context(self.disconnect_message)?;
                    self.record_signal()?;
                    continue;
                }
                self.signals.borrow_and_update();
                self.burst = None;
                self.quiet = None;
                self.due = None;
                self.read = Some((self.load)());
            }

            let mut connection = self.signals.clone();
            let disconnected = async move { while connection.changed().await.is_ok() {} };
            let read = self.read.as_mut().context("snapshot read is missing")?;
            let result = tokio::select! {
                biased;
                () = disconnected => anyhow::bail!(self.disconnect_message),
                result = read => anyhow::Ok(result),
            }?;
            self.read = None;
            self.signals
                .has_changed()
                .context(self.disconnect_message)?;

            match result {
                Ok(snapshot) => {
                    self.due = self
                        .schedule
                        .reconcile_interval
                        .map(|interval| Instant::now() + interval);
                    let sections_changed = snapshot.local_services != self.previous_local_services
                        || snapshot.runtime_policy != self.previous_runtime_policy;
                    let forced = std::mem::take(&mut self.rejected) || sections_changed;
                    let is_baseline = self.previous.is_none();
                    let delta = ConfigDelta::diff(self.previous.as_deref(), &snapshot.config);
                    self.previous = Some(Arc::clone(&snapshot.config));
                    self.previous_local_services
                        .clone_from(&snapshot.local_services);
                    self.previous_runtime_policy
                        .clone_from(&snapshot.runtime_policy);
                    if is_baseline || forced || !delta.is_empty() {
                        return Ok(Some(ConfigChangeEvent::Changed(ConfigChange {
                            config: snapshot.config,
                            delta,
                            local_services: snapshot.local_services,
                            runtime_policy: snapshot.runtime_policy,
                        })));
                    }
                }
                Err(()) => {
                    self.due = self
                        .schedule
                        .retry_interval
                        .map(|interval| Instant::now() + interval);
                    self.rejected = true;
                    return Ok(Some(ConfigChangeEvent::CandidateRejected));
                }
            }
        }
    }

    fn record_rejection(&mut self) {
        Self::record_rejection(self);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;

    use crate::{TacacsPlusBuilder, TacacsPlusServerBuilder, TacacsPlusServerType};
    use super::*;

    fn server_config(port: u16) -> Arc<TacacsPlus> {
        Arc::new(
            TacacsPlusBuilder::new()
                .with_server_builder(
                    TacacsPlusServerBuilder::new(
                        "primary",
                        TacacsPlusServerType::all(),
                        "192.0.2.10",
                        port,
                    )
                    .with_shared_secret("secret"),
                )
                .build()
                .unwrap(),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn burst_caps_at_max_delay_and_recovers_after_rejection() {
        let (tx, rx) = mpsc::channel(8);
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let mut observation = SignalObservation::spawn(
            ReceiverStream::new(rx),
            ObservationSchedule {
                debounce: Duration::from_millis(500),
                max_delay: Some(Duration::from_millis(1200)),
                reconcile_interval: Some(Duration::from_secs(60)),
                retry_interval: Some(Duration::from_secs(5)),
            },
            "test stream disconnected",
            move || {
                let step = counter.fetch_add(1, Ordering::AcqRel);
                Box::pin(async move {
                    match step {
                        0 | 2 => Ok(ObservedSnapshot::config_only(server_config(49))),
                        1 => Err(()),
                        _ => Ok(ObservedSnapshot::config_only(server_config(50))),
                    }
                })
            },
        );

        assert!(matches!(observation.next().await.unwrap(), Some(ConfigChangeEvent::Changed(_))));

        // Three notifications spaced by 450 ms exceed max_delay (1200 ms) before quiet (500 ms).
        let notifier = tokio::spawn(async move {
            for _ in 0..3 {
                tx.send(()).await.unwrap();
                tokio::time::sleep(Duration::from_millis(450)).await;
            }
            tx.closed().await;
        });
        let start = Instant::now();
        assert!(matches!(
            observation.next().await.unwrap(),
            Some(ConfigChangeEvent::CandidateRejected)
        ));
        assert_eq!(start.elapsed(), Duration::from_millis(1200));

        // Recovery retry fires at retry_interval (5 s) and emits Changed even with an unchanged snapshot.
        let retry_start = Instant::now();
        let Some(ConfigChangeEvent::Changed(recovered)) = observation.next().await.unwrap() else {
            panic!("expected recovery change");
        };
        assert_eq!(retry_start.elapsed(), Duration::from_secs(5));
        assert!(recovered.delta.is_empty());
        notifier.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn downstream_rejection_re_emits_unchanged_snapshot_on_retry_and_reconcile() {
        let (_tx, rx) = mpsc::channel(1);
        let mut observation = SignalObservation::spawn(
            ReceiverStream::new(rx),
            ObservationSchedule {
                debounce: Duration::from_millis(250),
                max_delay: None,
                reconcile_interval: Some(Duration::from_secs(60)),
                retry_interval: Some(Duration::from_secs(5)),
            },
            "test stream disconnected",
            || Box::pin(async { Ok(ObservedSnapshot::config_only(server_config(49))) }),
        );

        assert!(matches!(observation.next().await.unwrap(), Some(ConfigChangeEvent::Changed(_))));

        // Without a rejection, reconcile_interval suppresses identical snapshots.
        assert!(tokio::time::timeout(Duration::from_secs(65), observation.next())
            .await
            .is_err());

        // Recording a downstream rejection arms retry_interval and forces re-emission.
        ConfigObservation::record_rejection(&mut observation);
        let retry_start = Instant::now();
        let Some(ConfigChangeEvent::Changed(recovered)) = observation.next().await.unwrap() else {
            panic!("expected recovery change after downstream rejection");
        };
        assert_eq!(retry_start.elapsed(), Duration::from_secs(5));
        assert!(recovered.delta.is_empty());

        // Subsequent unchanged reconciliations resume normal suppression.
        assert!(tokio::time::timeout(Duration::from_secs(65), observation.next())
            .await
            .is_err());

        // A schedule without retry_interval still re-emits on reconcile_interval.
        let (_tx2, rx2) = mpsc::channel(1);
        let mut reconcile_only = SignalObservation::spawn(
            ReceiverStream::new(rx2),
            ObservationSchedule {
                debounce: Duration::from_millis(250),
                max_delay: None,
                reconcile_interval: Some(Duration::from_secs(60)),
                retry_interval: None,
            },
            "test stream disconnected",
            || Box::pin(async { Ok(ObservedSnapshot::config_only(server_config(49))) }),
        );
        assert!(matches!(
            reconcile_only.next().await.unwrap(),
            Some(ConfigChangeEvent::Changed(_))
        ));
        ConfigObservation::record_rejection(&mut reconcile_only);
        let reconcile_start = Instant::now();
        let Some(ConfigChangeEvent::Changed(reconciled)) = reconcile_only.next().await.unwrap()
        else {
            panic!("expected reconcile recovery change");
        };
        assert_eq!(reconcile_start.elapsed(), Duration::from_secs(60));
        assert!(reconciled.delta.is_empty());
    }
}
