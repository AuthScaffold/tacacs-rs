//! Bounded FIFO admission shared across routing generations.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use crate::RequestDeadline;

struct State {
    limit: usize,
    active: usize,
    next_ticket: u64,
    pending: VecDeque<u64>,
}

struct Pool {
    state: Mutex<State>,
    changed: Notify,
}

/// Shared active capacity with a bounded FIFO pending queue.
///
/// Clones share capacity. Keep this pool across catalog replacements. Reducing
/// the limit retains existing active requests and waiters. New waiters are
/// rejected when the pending count reaches the live limit. New admissions wait
/// until the active count is below that limit.
#[derive(Clone)]
pub struct AdmissionPool(Arc<Pool>);

impl AdmissionPool {
    /// Creates a pool. A zero limit rejects all new requests.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self(Arc::new(Pool {
            state: Mutex::new(State {
                limit,
                active: 0,
                next_ticket: 0,
                pending: VecDeque::new(),
            }),
            changed: Notify::new(),
        }))
    }

    /// Updates the active and pending limits without replacing the pool.
    pub fn update(&self, limit: usize) {
        self.0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .limit = limit;
        self.0.changed.notify_waiters();
    }

    /// Admits a request or waits in the bounded queue until its deadline.
    ///
    /// # Errors
    /// Returns [`AdmissionError::Full`] for overload or [`AdmissionError::Expired`]
    /// when the request budget is exhausted. Cancellation removes the waiter.
    pub async fn acquire(
        &self,
        deadline: RequestDeadline,
    ) -> Result<AdmissionPermit, AdmissionError> {
        self.reserve(deadline)?.wait().await
    }

    /// Reserves active or pending capacity before creating a request task.
    ///
    /// # Errors
    /// Returns overload or expiry without allocating an unbounded waiter.
    pub fn reserve(
        &self,
        deadline: RequestDeadline,
    ) -> Result<AdmissionReservation, AdmissionError> {
        deadline.check().map_err(|_| AdmissionError::Expired)?;
        let ticket = {
            let mut state = self
                .0
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            deadline.check().map_err(|_| AdmissionError::Expired)?;
            if state.pending.is_empty() && state.active < state.limit {
                state.active += 1;
                return Ok(AdmissionReservation {
                    deadline,
                    slot: ReservedSlot::Active(AdmissionPermit(Arc::clone(&self.0))),
                });
            }
            if state.pending.len() >= state.limit {
                return Err(AdmissionError::Full);
            }
            let ticket = state.next_ticket;
            state.next_ticket = state.next_ticket.wrapping_add(1);
            state.pending.push_back(ticket);
            ticket
        };
        let waiting = PendingRequest {
            pool: Arc::clone(&self.0),
            ticket,
        };
        Ok(AdmissionReservation {
            deadline,
            slot: ReservedSlot::Pending(waiting),
        })
    }
}

enum ReservedSlot {
    Active(AdmissionPermit),
    Pending(PendingRequest),
}

/// Owns bounded capacity even before its wait future is polled.
pub struct AdmissionReservation {
    deadline: RequestDeadline,
    slot: ReservedSlot,
}

impl AdmissionReservation {
    /// Waits for an active slot until the original reservation deadline.
    ///
    /// # Errors
    /// Returns expiry and releases the reservation when its budget is exhausted.
    pub async fn wait(self) -> Result<AdmissionPermit, AdmissionError> {
        let deadline = self.deadline;
        self.wait_until(deadline).await
    }

    /// Applies an earlier expiry without extending the reservation budget.
    ///
    /// # Errors
    /// Returns expiry if either deadline is exhausted before admission.
    pub async fn wait_until(
        self,
        deadline: RequestDeadline,
    ) -> Result<AdmissionPermit, AdmissionError> {
        let deadline = RequestDeadline::at(deadline.expires_at().min(self.deadline.expires_at()));
        deadline.check().map_err(|_| AdmissionError::Expired)?;
        let waiting = match self.slot {
            ReservedSlot::Active(permit) => return Ok(permit),
            ReservedSlot::Pending(waiting) => waiting,
        };
        loop {
            let changed = waiting.pool.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            deadline.check().map_err(|_| AdmissionError::Expired)?;
            {
                let mut state = waiting
                    .pool
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                deadline.check().map_err(|_| AdmissionError::Expired)?;
                if state.pending.front() == Some(&waiting.ticket) && state.active < state.limit {
                    state.pending.pop_front();
                    state.active += 1;
                    return Ok(AdmissionPermit(Arc::clone(&waiting.pool)));
                }
            }
            deadline
                .run(changed)
                .await
                .map_err(|_| AdmissionError::Expired)?;
        }
    }
}

struct PendingRequest {
    pool: Arc<Pool>,
    ticket: u64,
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        self.pool
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending
            .retain(|ticket| *ticket != self.ticket);
        self.pool.changed.notify_waiters();
    }
}

/// Owns one active slot and releases it synchronously on drop.
pub struct AdmissionPermit(Arc<Pool>);

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        self.0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active -= 1;
        self.0.changed.notify_waiters();
    }
}

/// Admission failed before any request transmission.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AdmissionError {
    /// Both active capacity and the pending queue are full.
    Full,
    /// The request budget expired before admission.
    Expired,
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Full => "The TACACS+ request admission queue is full",
            Self::Expired => "The TACACS+ request deadline expired before admission",
        })
    }
}

impl std::error::Error for AdmissionError {}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn deadline() -> RequestDeadline {
        RequestDeadline::after(Duration::from_secs(10)).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn reservations_bound_unpolled_tasks_and_release_on_drop() {
        let pool = AdmissionPool::new(1);
        let active = pool.reserve(deadline()).unwrap();
        let waiting = pool.reserve(deadline()).unwrap();
        assert!(matches!(pool.reserve(deadline()), Err(AdmissionError::Full)));
        drop(waiting);
        let waiting = pool.reserve(deadline()).unwrap();
        drop(active);
        waiting.wait().await.unwrap();
        assert_eq!(pool.0.state.lock().unwrap().active, 0);
        assert!(pool.0.state.lock().unwrap().pending.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn fifo_waiters_and_new_callers_share_one_pool() {
        let pool = AdmissionPool::new(1);
        let clone = pool.clone();
        let active = pool.acquire(deadline()).await.unwrap();
        let first = clone.acquire(deadline());
        tokio::pin!(first);
        assert!(futures::poll!(&mut first).is_pending());
        assert!(matches!(pool.acquire(deadline()).await, Err(AdmissionError::Full)));
        pool.update(2);
        let second = pool.acquire(deadline());
        tokio::pin!(second);
        assert!(
            futures::poll!(&mut second).is_pending(),
            "new arrivals cannot pass a queued request"
        );
        let first = first.await.unwrap();
        assert!(futures::poll!(&mut second).is_pending());
        drop(active);
        let second = second.await.unwrap();
        drop((first, second));
        assert_eq!(pool.0.state.lock().unwrap().active, 0);
        assert!(pool.0.state.lock().unwrap().pending.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_and_expired_waiters_release_queue_capacity() {
        let pool = AdmissionPool::new(1);
        let active = pool.acquire(deadline()).await.unwrap();
        {
            let cancelled = pool.acquire(deadline());
            tokio::pin!(cancelled);
            assert!(futures::poll!(&mut cancelled).is_pending());
        }
        let expires = RequestDeadline::after(Duration::from_secs(2)).unwrap();
        assert!(matches!(pool.acquire(expires).await, Err(AdmissionError::Expired)));
        assert!(pool.0.state.lock().unwrap().pending.is_empty());
        let waiting = pool.acquire(deadline());
        tokio::pin!(waiting);
        assert!(futures::poll!(&mut waiting).is_pending());
        drop(active);
        waiting.await.unwrap();
        assert_eq!(pool.0.state.lock().unwrap().active, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn reduced_limit_retains_waiters_without_admitting_excess_work() {
        let pool = AdmissionPool::new(2);
        let first = pool.acquire(deadline()).await.unwrap();
        let second = pool.acquire(deadline()).await.unwrap();
        let waiting = pool.acquire(deadline());
        tokio::pin!(waiting);
        assert!(futures::poll!(&mut waiting).is_pending());
        let next_waiter = pool.acquire(deadline());
        tokio::pin!(next_waiter);
        assert!(futures::poll!(&mut next_waiter).is_pending());
        pool.update(1);
        drop(first);
        assert!(futures::poll!(&mut waiting).is_pending());
        assert!(matches!(pool.acquire(deadline()).await, Err(AdmissionError::Full)));
        pool.update(0);
        drop(second);
        assert!(futures::poll!(&mut waiting).is_pending());
        pool.update(1);
        waiting.await.unwrap();
        next_waiter.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn an_expired_request_cannot_take_free_capacity() {
        let pool = AdmissionPool::new(1);
        let expires = RequestDeadline::after(Duration::ZERO).unwrap();
        assert!(matches!(pool.acquire(expires).await, Err(AdmissionError::Expired)));
        assert_eq!(pool.0.state.lock().unwrap().active, 0);
        assert!(pool.0.state.lock().unwrap().pending.is_empty());
    }
}
