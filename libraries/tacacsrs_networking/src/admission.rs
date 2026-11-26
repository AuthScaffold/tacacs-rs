//! Bounded FIFO concurrency and token-bucket rate admission shared across routing generations.

use std::collections::VecDeque;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::time::Instant;

use crate::RequestDeadline;

struct State {
    limit: usize,
    closed: bool,
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
                closed: false,
            }),
            changed: Notify::new(),
        }))
    }

    /// Permanently rejects new reservations and wakes pending waiters.
    pub fn close(&self) {
        self.0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed = true;
        self.0.changed.notify_waiters();
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
                if state.closed {
                    return Err(AdmissionError::Closed);
                }
                state.active += 1;
                return Ok(AdmissionReservation {
                    deadline,
                    slot: ReservedSlot::Active(AdmissionPermit(Arc::clone(&self.0))),
                });
            }
            if state.closed {
                return Err(AdmissionError::Closed);
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
            ReservedSlot::Active(permit) => {
                if permit
                    .0
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .closed
                {
                    return Err(AdmissionError::Closed);
                }
                return Ok(permit);
            }
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
                    if state.closed {
                        return Err(AdmissionError::Closed);
                    }
                    state.pending.pop_front();
                    state.active += 1;
                    return Ok(AdmissionPermit(Arc::clone(&waiting.pool)));
                }
                if state.closed {
                    return Err(AdmissionError::Closed);
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
    /// The pool permanently stopped accepting work.
    Closed,
    /// Both active capacity and the pending queue are full.
    Full,
    /// The request budget expired before admission.
    Expired,
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Closed => "The TACACS+ admission pool is closed",
            Self::Full => "The TACACS+ request admission queue is full",
            Self::Expired => "The TACACS+ request deadline expired before admission",
        })
    }
}

impl std::error::Error for AdmissionError {}

const TOKEN_COST: u128 = 1_000_000_000;

struct BucketState {
    rate: u128,
    used: u128,
    last_update: Instant,
    closed: bool,
}

impl BucketState {
    const fn max_used(&self) -> u128 {
        self.rate * TOKEN_COST
    }

    fn drain(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_update).as_nanos();
        self.used = self.used.saturating_sub(elapsed.saturating_mul(self.rate));
        self.last_update = now;
    }

    fn try_take(&mut self, now: Instant) -> Result<(), Duration> {
        self.drain(now);
        let max_used = self.max_used();
        if self.used + TOKEN_COST <= max_used {
            self.used += TOKEN_COST;
            return Ok(());
        }
        let excess = (self.used + TOKEN_COST) - max_used;
        let wait_nanos = u64::try_from(excess.div_ceil(self.rate)).unwrap_or(u64::MAX);
        Err(Duration::from_nanos(wait_nanos))
    }
}

struct Limiter {
    queue: AsyncMutex<()>,
    state: Mutex<BucketState>,
    changed: Notify,
}

/// Shared FIFO token-bucket rate limiter with a one-second burst window.
///
/// Clones share token state and waiter order. Tasks that exceed the immediate
/// burst capacity wait in FIFO order until tokens drain or their
/// [`RequestDeadline`] expires. Dropping a waiting future releases its queue
/// position without consuming tokens.
#[derive(Clone)]
pub struct RateLimiter(Arc<Limiter>);

impl RateLimiter {
    /// Creates a rate limiter that permits `rate_per_second` operations per
    /// second with a one-second burst capacity.
    #[must_use]
    pub fn new(rate_per_second: NonZeroU32) -> Self {
        Self(Arc::new(Limiter {
            queue: AsyncMutex::new(()),
            state: Mutex::new(BucketState {
                rate: u128::from(rate_per_second.get()),
                used: 0,
                last_update: Instant::now(),
                closed: false,
            }),
            changed: Notify::new(),
        }))
    }

    /// Permanently rejects new acquisitions and wakes pending waiters.
    pub fn close(&self) {
        self.0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed = true;
        self.0.changed.notify_waiters();
    }

    /// Updates the steady rate and one-second burst ceiling in place.
    pub fn update(&self, rate_per_second: NonZeroU32) {
        {
            let mut state = self
                .0
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.drain(Instant::now());
            state.rate = u128::from(rate_per_second.get());
            let max_used = state.max_used();
            state.used = state.used.min(max_used);
        }
        self.0.changed.notify_waiters();
    }

    /// Acquires one token, pacing in FIFO order when the burst window is full.
    ///
    /// # Errors
    /// Returns [`AdmissionError::Closed`] when the limiter is closed or
    /// [`AdmissionError::Expired`] when the next token will not arrive before
    /// `deadline`.
    pub async fn acquire(&self, deadline: RequestDeadline) -> Result<(), AdmissionError> {
        deadline.check().map_err(|_| AdmissionError::Expired)?;
        let _turn = deadline
            .run(self.0.queue.lock())
            .await
            .map_err(|_| AdmissionError::Expired)?;
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let wait = {
                let mut state = self
                    .0
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.closed {
                    return Err(AdmissionError::Closed);
                }
                deadline.check().map_err(|_| AdmissionError::Expired)?;
                match state.try_take(Instant::now()) {
                    Ok(()) => return Ok(()),
                    Err(wait) => wait,
                }
            };
            let ready_at = Instant::now()
                .checked_add(wait)
                .ok_or(AdmissionError::Expired)?;
            if ready_at >= deadline.expires_at() {
                return Err(AdmissionError::Expired);
            }
            tokio::select! {
                () = tokio::time::sleep_until(ready_at) => {}
                () = &mut changed => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn deadline() -> RequestDeadline {
        RequestDeadline::after(Duration::from_secs(10)).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn close_releases_waiters_and_rejects_unpolled_reservations() {
        let pool = AdmissionPool::new(1);
        let active = pool.reserve(deadline()).unwrap();
        let queued = pool.acquire(deadline());
        tokio::pin!(queued);
        assert!(futures::poll!(&mut queued).is_pending());
        pool.close();
        pool.update(100);
        assert!(matches!(queued.await, Err(AdmissionError::Closed)));
        assert!(matches!(active.wait().await, Err(AdmissionError::Closed)));
        assert!(matches!(pool.reserve(deadline()), Err(AdmissionError::Closed)));
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

    #[tokio::test(start_paused = true)]
    async fn rate_limiter_allows_burst_then_paces_in_fifo_order() {
        let limiter = RateLimiter::new(NonZeroU32::new(4).unwrap());
        let start = Instant::now();
        for _ in 0..4 {
            limiter.acquire(deadline()).await.unwrap();
        }
        assert_eq!(start.elapsed(), Duration::ZERO);

        let fifth = {
            let limiter = limiter.clone();
            tokio::spawn(async move {
                limiter.acquire(deadline()).await.unwrap();
                Instant::now()
            })
        };
        tokio::task::yield_now().await;
        let sixth = {
            let limiter = limiter.clone();
            tokio::spawn(async move {
                limiter.acquire(deadline()).await.unwrap();
                Instant::now()
            })
        };

        let fifth_at = fifth.await.unwrap();
        let sixth_at = sixth.await.unwrap();
        assert_eq!(fifth_at.duration_since(start), Duration::from_millis(250));
        assert_eq!(sixth_at.duration_since(start), Duration::from_millis(500));
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limiter_rejects_immediately_when_token_exceeds_deadline_and_cancels_cleanly() {
        let limiter = RateLimiter::new(NonZeroU32::new(2).unwrap());
        limiter.acquire(deadline()).await.unwrap();
        limiter.acquire(deadline()).await.unwrap();

        let start = Instant::now();
        let short = RequestDeadline::after(Duration::from_millis(200)).unwrap();
        assert_eq!(limiter.acquire(short).await, Err(AdmissionError::Expired));
        assert_eq!(
            start.elapsed(),
            Duration::ZERO,
            "requests whose deadline precedes the next token must fail without blocking the queue"
        );

        {
            let cancelled = limiter.acquire(deadline());
            tokio::pin!(cancelled);
            assert!(futures::poll!(&mut cancelled).is_pending());
            tokio::time::advance(Duration::from_millis(250)).await;
        }

        // The cancelled waiter must not consume the half-refilled token.
        let waited_start = Instant::now();
        limiter.acquire(deadline()).await.unwrap();
        assert_eq!(waited_start.elapsed(), Duration::from_millis(250));
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limiter_live_update_and_close_wake_sleeping_waiters() {
        let limiter = RateLimiter::new(NonZeroU32::new(1).unwrap());
        limiter.acquire(deadline()).await.unwrap();

        let start = Instant::now();
        let waiter = {
            let limiter = limiter.clone();
            tokio::spawn(async move { limiter.acquire(deadline()).await })
        };
        tokio::task::yield_now().await;

        // Raising the rate from 1/s to 10/s wakes the sleeper and grants an available burst slot.
        limiter.update(NonZeroU32::new(10).unwrap());
        waiter.await.unwrap().unwrap();
        assert_eq!(start.elapsed(), Duration::ZERO);

        // Exhaust the new 10-token window (2 already used above + 8 more), then lower to 2/s.
        for _ in 0..8 {
            limiter.acquire(deadline()).await.unwrap();
        }
        limiter.update(NonZeroU32::new(2).unwrap());
        let paced_start = Instant::now();
        limiter.acquire(deadline()).await.unwrap();
        assert_eq!(paced_start.elapsed(), Duration::from_millis(500));

        // Closing wakes a sleeping waiter immediately.
        let closed_waiter = {
            let limiter = limiter.clone();
            tokio::spawn(async move { limiter.acquire(deadline()).await })
        };
        tokio::task::yield_now().await;
        limiter.close();
        assert_eq!(closed_waiter.await.unwrap(), Err(AdmissionError::Closed));
    }
}
