use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::Mutex;

#[derive(Debug)]
struct SessionIdAllocatorState {
    active_session_ids: HashSet<u32>,
}

/// Owns session ID allocation for a single multiplexed TACACS+ connection.
///
/// Generated session IDs are unique while active and remain random on each
/// reservation attempt.
///
/// A synchronous mutex is intentional. Allocation only accesses a small
/// in-memory `HashSet`. It does not perform I/O or await while it holds the
/// lock. This design keeps the critical section short during concurrent session
/// creation and does not add async locks to the allocator API.
#[derive(Debug)]
pub(crate) struct SessionIdAllocator {
    state: Mutex<SessionIdAllocatorState>,
}

/// RAII lease for a session ID from [`SessionIdAllocator`].
///
/// When the lease is dropped, the session ID is released back to the owning
/// allocator so it is no longer considered active.
#[derive(Debug)]
pub(crate) struct ReservedSessionId {
    session_id: u32,
    allocator: Arc<SessionIdAllocator>,
}

impl SessionIdAllocator {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(SessionIdAllocatorState {
                active_session_ids: HashSet::new(),
            }),
        })
    }

    pub(crate) fn reserve_generated(self: &Arc<Self>) -> ReservedSessionId {
        let mut state = self.state.lock();

        let session_id = loop {
            let candidate = random_nonzero_session_id();
            if state.active_session_ids.insert(candidate) {
                break candidate;
            }
        };

        ReservedSessionId {
            session_id,
            allocator: Arc::clone(self),
        }
    }

    fn release(&self, session_id: u32) {
        let mut state = self.state.lock();
        state.active_session_ids.remove(&session_id);
    }
}

impl ReservedSessionId {
    pub(crate) const fn get(&self) -> u32 {
        self.session_id
    }
}

impl Drop for ReservedSessionId {
    fn drop(&mut self) {
        self.allocator.release(self.session_id);
    }
}

pub(crate) fn random_nonzero_session_id() -> u32 {
    loop {
        let candidate = rand::random::<u32>();
        if candidate != 0 {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SessionIdAllocator;

    #[test]
    fn generated_ids_are_unique_while_reserved() {
        let allocator = SessionIdAllocator::new();

        let first = allocator.reserve_generated();
        let second = allocator.reserve_generated();

        assert_ne!(first.get(), 0);
        assert_ne!(second.get(), 0);
        assert_ne!(first.get(), second.get());
    }
}
