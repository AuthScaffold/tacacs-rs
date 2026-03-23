use std::collections::HashSet;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct SessionIdAllocatorState {
    active_session_ids: HashSet<u32>,
}

/// Owns session ID allocation for a single multiplexed TACACS+ connection.
///
/// Generated session IDs are unique while active and remain random on each
/// reservation attempt.
#[derive(Debug)]
pub(crate) struct SessionIdAllocator {
    state: Mutex<SessionIdAllocatorState>,
}

/// RAII lease for a session ID allocated by [`SessionIdAllocator`].
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
        let mut state = self.state.lock().expect("session id allocator poisoned");

        let session_id = loop {
            let candidate = random_nonzero_session_id();
            if !state.active_session_ids.contains(&candidate) {
                break candidate;
            }
        };

        state.active_session_ids.insert(session_id);

        ReservedSessionId {
            session_id,
            allocator: Arc::clone(self),
        }
    }

    pub(crate) fn reserve_specific(
        self: &Arc<Self>,
        session_id: u32,
    ) -> anyhow::Result<ReservedSessionId> {
        let mut state = self.state.lock().expect("session id allocator poisoned");

        anyhow::ensure!(
            !state.active_session_ids.contains(&session_id),
            "Session ID {session_id} is already in use"
        );

        state.active_session_ids.insert(session_id);

        Ok(ReservedSessionId {
            session_id,
            allocator: Arc::clone(self),
        })
    }

    fn release(&self, session_id: u32) {
        let mut state = self.state.lock().expect("session id allocator poisoned");
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

fn random_nonzero_session_id() -> u32 {
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

    #[test]
    fn specific_ids_can_be_reused_after_drop() {
        let allocator = SessionIdAllocator::new();

        {
            let reserved = allocator.reserve_specific(0xDEAD_BEEF).unwrap();
            assert_eq!(reserved.get(), 0xDEAD_BEEF);
        }

        let reserved_again = allocator.reserve_specific(0xDEAD_BEEF).unwrap();
        assert_eq!(reserved_again.get(), 0xDEAD_BEEF);
    }
}
