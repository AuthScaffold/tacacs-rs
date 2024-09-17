use std::{collections::HashMap, sync::Arc};
use tacacsrs_messages::enumerations::TacacsType;
use crate::sessions::Session;

pub struct SessionManager
{
    session_lock : std::sync::Mutex<u8>,
    sessions: HashMap<u32, Arc<Session>>,
}

impl SessionManager
{
    pub fn get_session(&self, session_id: u32) -> Option<Arc<Session>>
    {
        match self.sessions.get(&session_id)
        {
            Some(session) => Some(session.clone()),
            None => None
        }
    }

    pub fn create_session(&mut self, tacacs_type : TacacsType) -> anyhow::Result<Arc<Session>>
    {
        let mut session_id = rand::random::<u32>();

        let session_entry = match self.session_lock.lock() {
            Ok(mut _lock) => {
                // Regenerate session id if it already exists
                while self.sessions.contains_key(&session_id)
                {
                    session_id = rand::random::<u32>();
                };

                let session_entry = Arc::new(Session::new(session_id, tacacs_type));
                self.sessions.insert(session_id, session_entry.clone());
                session_entry
            }

            Err(err) => return Err(anyhow::Error::msg(err.to_string()))
        };
        
        Ok(session_entry)
    }

    pub fn end_session(&mut self, session: Arc<Session>) -> anyhow::Result<()>
    {
        match self.session_lock.lock() {
            Ok(mut _lock) => {
                if self.sessions.contains_key(&session.session_id())
                {
                    self.sessions.remove(&session.session_id());
                    let _ = drop_session(&session);
                }
            }

            Err(err) => return Err(anyhow::Error::msg(err.to_string()))
        }

        Ok(())
    }

    pub fn shutdown_all_sessions(&mut self) -> anyhow::Result<()>
    {
        match self.session_lock.lock() {
            Ok(mut _lock) => {
                for (_, session) in self.sessions.iter()
                {
                    let _ = drop_session(session);
                }

                self.sessions.clear();
            }

            Err(err) => return Err(anyhow::Error::msg(err.to_string()))
        }

        Ok(())
    }
}

fn drop_session(session : &Arc<Session>) -> anyhow::Result<()> {
    match session.queue_entry.lock() {
        Ok(mut _lock) => {
            if let Some(queue_entry) = _lock.take() {
                let _ = queue_entry.callback.send(Err(anyhow::Error::msg("Session was dropped. Packet was not sent.")));
            }
        }

        Err(err) => return Err(anyhow::Error::msg(err.to_string()))
    }

    Ok(())
}