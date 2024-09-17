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
    pub fn new() -> Self
    {
        Self
        {
            session_lock: std::sync::Mutex::new(0),
            sessions: HashMap::new()
        }
    }

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

#[cfg(test)]
pub mod tests
{
    use super::*;
    use tacacsrs_messages::{accounting::reply::AccountingReply, enumerations::{TacacsAccountingStatus, TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType}, header::Header, packet::Packet, traits::TacacsBodyTrait};
    use tokio::sync::oneshot;

    #[test]
    fn test_create_session()
    {
        let mut session_manager = SessionManager {
            session_lock: std::sync::Mutex::new(0),
            sessions: HashMap::new()
        };

        let _ = session_manager.create_session(TacacsType::TacPlusAccounting).unwrap();
        assert!(true);
    }

    #[test]
    fn test_end_session()
    {
        let mut session_manager = SessionManager {
            session_lock: std::sync::Mutex::new(0),
            sessions: HashMap::new()
        };

        let session = session_manager.create_session(TacacsType::TacPlusAccounting).unwrap();
        assert_eq!(session_manager.sessions.len(), 1);

        session_manager.end_session(session).unwrap();
        assert_eq!(session_manager.sessions.len(), 0);
    }

    #[test]
    fn test_shutdown_all_sessions()
    {
        let mut session_manager = SessionManager {
            session_lock: std::sync::Mutex::new(0),
            sessions: HashMap::new()
        };

        let _session1 = session_manager.create_session(TacacsType::TacPlusAccounting).unwrap();
        let _session2 = session_manager.create_session(TacacsType::TacPlusAccounting).unwrap();
        assert_eq!(session_manager.sessions.len(), 2);

        session_manager.shutdown_all_sessions().unwrap();
        assert_eq!(session_manager.sessions.len(), 0);
    }

    #[test]
    fn test_drop_session_closes_queue_entry()
    {
        let mut session_manager = SessionManager {
            session_lock: std::sync::Mutex::new(0),
            sessions: HashMap::new()
        };

        let session = session_manager.create_session(TacacsType::TacPlusAccounting).unwrap();
        assert_eq!(session_manager.sessions.len(), 1);

        let (tx, mut rx) = oneshot::channel::<anyhow::Result<Packet>>();

        let body = AccountingReply {
            server_msg: "server_msg".to_string(),
            data: "data".to_string(),
            status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
        };

        let data = body.to_bytes();
        
        let header = Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAccounting,
            seq_no: 1,
            flags: TacacsFlags::empty(),
            session_id: 0,
            length: data.len() as u32,
        };
        
        let packet = tacacsrs_messages::packet::Packet::new(header, data).unwrap();
        
        session.queue_entry.lock().unwrap().replace(crate::sessions::QueueEntry {
            callback: tx,
            packet,
        });

        session_manager.end_session(session).unwrap();
        assert_eq!(session_manager.sessions.len(), 0);

        match rx.try_recv() {
            Ok(result) => return assert!(result.is_err()),
            Err(_) => assert!(false)
        }

        assert!(false)
    }
}