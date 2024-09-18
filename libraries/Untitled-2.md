LibPAM: Login (Authentication)

create_tacacs_connection_manager() -> ConnectionManager

create_authentication_session(ConnectionManager) -> Session
let result = send_authentication_start(Session) -> AuthenticationContinue
if (result.is_ok == false)
{
    fail?? or something else
}

bool is_password_ok = false;
while (!is_password_ok)
{
    let result = send_authentication_send_password(Session, password) -> NotOk
    if (result.is_ok == false)
    {
        fail?? or something else
    }

    is_password_ok result.password_is_ok();
}

send_authentication_finish(Session) -> AuthenticationComplete



----------------

create_authentication_session:
- Create mpsc
- generate session id
- generate hashmap between session id and mpsc
- return session



-----------------





let task = send_authentication_start() -> NetTask<AuthenticationContinue>                 [Session Sequence Number 1]
if (task.is_ok == false)
{
    fail?? or something else
}

bool is_password_ok = false;
while (!is_password_ok)
{
    let result = send_authentication_send_password(Session, password) -> NetTask<NotOk>          [Session Sequence Number 3 + 2*i]
    if (result.is_ok == false)
    {
        fail?? or something else
    }

    is_password_ok result.password_is_ok();
}

send_authentication_finish(Session) -> NetTask<AuthenticationComplete>














---------------







create_tacacs_connection_manager() -> ConnectionManager
create_authentication_session(ConnectionManager) -> Session [1 specific authentication session]

+----------------------+    +--------------------------+
| Connection           |    | Session                  |
+----------------------+    +--------------------------+
| sessions: Sessions[] |    | task : Optional<NetTask> |
+----------------------+    +--------------------------+

-----

LibAudit: Accounting

send_accounting_message(....) -> Ok


LibBash: Authorization

send_authorization_request() -> Allowed/NotAllowed




---------





TCP Stack
- Queued Tasks
- Associated Sessions

| Tac Client |                   | Tac Server |
     |                                |
  start session  -------------------  |
     |                                |   \
 send Tac Packet --------(1)--------->|   | loops until done
     |                                |   |
 process response <------(2)----------|   /
     |
  session complete

-----------------------------------------------

| Tac Client |                   | Tac Server |
     |                                |
  start session  -------------------  |
     |                                |
 send Tac Packet -------------------->|
     |                   (3)          x - network issues/server gone
     |
 what does a session do?

-------------------------------------------------



(1)

| Connection Manager |      | TCP Socket |
       |                        |
   message queued  ----------> send
       |
    store session
       reference

(2)
| Connection Manager |      | TCP Socket |
       |                         |
   find session <----------     read
       |
   run callback


(3)
| Connection Manager |      | TCP Socket |
       |                         |
   find all sessions <-----   closed
       |
   for all mpsc
      close

