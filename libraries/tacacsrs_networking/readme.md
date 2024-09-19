


## Consumer vs TACACS-RS Networking Perspective

**Clients Perspective**

A Client considers their sessions to be independent and completing at their own pace.

```
Session 123: Accounting Session
    Sequence Number: 1 -> AccountingRequest
    Sequence Number: 2 <- AccountingResponse
    *DONE*

Session 123465: Accounting Session
    Sequence Number: 1 -> AccountingRequest
    Sequence Number: 2 <- AccountingResponse
    *DONE*
```

**Networking Perspective**

The networking perspective is that there is many things in flight and they don't necessarily occur in order.

```
/// TCP Side
Session 123465.1 ->
Session 123.1 ->
Session 123465.2 <-
Session 123.2 <-
```


TCP Stack is broken down with two key components

1. Queued Tasks in a channel
2. Associated sessions registered on the connection

```
| Tac Client |                   | Tac Server |
     |                                |
  start session   ----------------->  |
     |                                |
  session         <----------------   |
     |                                |   \
 send request     -----(1)--------->  | loops until done
     |                                |   |
 process response <------(2)----------|   /
     |
  session complete
```

```
| Tac Client |                   | Tac Server |
     |                                |
  start session   ----------------->  |
     |                                |
  session         <----------------   |
     |                                |
 send Tac Packet -------------------->|
     |                   (3)          x - network issues/server gone
     |
 what does a session do?

```

```
(1)

| Connection Manager |      | TCP Socket |
       |                        |
   message queued  ----------> send
       |
    store session
       reference
```

```
(2)
| Connection Manager |      | TCP Socket |
       |                         |
   find session <----------     read
       |
   run callback
```


```
(3)
| Connection Manager |      | TCP Socket |
       |                         |
   find all sessions <-----   closed
       |
   for all sessions
      close
```


## Async Connections


### Non-Single Connection Mode

```
| tcp connection |
        |
    Run Authentication Transaction [several packets, single_connection_mode_client=true, single_connection_mode_server=false]
        |
        x [server closes connection (NetAAA will close connection), client should close connection]
```

```
| tcp connection |
        |
    Run Authentication Transaction [several packets, single_connection_mode_client=false, single_connection_mode_server=true]
        |    
        x [client should close connection, server closes connection (NetAAA will close connection)]
```

### Single Connection Mode Blocking

```
| tcp connection |
        |
    Run Authentication Transaction [several packets, single_connection_mode_client=true, single_connection_mode_server=true]
        |    
    Run Accounting Transaction [2 packets, single_connection_mode=true]
```

### Single Connection Mode Non-Blocking

```
| tcp connection |
        |
    Start Authentication Transaction [several packets, single_connection_mode_client=true, single_connection_mode_server=true]
     |  Start Accounting Transaction [2 packets, single_connection_mode=true]
     |              |
    Send         finished    Start Authorization Session [2 packets]
  password                                |
     |                                  send
     |                                    |
  finished                             finished
```

## Consumers

### Login (Authentication)

Roughly an authentication session looks like

- Create a session against a specific connection
  - generates channels,
  - a session id,
  - registers link between session id and channels
- Run the necessary steps, inspecting the output of the function calls
- Complete or drop the session

```rust
// This is not valid code, it's only to illustrate
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
    let password : Vec::<u8>() = get_password_from_user();
    let result = send_authentication_send_password(Session, password) -> NotOk
    if (result.is_ok == false)
    {
        fail?? or something else
    }

    is_password_ok result.password_is_ok();
}

send_authentication_finish(Session) -> AuthenticationComplete
```
