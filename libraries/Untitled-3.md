
# Non-Single Connection Mode

| tcp connection |
        |
    Run Authentication Transaction [several packets, single_connection_mode_client=true, single_connection_mode_server=false]
        |
        x [server closes connection (NetAAA will close connection), client should close connection]

| tcp connection |
        |
    Run Authentication Transaction [several packets, single_connection_mode_client=false, single_connection_mode_server=true]
        |    
        x [client should close connection, server closes connection (NetAAA will close connection)]

# Single Connection Mode Blocking

| tcp connection |
        |
    Run Authentication Transaction [several packets, single_connection_mode_client=true, single_connection_mode_server=true]
        |    
    Run Accounting Transaction [2 packets, single_connection_mode=true]


# Single Connection Mode Non-Blocking

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