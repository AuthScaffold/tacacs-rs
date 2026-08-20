# tacacsrs-agent-health

`tacacsrs-agent-health` probes the standard gRPC health service exposed by
`tacacsrs-agentd`. It supports Unix domain sockets and loopback TCP endpoints.

```bash
tacacsrs-agent-health \
    --endpoint /run/tacacs/tacacs.sock \
    --check readiness \
    --timeout-seconds 2
```

Exit status is `0` when the selected service is serving, `1` when it is not
serving, `2` for invalid invocation, and `3` for connection or timeout errors.