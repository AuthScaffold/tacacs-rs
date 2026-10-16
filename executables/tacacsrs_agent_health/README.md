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

## Operational Diagnostics

The `statistics` command reads the agent's current operational snapshot through
the same local socket. It does not connect to an upstream server or change
routing, counters, or health state. The command also works while readiness is
false, provided the local listener is available.

```bash
tacacsrs-agent-health statistics
tacacsrs-agent-health statistics --server primary
tacacsrs-agent-health statistics --format json --endpoint /run/tacacs/tacacs.sock
```

The server filter matches the configured name exactly. An unknown name returns
an error. Successful queries exit with `0`, invalid invocations with `2`, and
query failures or timeouts with `3`. Do not combine `statistics` with `--check`.

Text output groups each server's connection, packet, AAA, and TLS measurements.
JSON output is the RFC 7951 operational subtree under
`ietf-system-tacacs-plus:tacacs-plus`. It is not loadable desired configuration.
The `tacacsrs:diagnostics` augmentation describes new observations. Counter64 and
uint64 values use decimal JSON strings to preserve their full range.

### Measurement Semantics

- Connection opens count attempts. Successful connections have a separate
    counter and require completed transport setup and required TLS verification.
- `connected` and `connecting` are gauges. Connection state is not agent
    readiness or proof that a remote server will accept an operation.
- `expected-replies` counts requests awaiting validated completion, including
    queued sends. Completion, failure, or cancellation releases the gauge. It is
    not the difference between sent and received packet totals.
- AAA counters count per-server attempts and validated terminal responses.
    Authentication challenges are not terminal responses. Denials do not become
    transport failures or trigger a different retry policy. Consecutive failure
    counts use local completion order and reset on a successful terminal reply.
- Active connections have separate IDs and negotiated TLS metadata. At most
    32 active detail rows are retained per server; `connections-omitted` reports
    additional active transports. Aggregate connection gauges remain complete.
    `last-connection` is explicitly historical and can describe a closed connection.
- Configured single-connect policy is separate from the first-reply negotiated
    observation. The last connection's cipher does not describe every connection.
- Disconnect counters retain the first observed cause. Secondary cleanup errors
    do not replace that cause. Packet counts since reset restart when any
    connection in the endpoint's counter epoch closes non-gracefully.
- TLS categories use native numeric error and verification codes, not diagnostic
    string matching. Unclassified TLS failures increment `tls-other-errors`.
    Certificate subcategories overlap the aggregate certificate failure counter.
- Runtime generation identifies the captured server set. Counter epoch and
    discontinuity time identify counter lifetime. Unchanged endpoints retain their
    counters across reloads; replacements begin new epochs. Each server's sample
    is coherent, but servers are not sampled in one global atomic transaction.

### Limits And Unsupported Observations

Queries include at most 128 selected servers and 120 KiB of encoded JSON.
Oversized results fail explicitly; use the server filter. Metadata limits apply
before copying, and byte limits apply during serialization. Public provider
errors use fixed messages rather than arbitrary exception text.

The current runtime has no idle-disconnect policy or periodic watchdog timer.
Those capabilities and packet counters since an idle/watchdog timer event are
listed as unsupported. Existing optional accounting-watchdog preflights have
attempt, success, failure, and since-reset counters; diagnostics do not enable them.
FIPS mode is not inferred from cipher names and is
reported as unknown. Missing observations never appear as invented zero counters.
Cleartext connections explicitly report `tls-enabled: false`.

This report contains no passwords, shared secrets, PSK identities or values,
private keys, commands, or packet payloads. Server names and addresses are
operator metadata. Text output escapes control characters in returned strings.

## Cisco-Inspired Field Coverage

| Operational field | Source and coverage |
| --- | --- |
| Server name, address, port, source and routing context | Captured canonical server metadata |
| Socket opens, closes, aborts, failures and timeouts | Owned connection attempts and records |
| Packets sent and received | Complete codec I/O, not byte counts |
| Expected replies | Request-lifetime guards, including queued requests |
| Alive / connected / on hold | Explicit transport state and operation-specific routing circuit state |
| Single-connect, family, last attempt | Configured policy, first reply, observed peer address, setup timestamp |
| Authentication/authorization failure streaks | Validated terminal replies in local completion order |
| TLS version, cipher and successful handshakes | Native established streams before transport erasure |
| TLS errors, revoked certificates and untrusted issuers | Structured native verification results and error codes |
| Reset reasons and packets since reset | First observed connection close cause and endpoint event counters |
| Accounting-watchdog preflights | Existing configured preflight attempts, successes, failures, and since-reset count |
| Idle policy, periodic watchdog timer and FIPS mode | Explicitly unsupported or unknown; diagnostics create no traffic |

The corresponding invariants are tested in networking statistics, managed
transport and native certificate fixtures, agent snapshot tests, IPC bounds
tests, and health-client process tests.