# tacacsrs-agent-ipc-emulator

OPA/Rego-driven emulator for the local `TacacsAgent` gRPC IPC API. It is
intended for integration tests that need to exercise `ServiceClient`, `tacon`,
`session-wrapper`, or other IPC clients without running `tacacsrs-agentd` and a
real TACACS+ server.

Policies are written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/)
and evaluated with [regorus](https://github.com/microsoft/regorus). The Rego
source and its fixed data document are compiled once at startup; each captured
TACACS+ request is supplied as Rego `input` at evaluation time.

## Policy format

For every request the emulator evaluates `data.tacacs.emulator.decision`. The
request is provided as `input`:

- `input.rpc` is `"Accounting"` or `"Authorization"`.
- Accounting requests expose `user`, `port`, `remote_address`, `command`, and
  `command_arguments`.
- Authorization requests additionally expose `privilege_level`, `args`, and
  convenience `command` / `command_arguments` fields derived from the TACACS+
  authorization args.

`decision` must evaluate to an object tagged with `type`:

- `type: "response"` — a successful IPC reply with `server`, `status`,
  `server_message`, `data`, and optional `args`. Accounting statuses are
  `Success`, `Error`, and `Follow`; authorization statuses are `PassAdd`,
  `PassRepl`, `Fail`, `Error`, and `Follow`.
- `type: "error"` — a structured service error with `message`, `server`, and
  `retriable`.

Either object may also carry `delay_ms` to delay the reply.

When `decision` is left undefined the emulator returns a gRPC `NotFound` for
Accounting requests and a `Fail` response for Authorization requests.

```rego
package tacacs.emulator

import rego.v1

decision := {
"type": "response",
"server": "tacacs-primary:49",
"status": "Success",
"server_message": "",
"data": "",
"delay_ms": 50,
} if {
input.rpc == "Accounting"
input.user == "admin"
input.command == "show"
}
```

See [`examples/policy.rego`](examples/policy.rego) and its companion
[`examples/policy_data.json`](examples/policy_data.json) for a fuller policy
that drives an authorization denylist from fixed policy data.

## In-process tests

```rust,no_run
# async fn example() -> anyhow::Result<()> {
use tacacsrs_agent_client::ServiceClient;
use tacacsrs_agent_ipc_emulator::{EmulatorPolicy, IpcEmulator};

let policy = EmulatorPolicy::new(
    r#"
package tacacs.emulator
import rego.v1
decision := {"type": "response", "server": "primary", "status": "Success"} if {
    input.rpc == "Accounting"
}
"#,
);
let (emulator, endpoint) = IpcEmulator::from_policy(policy).await?;
let client = ServiceClient::connect(endpoint).await?;

// use client normally, then assert on captured requests
let _captured = emulator.captured_requests().await;
emulator.shutdown().await;
# Ok(())
# }
```

## Standalone process

Run the companion executable for out-of-process integration tests:

```bash
cargo run -p tacacsrs-agent-ipc-emulatord -- \
  --policy libraries/tacacsrs_agent_ipc_emulator/examples/policy.rego \
  --data libraries/tacacsrs_agent_ipc_emulator/examples/policy_data.json \
  --listen-endpoint 127.0.0.1:0
```

The process prints the bound endpoint to stdout. Use the mock-controller client
or protobuf service to load/replace the policy, reset captured state, fetch
captured requests, and trigger graceful shutdown.

Diagnostics are written to stderr in a compact timestamped format while stdout
stays reserved for the endpoint. By default the process logs emulator lifecycle,
incoming Accounting/Authorization requests, policy decisions, configured delays,
responses, undefined decisions, and controller operations. Use `-vv` for full
request-field JSON and controller inspection calls, `-vvv` for trace-level
emulator details, or `--quiet` when a test harness needs endpoint-only output.
