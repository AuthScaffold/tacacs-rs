# tacacsrs-agent-ipc-emulator

JSON-driven emulator for the local `TacacsAgent` gRPC IPC API. It is intended
for integration tests that need to exercise `ServiceClient`, `tacon`,
`session-wrapper`, or other IPC clients without running `tacacsrs-agentd` and a
real TACACS+ server.

## Scenario format

A scenario contains ordered transaction rules. The first matching rule wins, so
files can model fallback and retry behavior.

```json
{
  "transactions": [
    {
      "rpc": "Accounting",
      "match": { "user": "admin", "command": "show" },
      "respond": {
        "type": "response",
        "server": "tacacs-primary:49",
        "status": "Success",
        "server_message": "",
        "data": ""
      },
      "delay_ms": 50
    }
  ]
}
```

`match` is partial: only keys present in the object are compared. `{}` is an
unconditional fallback. Accounting requests expose `user`, `port`,
`remote_address`, `command`, and `command_arguments`. Authorization requests
also expose `privilege_level`, `args`, and convenience `command` /
`command_arguments` fields derived from TACACS+ authorization args.

Responses use `type: "response"` for successful IPC replies and `type:
"error"` for structured service errors. Accounting statuses are `Success`,
`Error`, and `Follow`. Authorization statuses are `PassAdd`, `PassRepl`,
`Fail`, `Error`, and `Follow`.

## In-process tests

```rust,no_run
# async fn example() -> anyhow::Result<()> {
use tacacsrs_agent_client::ServiceClient;
use tacacsrs_agent_ipc_emulator::{EmulatorScenario, IpcEmulator};

let scenario = EmulatorScenario { transactions: Vec::new() };
let (emulator, endpoint) = IpcEmulator::from_scenario(scenario).await?;
let client = ServiceClient::connect(endpoint).await?;

// use client normally, then assert on captured requests or hit counts
let _captured = emulator.captured_requests().await;
emulator.shutdown().await;
# Ok(())
# }
```

## Standalone process

Run the companion executable for out-of-process integration tests:

```bash
cargo run -p tacacsrs-agent-ipc-emulatord -- \
  --scenario libraries/tacacsrs_agent_ipc_emulator/examples/accounting_authorization.json \
  --listen-endpoint 127.0.0.1:0
```

The process prints the bound endpoint to stdout. Use the mock-controller client
or protobuf service to load/replace scenarios, reset state, fetch captured
requests, fetch per-rule hit counts, and trigger graceful shutdown.

Diagnostics are written to stderr in a compact timestamped format while stdout
stays reserved for the endpoint. By default the process logs emulator lifecycle,
incoming Accounting/Authorization requests, matched rule indexes, configured
delays, responses, unmatched requests, and controller operations. Use `-vv` for
full request-field JSON and controller inspection calls, `-vvv` for trace-level
emulator details, or `--quiet` when a test harness needs endpoint-only output.
