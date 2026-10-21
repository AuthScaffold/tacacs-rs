# tacacsrs-agent-ipc-emulator

This library and its companion `tacacsrs-agent-ipc-emulatord` executable are experimental.
Default Cargo builds and supported release artifacts exclude both packages. Full workspace builds and CI tests still include them.
Use `cargo test -p tacacsrs-agent-ipc-emulator` or `cargo run -p tacacsrs-agent-ipc-emulatord -- --help` for explicit selection.

OPA/Rego-driven emulator for the local `TacacsAgent` gRPC IPC API. It is
intended for integration tests that need to exercise `ServiceClient`, `tacon`,
`session-wrapper`, or other IPC clients without running `tacacsrs-agentd` and a
real TACACS+ server.

You write policies in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/),
and the emulator evaluates them with [regorus](https://github.com/microsoft/regorus).
The emulator compiles the Rego source and its fixed data document once at
startup. It supplies each captured TACACS+ request as Rego `input` at
evaluation time.

## Policy loading and compilation

`EmulatorPolicy` stores Rego source and fixed JSON data. It does not store a compiled engine.
`from_file` and `from_file_async` read source without compilation.
`from_files_async` also reads and decodes JSON data.
Read errors and invalid JSON syntax fail during loading.

`EmulatorPolicy::compile()` explicitly parses Rego source and loads the fixed data.
Invalid Rego syntax and unsupported data shapes fail at this boundary.
The data must be an object or `null`. An empty object or `null` supplies no fixed data.
Evaluation errors that depend on request input remain RPC errors.

All `IpcEmulator` constructors compile the completed policy once, before listener setup.
Invalid startup source or data cannot replace a Unix endpoint path or start a listener.
The standalone process follows the same boundary and prints no endpoint on startup error.
Callers that need a running emulator pass the completed `EmulatorPolicy` to a constructor without a separate compilation step.

The controller compiles each replacement before it swaps the active engine.
Invalid JSON, invalid Rego syntax, or unsupported data shapes retain the active policy and captured requests.
A successful replacement clears captured requests.

## Policy format

For every request the emulator evaluates `data.tacacs.emulator.decision` and
provides the request as `input`:

- `input.rpc` is `"Accounting"` or `"Authorization"`.
- Accounting requests expose `user`, `port`, `remote_address`, `command`, and
  `command_arguments`.
- Authorization requests additionally expose `privilege_level`, `args`, and
  convenience `command` / `command_arguments` fields derived from the TACACS+
  authorization args.

`decision` must evaluate to an object tagged with `type`:

- `type: "response"` — a successful IPC reply with `server`, `status`,
  `server_message`, `data`, and optional `args`. Accounting statuses are
  `Success`, `Error`, and `Follow`. Authorization statuses are `PassAdd`,
  `PassRepl`, `Fail`, `Error`, and `Follow`.
- `type: "error"` — a structured service error with `message`, `server`, and
  `retriable`.

Either object can also carry `delay_ms` to delay the reply.

When a policy does not define `decision`, the emulator returns a gRPC
`NotFound` for Accounting requests and a `Fail` response for Authorization
requests.

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

## Domain fidelity and fault simulation

Ordinary policy responses use shared protocol response types and IPC conversions.
Structured policy errors use shared failure facts. The emulator performs no upstream I/O, so their delivery state is `NotSent`.
The policy's `retriable` field selects a failure category. The shared domain type derives retry advice.

The emulator is not a substitute for production request validation.
Accounting and Authorization project raw protobuf fields into policy input without domain validation.
Raw generated clients can send invalid privileges or argument names for malformed-request scenarios.
`ServiceClient` uses domain request types. Production validation tests must exercise the production IPC adapter or shared conversions.
PAP requests use domain validation, then return a structured unsupported-operation error.

The raw gRPC handlers also preserve deliberate fault simulation.
Undefined Accounting decisions return `NotFound`. Malformed decision objects and unknown response statuses return `FailedPrecondition`.
Evaluation errors return `Internal`. These statuses remain RPC errors, not structured domain errors.

`ServiceClient` treats an in-flight status error as an unknown delivery outcome and never recommends automatic replay.
Controller shutdown stops the listener for transport-loss scenarios.
Arbitrary malformed reply envelopes require a separate raw gRPC test service, not a policy response.

## In-process tests

```rust,no_run
# async fn example() -> anyhow::Result<()> {
use tacacsrs_ipc::ServiceClient;
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

The process writes diagnostics to stderr in a compact timestamped format and
reserves stdout for the endpoint. By default the process logs emulator
lifecycle, incoming Accounting/Authorization requests, policy decisions,
configured delays, responses, undefined decisions, and controller operations.
Use `-vv` for full request-field JSON and controller inspection calls, `-vvv`
for trace-level emulator details, or `--quiet` when a test harness needs
endpoint-only output.
