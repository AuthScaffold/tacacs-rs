# Copilot Instructions

## Build, Test, and Lint

Before preparing a commit or considering Rust code changes complete, run the relevant local checks that mirror CI. Do not leave formatting changes, clippy warnings, rustdoc warnings, test failures, or build failures unresolved before commit.

```bash
# Format (requires nightly toolchain)
cargo +nightly fmt --all -- --check   # check only
cargo +nightly fmt --all              # apply fixes

# Lint
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Docs (warnings denied)
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

# Build
cargo build --workspace

# Test — full suite
cargo test --workspace --all-features

# Test — single test by name
cargo test test_name

# Test — single crate
cargo test -p tacacsrs-messages
```

If a relevant check cannot be run in the current environment, say so explicitly and note that CI requires the corresponding job to pass cleanly.

## Architecture

This is a Rust workspace implementing the TACACS+ protocol (RFC 8907) for authentication, authorization, and accounting (AAA). The workspace version is defined once in the root `Cargo.toml` and inherited by all members via `version.workspace = true`.

### Crate Dependency Graph

```
tacon (CLI)  ──────┬──► tacacsrs-agent-client (gRPC IPC client)
                   ├──► tacacsrs-messages (protocol types)
                   └──► tacacsrs-networking (transport/sessions)

tacacsrs-agentd (daemon) ──┬──► tacacsrs-agent (service logic)
                           └──► tacacsrs-agent-client

tacacsrs-agent ──┬──► tacacsrs-agent-client
                 ├──► tacacsrs-messages
                 └──► tacacsrs-networking

tacacsrs-networking ──► tacacsrs-messages
```

### Libraries

- **`tacacsrs-messages`** — Core protocol types: `Packet`, `Header` (12-byte TACACS+ header), `AccountingRequest`/`AccountingReply`, obfuscation via MD5 XOR pad. Serialization uses `to_bytes()`/`from_bytes()` methods and `TacacsBodyTrait`.
- **`tacacsrs-networking`** — Transport layer: `Transport` trait (TCP, TLS, PSK, mock), `TacacsConnection` (multiplexed sessions), `DedicatedConnection` (one-shot). TLS configured via `TlsConfigurationBuilder` (builder pattern, rustls + webpki-roots). Session multiplexing uses `SessionManager` to route packets by `session_id` over bidirectional `DuplexChannel`s.
- **`tacacsrs-agent-client`** — Stateless gRPC client (`ServiceClient`) for IPC with the agent daemon. Protobuf schema in `proto/tacacsrs_agent.proto`, auto-generated via tonic/prost in `build.rs`. Uses Unix domain sockets on Linux, TCP on Windows.
- **`tacacsrs-agent`** — Service coordinator with ordered upstream failover. `TacacsClientService` manages connections to TACACS+ servers, probes preferred server for recovery, and serializes reconnects per-server.

### Executables

- **`tacon`** — CLI client (clap). Two mutually exclusive modes: `--server-addr` (direct TACACS+ connection) or `--service-endpoint` (IPC to agent daemon). Subcommands: `accounting`, `authentication` (stub), `authorization` (stub), `batch` (JSON batch execution with parallel/sequential/load-test modes). Optional `--dedicated` flag uses `DedicatedConnection` for single-exchange mode.
- **`tacacsrs-agentd`** — Daemon that listens on IPC and proxies TACACS+ requests to upstream servers with connection pooling and failover.

### The `psk` Feature Flag

The `psk` feature enables TLS 1.3 Pre-Shared Key support via OpenSSL. Without it, the default build uses rustls (pure Rust) and requires no external dependencies. The feature propagates through the crate graph: `tacon` → `tacacsrs-networking` → OpenSSL.

## Conventions

### Design Principles

- **Follow existing patterns** — Before introducing new abstractions, check how the codebase already solves the same problem. New code should mirror established patterns (e.g. `DedicatedConnection` mirrors `TacacsConnection`: non-generic struct, generic method that accepts `impl Transport`).
- **Prefer non-generic structs with generic methods** — Keep structs concrete and push generics to the method level. Store type-erased (`Box<dyn Trait>`) halves when needed for ownership. Do not add type parameters to structs unless there is a compelling reason.
- **Reuse existing trait abstractions** — Use `Transport` for anything that can be split into read/write halves. Do not re-derive `AsyncRead`/`AsyncWrite` wrappers, enum-based manual trait delegation, or parallel trait hierarchies when the existing abstraction already covers the use case.
- **Type erasure only at the boundary** — Use `BoxedTransport` only where runtime polymorphism is genuinely needed (e.g. `establish_stream` choosing TCP vs TLS from CLI flags). Callers that know the concrete type at compile time should pass it directly as `impl Transport`.
- **Simple over clever** — Avoid unnecessary layers of indirection. If the only operation on a type is `split()`, don't implement `AsyncRead`/`AsyncWrite`/`Pin`/`Poll` on it. Minimise boilerplate.
- **Propagate refactors fully** — When changing an abstraction, update all code that uses it. Do not leave related code untouched because it "still compiles". If `DedicatedConnection` should use `Transport`, change it — don't keep the old raw-stream API alongside the new one.
- **Justify design decisions** — Before implementing, explain *why* the chosen approach is right and what alternatives were rejected. Don't just make things compile.

### Imports

`rustfmt.toml` sets `reorder_imports = false` and `imports_granularity = "Preserve"`. Import order is manually maintained:
1. Standard library (`std::`)
2. External crates (`tokio::`, `anyhow::`, `clap::`, etc.)
3. Workspace crates (`tacacsrs_*::`)

### Error Handling

Uses `anyhow::Result<T>` with `.context()` / `.with_context()` for error chains. One structured error type: `ServiceError` in `tacacsrs-agent-client` with builder pattern (`ServiceError::new("msg").with_server("addr").retriable(true)`).

### Design Patterns

- **Builder pattern**: `TlsConfigurationBuilder`, `PskConfigurationBuilder`, `ServiceError`
- **Trait abstractions**: `Transport` (unifies TCP/TLS/PSK/mock), `SessionManagementTrait`, `AccountingSessionTrait`, `PacketReaderTrait`/`PacketWriterTrait`
- **Type erasure**: `BoxedTransport` wraps transport behind `dyn` trait for runtime polymorphism
- **Shared state**: `Arc<T>` + `RwLock<T>` for concurrent session/connection management
- **Feature gating**: `#[cfg(feature = "psk")]` isolates OpenSSL dependency

### Rust Style

- Prefer borrowing (`&T`, `&str`) over cloning or taking ownership unless ownership transfer is required.
- Use iterators over index-based loops.
- Avoid `unwrap()`/`expect()` in library code — return `Result` instead.
- Avoid `unsafe` — the workspace forbids it via `unsafe_code = "forbid"`.
- Don't ignore compiler or clippy warnings — CI treats them as errors.
- Prefer `&str` over `String` for function parameters when ownership is not needed.

### Testing

Tests are inline (`#[cfg(test)]` modules), not in a separate `tests/` directory. Mock infrastructure lives in `tacacsrs_networking::transport::mock` (`MockTransport`, `ChannelReader`/`ChannelWriter`). Agent test helpers are in `tacacsrs_agent::service::test_support`.

### Man Page

The `tacon` man page is auto-generated from clap definitions via `clap_mangen` in `build.rs`. To change man page content, update doc comments and `#[arg(help = "...")]` attributes in `executables/tacon/src/cli.rs`.

## CI Alignment

- **Rustfmt**: `cargo +nightly fmt --all -- --check`
- **Clippy**: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- **Docs**: `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`
- **Tests**: `cargo test --workspace --all-features`
- **Build**: `cargo build --workspace --release --target <target>` for Linux GNU, Linux MUSL, and Windows MSVC
- **Coverage**: `cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info`
- **SBOM**: `cargo cyclonedx --format json --all --all-features` and `cargo cyclonedx --format xml --all --all-features`
- **Security audit**: `cargo generate-lockfile` then `cargo audit` via `rustsec/audit-check` (relevant when dependencies change)
- **Debian packaging**: builds `tacon`, generates man page, runs `cargo deb --package tacon --no-build --dbgsym` (relevant when CLI, packaging, or Debian assets change)