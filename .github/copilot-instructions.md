# Copilot Instructions

## Operating Model

This is a Rust workspace for TACACS+ (RFC 8907) authentication,
authorization, accounting, local agent IPC, SONiC integration, and compatibility
surfaces. Treat checked-in code, manifests, READMEs, and CI workflows as the
source of truth. These instructions are a map, not a reason to skip reading the
local module you are changing.

- Keep changes focused on the requested behavior and the owning crate.
- Prefer existing repo patterns over new abstractions.
- Preserve user changes in the worktree; never reset or revert unrelated files.
- Internal APIs may break when that improves correctness or maintainability, but
  propagate refactors through every affected crate.
- Rust edition is 2021 and the workspace MSRV is `1.88`.
- All workspace crates are internal and are not published to crates.io.

## Build, Test, and Lint

Before considering Rust changes complete, run the relevant local checks that
mirror CI. For narrow changes, run targeted package checks first, then broaden
when the touched behavior crosses crate or user-facing boundaries.

```bash
# Format (requires nightly because rustfmt.toml uses unstable options)
cargo +nightly fmt --all -- --check
cargo +nightly fmt --all

# Lint
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Docs (PowerShell: set $env:RUSTDOCFLAGS="-D warnings" first)
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

# Build and test
cargo build --workspace
cargo test --workspace --all-features

# Targeted loops
cargo test -p tacacsrs-messages
cargo test test_name
cargo clippy -p tacacsrs-networking --all-targets --all-features -- -D warnings
```

CI also exercises these jobs. Run them locally when relevant to the files you
changed or say explicitly why they could not be run:

- `cargo +nightly udeps --workspace --all-targets` for dependency changes.
- `cargo outdated --workspace --exit-code 1` when dependency freshness matters.
- `cargo audit` after dependency or lockfile changes.
- `cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info`
  for coverage-sensitive work.
- `buf breaking --against '.git#branch=main'` after protobuf schema changes.
- `cargo +nightly miri test --workspace --all-features` for unsafe, FFI, or
  aliasing-sensitive changes.
- `cargo +nightly fuzz run <target> -- -max_total_time=30` for protocol parser
  changes under `fuzz/`.
- `cargo deb --package tacon --no-build --dbgsym` when CLI packaging assets or
  Debian metadata change.

The full reusable pipeline also warms caches, checks formatting, clippy, docs,
protobuf compatibility, tests, coverage, audit, unused dependencies, outdated
dependencies, clippy nursery, Miri, fuzz smoke tests, build artifacts, SBOM, and
Debian packaging.

## Workspace Architecture

Current workspace members are listed in `Cargo.toml`. In the sketch below,
arrows point from a crate to the workspace crates it depends on:

```text
tacacsrs-flow-abstractions -> tacacsrs-messages
tacacsrs-networking -> tacacsrs-config, tacacsrs-flow-abstractions, tacacsrs-messages
tacacsrs-flows -> tacacsrs-flow-abstractions, tacacsrs-messages, tacacsrs-networking

tacacsrs-datastore -> tacacsrs-config
tacacsrs-sonic -> tacacsrs-config, tacacsrs-datastore

tacacsrs-agent -> tacacsrs-agent-client, tacacsrs-config, tacacsrs-flows,
                  tacacsrs-messages, tacacsrs-networking
tacacsrs-agent-ipc-emulator -> tacacsrs-agent-client
tacacsrs-libtac -> tacacsrs-agent-client
tacacsrs-bash-plugin -> tacacsrs-agent-client

tacon -> tacacsrs-agent-client, tacacsrs-config, tacacsrs-flows,
         tacacsrs-messages, tacacsrs-networking
tacacsrs-agentd -> tacacsrs-agent, tacacsrs-agent-client, tacacsrs-config,
                   tacacsrs-datastore, tacacsrs-networking, tacacsrs-sonic
tacacsrs-agent-ipc-emulatord -> tacacsrs-agent-client, tacacsrs-agent-ipc-emulator
session-wrapper -> tacacsrs-agent-client
```

### Libraries

- `tacacsrs-messages` contains protocol types: `Header`, `Packet`, accounting
  and authorization request/reply bodies, enumerations, `TacacsBodyTrait`, and
  TACACS+ MD5 XOR obfuscation. Obfuscation is not encryption.
- `tacacsrs-flow-abstractions` contains sans-I/O flow helpers and traits such as
  packet construction/parsing and `ClientSessionFlowIoTrait`.
- `tacacsrs-flows` contains high-level protocol flows such as
  `AccountingFlow`, implemented over session I/O abstractions.
- `tacacsrs-networking` owns transports, packet reader/writer plumbing,
  `TacacsConnection`, `DedicatedConnection`, session multiplexing, single-connect
  tracking, and config-driven connection establishment.
- `tacacsrs-agent-client` owns the protobuf/gRPC IPC contract, `IpcEndpoint`,
  domain request/response types, and `ServiceClient`. `ServiceClient` holds a
  reusable tonic channel; do not describe it as stateless.
- `tacacsrs-agent` coordinates central service behavior: upstream connection
  caching, ordered failover, preferred-server probes, per-server reconnect
  serialization, and IPC service handling.
- `tacacsrs-config` contains generated RFC 7951/YANG JSON model types,
  builders, validation options, server enumeration, and credential reference
  validation for `ietf-system-tacacs-plus`.
- `tacacsrs-datastore` defines the `ConfigDatastore` abstraction, static
  datastore, config change events, and change stream helpers.
- `tacacsrs-sonic` maps SONiC ConfigDB `TACPLUS` / `TACPLUS_SERVER` data into
  the YANG model and implements SONiC-backed config loading and watching.
- `tacacsrs-agent-ipc-emulator` provides JSON-driven local IPC emulation for
  integration and scenario testing.
- `tacacsrs-libtac` exposes a libtac-compatible C ABI backed by agent IPC.
- `tacacsrs-bash-plugin` exposes the SONiC Bash `execve` plugin surface and must
  keep FFI, runtime, configuration, logging, authorization, and session concerns
  separated.

### Executables

- `tacon` is the CLI client. It supports direct server mode and agent IPC mode,
  accounting, batch execution, and stubs for authentication and authorization.
  Its man page is generated from clap definitions in `executables/tacon/src/cli.rs`.
- `tacacsrs-agentd` is the local central agent daemon. It can load static JSON or
  SONiC ConfigDB-backed configuration and proxies IPC operations to upstream
  TACACS+ servers.
- `tacacsrs-agent-ipc-emulatord` runs the JSON-driven IPC emulator as a process.
- `session-wrapper` is a Linux x86_64 login session wrapper proof of concept.
  Use the session-wrapper WSL testing instructions when touching it on Windows.

## Versioning and Release

Committed manifests use `0.0.0-dev`. CI computes real versions from git tags and
injects them during builds through `.github/steps/compute-versions` and
`.github/steps/inject-versions`.

- Libraries receive semver versions and tags of the form `<crate>-vX.Y.Z`.
  The compute step can run `cargo-semver-checks` and cascades dependency-aware
  version bumps.
- Executables receive CalVer versions of the form `YYYY.MMDD.BUILD` for the
  configured `binary-name` (default: `tacon`) and tags of the form
  `<binary>-YYYY.MMDD.BUILD`.
- `release-plz.toml` is configured for git-only, non-publishing workflows. Do
  not assume crates are published to crates.io.

## Feature Flags and Platforms

- The `psk` feature enables TLS 1.3 pre-shared key support through OpenSSL in
  `tacacsrs-networking` and propagates through `tacon`, `tacacsrs-agent`, and
  `tacacsrs-agentd`.
- Default builds should remain pure Rust and avoid external OpenSSL requirements.
- Library features must be additive: enabling a feature may add capability, but
  must not remove or change unrelated public API behavior.
- Use `#[cfg(feature = "psk")]` and platform `cfg`s narrowly around code that
  truly needs them.
- Windows CI may build release artifacts with `psk`; Linux GNU release artifacts
  build the executable Debian packages with `psk` and package
  `tacacsrs-bash-plugin` without additional feature flags.
- `session-wrapper` is Linux x86_64-specific. On Windows, validate it through WSL
  with paths mapped under `/mnt/<drive>/...`.

## Module and Crate Boundaries

- Keep `lib.rs` files as crate facades: crate docs, module declarations,
  intentional re-exports, and tiny glue only.
- Split implementation by protocol concept, platform boundary, I/O boundary,
  ownership boundary, or public API area. Avoid vague dumping grounds like
  `utils`, `helpers`, `common`, or `misc` unless the crate already has a clear
  local convention.
- Prefer `pub(crate)` for cross-module seams and `pub` only for intentional crate
  API.
- Re-export items explicitly. Avoid `pub use foo::*` except for narrow,
  well-understood platform forwarding.
- When re-exporting local public items for docs, consider `#[doc(inline)]`.
- If a module can reasonably stand alone and avoid cyclic dependencies, prefer a
  small crate over an oversized mixed-purpose crate.

## Rust API Design

- Design APIs that are idiomatic for both humans and agents: clear types,
  discoverable constructors, useful docs, and directly testable seams.
- Use strong types with documented semantics instead of primitive strings or
  integers when the domain has meaning. Use the right standard type family early:
  `Path`/`PathBuf` for filesystem paths, `SocketAddr` for socket endpoints,
  `Duration` for time, and byte slices for borrowed binary data.
- Prefer borrowing (`&T`, `&str`, `&[u8]`, `&Path`) over cloning or taking
  ownership unless ownership transfer is required. For flexible function inputs,
  consider `impl AsRef<str>`, `impl AsRef<Path>`, or `impl AsRef<[u8]>` when it
  improves ergonomics without infecting stored types.
- Reuse existing abstractions: `Transport`, `BoxedTransport`,
  `ClientSessionFlowIoTrait`, `AccountingFlow`, `ConfigDatastore`,
  `ServiceError`, `IpcEndpoint`, and the mock transport/controller patterns.
- Essential behavior should be inherent on the owning type; traits should expose
  extension or abstraction seams, not hide core functionality.
- Use builders for complex construction with many optional combinations. Builder
  methods should be chainable, named after the value they set, and end in
  `build()`.
- Avoid exposing smart pointers, nested generics, or concrete async runtime
  machinery in public APIs unless that is the point of the API.

## Async and Concurrency

- Public futures and primary async entry points should be `Send` unless there is
  a documented reason they cannot be.
- Do not hold `Rc`, `RefCell`, non-Send guards, or long-held locks across
  `.await` points.
- Use `Arc`, `Mutex`, and `RwLock` when sharing is cheaper and clearer than
  recomputation. Keep lock scopes small.
- Do not hot-spin. Await readiness, sleep through configured intervals, or use
  channels and notifications.
- Long CPU-bound work in async code should use `spawn_blocking` or cooperative
  yield points so it does not starve the runtime.
- Preserve the service failover model: per-server reconnects are serialized, new
  sessions use the active server index, and the preferred-server probe only does
  extra work while failed over.

## Error Handling and Panics

- The workspace uses `anyhow::Result<T>` with `.context()` and `.with_context()`
  broadly because these crates are internal. Follow that pattern unless you are
  working on an API that already exposes a structured error type.
- `ServiceError` is the structured IPC error contract. Preserve its builder
  pattern and metadata such as server identity and retriable status.
- Return `Result` for external input, I/O, parsing, protocol, config, and IPC
  failures.
- Use panics only for programming bugs or impossible invariants. Panics are not a
  substitute for recoverable errors.
- Avoid `unwrap()` and `expect()` in production library code. If an invariant
  truly justifies one, make the message specific.
- Do not catch panics as control flow. Code should remain panic-safe even when a
  panic would normally abort the process.

## Documentation

- Public library modules should have `//!` module docs that explain what the
  module contains, when to use it, and the important invariants or side effects.
- Public items should have a concise first rustdoc sentence. Keep `# Errors`,
  `# Panics`, `# Safety`, and examples where applicable.
- Examples should be directly usable where practical and should prefer `?` over
  `unwrap()`.
- Document magic constants by naming them and explaining why the value matters.
- Do not add parameter tables to rustdoc; explain parameters in normal prose.
- For `tacon` man page text, edit clap doc comments and `#[arg(help = "...")]`
  attributes rather than generated man page output.

## Imports and Formatting

`rustfmt.toml` preserves import order and granularity. Keep imports grouped in
this order:

1. Standard library imports (`std::...`).
2. External crates (`tokio::...`, `anyhow::...`, `clap::...`).
3. Workspace crates (`tacacsrs_*::...`).
4. Local crate/module imports (`crate::...`, `super::...`).

Do not fight rustfmt. If rustfmt changes a signature, accept it unless it harms
readability and the config already supports the preferred shape.

## Testing

- Tests are usually inline `#[cfg(test)] mod tests`, with focused test support
  modules when reuse is needed.
- Prefer observable behavior tests over implementation-detail tests.
- Use `MockTransport` and `MockTransportCoordinator` for networking tests.
- Use `tacacsrs_agent::service::test_support` for agent failover and service
  tests.
- Use `ConfigDatastore` abstractions and static datastores instead of ad-hoc file
  or environment access when testing config consumers.
- Add regression tests with bug fixes. Broaden tests when behavior crosses crate,
  protocol, FFI, IPC, or user-facing CLI boundaries.
- Parser and serialization changes should consider fuzz targets.
- Unsafe or FFI changes should consider Miri and ABI-focused tests.

## Security, Secrets, and FFI

- The workspace denies unsafe code by default. Do not add `unsafe` unless it is
  needed for FFI, platform calls, or a carefully justified abstraction.
- Every unsafe block or local unsafe allowance must have nearby plain-language
  safety reasoning and tests that exercise the assumptions.
- Unsound safe APIs are never acceptable. If callers must uphold safety
  invariants, expose an `unsafe` function and document them under `# Safety`.
- FFI-facing crates must keep C ABI data portable: use `#[repr(C)]` where
  appropriate, avoid Rust-owned types across the boundary, make ownership and
  lifetimes explicit, and avoid sharing non-portable Rust state between dynamic
  libraries.
- Never log raw shared secrets, passwords, private keys, PSK values, auth tokens,
  or full command lines containing sensitive flags. Use existing redaction
  helpers or add tested redaction first.
- Treat CONFIG_DB and generated reports as operator-visible surfaces: store and
  display credential references, not raw secret material.
- Be careful with `Debug` for secret-bearing public types; custom redacted
  implementations need tests proving the secret is not rendered.

## Protocol and Config Rules

- Keep TACACS+ wire behavior aligned with RFC 8907 and the existing tests.
- The TACACS+ header is 12 bytes. Preserve sequence number, session ID,
  single-connect, and obfuscation semantics when changing packet code.
- Message serialization uses `to_bytes()` / `from_bytes()` and
  `TacacsBodyTrait`; prefer structured parsing over ad-hoc byte slicing unless
  the module already owns that byte-level parser.
- Configuration parsing uses RFC 7951/YANG JSON generated types. Entry points
  include `parse_yang_json`, `parse_yang_json_file`, validation options,
  builders, and server enumeration helpers.
- SONiC mapping should stay deterministic and reviewable. Preserve stable server
  ordering, explicit validation, and clear separation between ConfigDB shape and
  generated YANG model shape.
- TLS credential choices must remain unambiguous: TCP, certificate-based TLS,
  mTLS, and PSK settings should not be mixed into invalid intermediate config.

## Logging and Observability

- Follow the existing `log`/`env_logger` style unless a crate already uses a more
  structured logging API.
- Prefer stable, searchable log messages with enough context to diagnose server,
  session, config, and failover behavior.
- Avoid expensive string formatting or cloning in hot paths unless the context is
  needed.
- Redact before logging, not after.

## Dependency Hygiene

- Before adding a dependency, check whether the standard library or an existing
  workspace dependency is enough.
- Keep default builds working without non-Rust system prerequisites. Gate native
  dependencies behind opt-in features or platform `cfg`s when possible.
- Prefer libraries that are well-maintained, small in API surface, and compatible
  with the workspace MSRV.
- Update `Cargo.toml`, `Cargo.lock`, docs, SBOM/security expectations, and CI
  notes when dependency changes require it.

## Specialized Areas

- For `executables/session_wrapper/**` or `docs/session-wrapper-testing.md`, use
  `.github/instructions/session-wrapper-wsl-testing.instructions.md`.
- For `libraries/tacacsrs_sonic/**`, `executables/tacacsrs_agentd/**`, SONiC
  docs, or QEMU smoke work, use
  `.github/instructions/sonic-qemu-testing.instructions.md`.
- For protobuf IPC changes, keep `libraries/tacacsrs_agent_client/proto` as the
  source contract, update domain/protobuf conversions together, and run or note
  the `buf breaking` compatibility check.
