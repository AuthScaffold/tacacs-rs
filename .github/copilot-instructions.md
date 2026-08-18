# Copilot Instructions

## Operating Model

This is a Rust workspace for TACACS+ (RFC 8907) authentication,
authorization, accounting, local agent IPC, SONiC integration, and compatibility
surfaces. Treat checked-in code, manifests, READMEs, and CI workflows as the
source of truth. These instructions are a map, not a reason to skip reading the
local module you are changing.

- Keep changes focused on the requested behavior and the owning crate.
- Prefer existing repo patterns over new abstractions.
- Preserve user changes in the worktree. Never reset or revert unrelated files.
- Internal APIs can break when the change improves correctness or maintainability.
  When an API breaks, propagate the refactor through every affected crate.
- The Rust edition is 2021. The workspace MSRV is `1.88`.
- All workspace crates are internal. They are not published to crates.io.

## Writing Style

- Apply `.github/skills/simple-english/SKILL.md` in pragmatic mode to all prose
  that you create or revise.
- This rule applies to responses, documentation, code comments, user-facing
  messages, commit messages, pull request text, and release notes.
- Write technical facts and instructions in short, direct, unambiguous
  sentences. Use consistent terms and remove filler.
- Do not rewrite source code, identifiers, commands, file paths, protocol
  values, or quoted errors and logs. This writing style does not apply to them.
- If the user requests STE or ASD-STE100 compliance, use strict ASD-STE100
  mode.
- Do not claim full ASD-STE100 compliance without the official Issue 9
  dictionary.

## Build, Test, and Lint

Before considering Rust changes complete, run the relevant local checks that
mirror CI. For narrow changes, run targeted package checks first. When the touched
behavior crosses crate or user-facing boundaries, broaden the checks.

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

CI also exercises these jobs. When a job is relevant to your changes, run it
locally. If you cannot run a job, explain why:

- `cargo +nightly udeps --workspace --all-targets` for dependency changes.
- When dependency freshness matters, run `cargo outdated --workspace --exit-code 1`.
- `cargo audit` after dependency or lockfile changes.
- `cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info`
  for coverage-sensitive work.
- `buf breaking --against '.git#branch=main'` after protobuf schema changes.
- `cargo +nightly miri test --workspace --all-features` for unsafe, FFI, or
  aliasing-sensitive changes.
- `cargo +nightly fuzz run <target> -- -max_total_time=30` for protocol parser
  changes under `fuzz/`.

The full reusable pipeline also runs these additional checks:

- Cache warming
- Format check
- Clippy
- Docs build
- Protobuf compatibility check
- Tests
- Coverage
- Dependency audit
- Unused dependency check
- Outdated dependency check
- Clippy nursery
- Miri
- Fuzz smoke tests
- Build artifacts
- SBOM generation
- Linux release archives

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
  tracking, and configuration-driven connection establishment.
- `tacacsrs-agent-client` owns the protobuf/gRPC IPC contract, `IpcEndpoint`,
  domain request/response types, and `ServiceClient`. `ServiceClient` holds a
  reusable tonic channel. Do not describe it as stateless.
- `tacacsrs-agent` coordinates central service behavior: upstream connection
  caching, ordered failover, preferred-server probes, per-server reconnect
  serialization, and IPC service handling.
- `tacacsrs-config` contains generated RFC 7951/YANG JSON model types,
  builders, validation options, server enumeration, and credential reference
  validation for `ietf-system-tacacs-plus`.
- `tacacsrs-datastore` defines the `ConfigDatastore` abstraction, static
  datastore, configuration change events, and change stream helpers.
- `tacacsrs-sonic` maps SONiC ConfigDB `TACPLUS` / `TACPLUS_SERVER` data into
  the YANG model and implements SONiC-backed configuration loading and watching.
- `tacacsrs-agent-ipc-emulator` provides OPA/Rego-driven local IPC emulation for
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
- `tacacsrs-agent-ipc-emulatord` runs the OPA/Rego-driven IPC emulator as a process.
- `session-wrapper` is a Linux x86_64 login session wrapper proof of concept.
  When you change it on Windows, use the session-wrapper WSL testing instructions.

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

## Feature Flags and Platforms

- Default builds use dynamically linked OpenSSL for certificate-based TLS and
  TLS 1.3 pre-shared key support.
- Library features must be additive: enabling a feature can add capability, but
  must not remove or change unrelated public API behavior.
- The complete workspace supports Linux GNU. Product crates do not provide
  unsupported-platform fallback implementations.
- Windows supports `tacon` direct mode and its dependency crates only.
- Use the development container for complete workspace development on Windows.
- Windows CI packages OpenSSL runtime DLLs with release artifacts. Linux GNU
  release artifacts dynamically link against the system OpenSSL packages.
- `session-wrapper` is Linux x86_64-specific. On Windows, validate it through WSL
  with paths mapped under `/mnt/<drive>/...`.

## Module and Crate Boundaries

- Keep `lib.rs` files as crate facades: crate docs, module declarations,
  intentional re-exports, and tiny glue only.
- Split implementation by protocol concept, platform boundary, I/O boundary,
  ownership boundary, or public API area. Unless the crate already has a clear
  local convention, avoid vague dumping grounds like `utils`, `helpers`,
  `common`, or `misc`.
- Prefer `pub(crate)` for cross-module seams and `pub` only for intentional crate
  API.
- Re-export items explicitly. Avoid `pub use foo::*` except for narrow,
  well-understood platform forwarding.
- When you re-export local public items for docs, consider `#[doc(inline)]`.
- If a module can reasonably stand alone and avoid cyclic dependencies, prefer a
  small crate over an oversized mixed-purpose crate.

## Rust API Design

- Design APIs that are idiomatic for both humans and agents: clear types,
  discoverable constructors, useful docs, and directly testable seams.
- When the domain has meaning, use strong types with documented semantics
  instead of primitive strings or integers. Use the right standard type family
  early: `Path`/`PathBuf` for filesystem paths, `SocketAddr` for socket
  endpoints, `Duration` for time, and byte slices for borrowed binary data.
- Unless ownership transfer is required, prefer borrowing (`&T`, `&str`,
  `&[u8]`, `&Path`) over cloning or taking ownership. When it improves
  ergonomics without infecting stored types, consider `impl AsRef<str>`,
  `impl AsRef<Path>`, or `impl AsRef<[u8]>` for flexible function inputs.
- Reuse existing abstractions: `Transport`, `BoxedTransport`,
  `ClientSessionFlowIoTrait`, `AccountingFlow`, `ConfigDatastore`,
  `ServiceError`, `IpcEndpoint`, and the mock transport/controller patterns.
- Prefer essential behavior on the owning type. Use traits for extension or
  abstraction seams, not to hide core functionality.
- Use builders for complex construction with many optional combinations. Prefer
  chainable methods that use the value name and end in `build()`.
- Unless that is the point of the API, avoid exposing smart pointers, nested
  generics, or concrete async runtime machinery in public APIs.

## Async and Concurrency

- Public futures and primary async entry points must be `Send` unless a
  documented reason prevents it.
- Do not hold `Rc`, `RefCell`, non-Send guards, or long-held locks across
  `.await` points.
- When sharing is cheaper and clearer than recomputation, use `Arc`, `Mutex`,
  and `RwLock`. Keep lock scopes small.
- Do not hot-spin. Await readiness, sleep through configured intervals, or use
  channels and notifications.
- Long CPU-bound work in async code must use `spawn_blocking` or cooperative
  yield points so it does not starve the runtime.
- Preserve the service failover model: per-server reconnects are serialized, new
  sessions use the active server index, and the preferred-server probe only does
  extra work while failed over.

## Error Handling and Panics

- The workspace uses `anyhow::Result<T>` with `.context()` and `.with_context()`
  broadly because these crates are internal. Unless you work on an API that
  already exposes a structured error type, follow that pattern.
- `ServiceError` is the structured IPC error contract. Preserve its builder
  pattern and metadata such as server identity and retriable status.
- Return `Result` for external input, I/O, parsing, protocol, configuration, and
  IPC failures.
- Use panics only for programming bugs or impossible invariants. Panics are not a
  substitute for recoverable errors.
- Avoid `unwrap()` and `expect()` in production library code. If an invariant
  truly justifies one, make the message specific.
- Do not catch panics as control flow. Code must remain panic-safe even when a
  panic normally aborts the process.

## Documentation

- Prefer `//!` module docs for public library modules. Explain the module
  contents, its uses, and its important invariants or side effects.
- Prefer a concise first rustdoc sentence for public items. Keep `# Errors`,
  `# Panics`, `# Safety`, and examples where applicable.
- Prefer directly usable examples where practical. In examples, prefer `?` over
  `unwrap()`.
- Document magic constants by naming them and explaining why the value matters.
- Do not add parameter tables to rustdoc. Explain parameters in normal prose.
- For `tacon` man page text, edit clap doc comments and `#[arg(help = "...")]`
  attributes rather than generated man page output.

## Imports and Formatting

`rustfmt.toml` preserves import order and granularity. Keep imports grouped in
this order:

1. Standard library imports (`std::...`).
2. External crates (`tokio::...`, `anyhow::...`, `clap::...`).
3. Workspace crates (`tacacsrs_*::...`).
4. Local crate/module imports (`crate::...`, `super::...`).

Do not fight rustfmt. If rustfmt changes a signature, accept the change. Reject
the change only when it harms readability and the configuration already
supports the preferred shape.

## Testing

- Tests are usually inline `#[cfg(test)] mod tests`, with focused test support
  modules when reuse is needed.
- Prefer observable behavior tests over implementation-detail tests.
- Use `MockTransport` and `MockTransportCoordinator` for networking tests.
- Use `tacacsrs_agent::service::test_support` for agent failover and service
  tests.
- When testing configuration consumers, use `ConfigDatastore` abstractions and static
  datastores instead of ad-hoc file or environment access.
- Add regression tests with bug fixes. When behavior crosses crate, protocol,
  FFI, IPC, or user-facing CLI boundaries, broaden tests.
- Consider fuzz targets for parser and serialization changes.
- Consider Miri and ABI-focused tests for unsafe or FFI changes.

## Security, Secrets, and FFI

- The workspace denies unsafe code by default. Unless you need `unsafe` for
  FFI, platform calls, or a carefully justified abstraction, do not add it.
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
- Be careful with `Debug` for secret-bearing public types. Custom redacted
  implementations need tests that prove the secret is not rendered.

## Protocol and Configuration Rules

- Keep TACACS+ wire behavior aligned with RFC 8907 and the existing tests.
- The TACACS+ header is 12 bytes. When changing packet code, preserve sequence
  number, session ID, single-connect, and obfuscation semantics.
- Message serialization uses `to_bytes()` / `from_bytes()` and
  `TacacsBodyTrait`. Unless the module already owns that byte-level parser,
  prefer structured parsing over ad-hoc byte slicing.
- Configuration parsing uses RFC 7951/YANG JSON generated types. Entry points
  include `parse_yang_json`, `parse_yang_json_file`, validation options,
  builders, and server enumeration helpers.
- Prefer deterministic and reviewable SONiC mapping. Preserve stable server
  ordering, explicit validation, and clear separation between ConfigDB shape and
  generated YANG model shape.
- Keep TLS credential choices unambiguous. Avoid mixing TCP,
  certificate-based TLS, mTLS, and PSK configuration into an invalid
  intermediate configuration.

## Logging and Observability

- Unless a crate already uses a more structured logging API, follow the
  existing `log`/`env_logger` style.
- Prefer stable, searchable log messages with enough context to diagnose server,
  session, configuration, and failover behavior.
- Unless the context is needed, avoid expensive string formatting or cloning in
  hot paths.
- Redact before logging, not after.

## Dependency Hygiene

- Before you add a dependency, make sure that the standard library or an
  existing workspace dependency is not sufficient.
- Keep portable library builds working without non-Rust system prerequisites.
- Linux product crates can use their required native dependencies directly.
- Prefer libraries that are well-maintained, small in API surface, and compatible
  with the workspace MSRV.
- When dependency changes require it, update `Cargo.toml`, `Cargo.lock`, docs,
  SBOM/security expectations, and CI notes.

## Specialized Areas

- For `executables/session_wrapper/**` or `docs/session-wrapper-testing.md`, use
  `.github/instructions/session-wrapper-wsl-testing.instructions.md`.
- For `libraries/tacacsrs_sonic/**`, `executables/tacacsrs_agentd/**`, SONiC
  docs, or QEMU smoke work, use
  `.github/instructions/sonic-qemu-testing.instructions.md`.
- For protobuf IPC changes, keep `libraries/tacacsrs_agent_client/proto` as the
  source contract, update domain/protobuf conversions together, and run or note
  the `buf breaking` compatibility check.
