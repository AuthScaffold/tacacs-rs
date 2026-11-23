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
- The Rust edition is 2021. The workspace MSRV is `1.91`.
- All workspace crates are internal. They are not published to crates.io.

## Refactor Workflow

- Before continuing a refactor, read the relevant crate guides and tests.
- Verify the current branch, disk state, and commit history before making changes.
- Preserve canonical YANG configuration. Prepared runtime values are derived artifacts, not a competing configuration model.
- Serialize editor edits and terminal rewrites of each file. Verify saves before formatting and editor refresh afterward.
- If editor and disk content differ, compare them before recovery. Never discard all unsaved buffers automatically.

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
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --document-private-items

# Build and test
cargo build --workspace
cargo test --workspace --all-features

# Targeted loops
cargo test -p tacacsrs-protocol
cargo test test_name
cargo clippy -p tacacsrs-networking --all-targets --all-features -- -D warnings
```

CI also exercises these jobs. When a job is relevant to your changes, run it
locally. If you cannot run a job, explain why:

- `cargo machete --with-metadata --skip-target-dir . .github/tools/api-classifier`
  for dependency changes.
- `cargo audit --file Cargo.lock` after dependency or lockfile changes.
- `cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info`
  for coverage-sensitive work.
- `buf breaking --against '.git#branch=main'` after protobuf schema changes.
- `MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test --locked --all-features -p tacacsrs-secrets -p tacacsrs-protocol -p tacacsrs-credential-resolution -p tacacsrs-lifecycle -p tacacsrs-composition`
  and `MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test --locked --all-features -p tacacsrs-bash-plugin --lib`
  for unsafe, FFI, or aliasing-sensitive changes.
- `cargo +nightly fuzz run <target> -- -max_total_time=30` for protocol parser
  changes under `fuzz/`.

The full reusable pipeline also runs these additional checks:

- Toolchain cache restore and save
- Format check
- Clippy
- Docs build
- Protobuf compatibility check
- Tests
- Coverage
- Dependency audit
- Unused dependency check (`cargo-machete`)
- Miri (path-filtered on pull requests; unconditional on `main`, schedules, and manual runs)
- Fuzz smoke tests (path-filtered on pull requests; unconditional on `main`, schedules, and manual runs)
- Independent default-feature compilation checks
- AMD64 and executed ARMhf platform validation

## Workspace Architecture

Current workspace members are listed in `Cargo.toml`. In the sketch below,
arrows point from a crate to the workspace crates it depends on:

```text
tacacsrs-lifecycle -> (no workspace crates)
tacacsrs-composition -> tacacsrs-lifecycle
tacacsrs-protocol -> tacacsrs-secrets
tacacsrs-networking -> tacacsrs-protocol, tacacsrs-secrets
tacacsrs-credential-resolution -> tacacsrs-secrets
tacacsrs-config -> tacacsrs-networking, tacacsrs-protocol,
                   tacacsrs-credential-resolution, tacacsrs-secrets
tacacsrs-provider -> tacacsrs-config, tacacsrs-credential-resolution
tacacsrs-sonic -> tacacsrs-composition, tacacsrs-config,
                  tacacsrs-credential-resolution, tacacsrs-provider
tacacsrs-kubesonic -> tacacsrs-composition, tacacsrs-config,
                      tacacsrs-credential-resolution, tacacsrs-lifecycle,
                      tacacsrs-provider, tacacsrs-secrets
tacacsrs-revocation -> tacacsrs-networking
tacacsrs-ipc -> tacacsrs-protocol, tacacsrs-secrets, tacacsrs-unix-socket
tacacsrs-agent -> tacacsrs-config, tacacsrs-protocol, tacacsrs-networking,
                  tacacsrs-credential-resolution, tacacsrs-composition,
                  tacacsrs-ipc, tacacsrs-lifecycle, tacacsrs-provider,
                  tacacsrs-secrets, tacacsrs-unix-socket
tacacsrs-agent-ipc-emulator -> tacacsrs-ipc
tacacsrs-bash-plugin -> tacacsrs-ipc

tacon -> tacacsrs-ipc (Linux only), tacacsrs-config, tacacsrs-protocol, tacacsrs-networking,
         tacacsrs-revocation
tacacsrs-agentd -> tacacsrs-agent, tacacsrs-composition, tacacsrs-config,
                   tacacsrs-lifecycle, tacacsrs-networking, tacacsrs-secrets,
                   tacacsrs-sonic, tacacsrs-kubesonic, tacacsrs-revocation
tacacsrs-agent-health -> tacacsrs-ipc
tacacsrs-agent-ipc-emulatord -> tacacsrs-ipc, tacacsrs-agent-ipc-emulator
session-wrapper -> tacacsrs-ipc
```

### Libraries

- `tacacsrs-protocol` owns wire bodies, logical operations, failure facts, exchange
  descriptions, and unchanged-command interpretation. Body codecs live in `body`.
  TACACS+ MD5 XOR obfuscation is not encryption.
- `tacacsrs-networking` owns prepared endpoints, transports, client selection,
  connection drivers, sessions, single-connect promotion, routed catalogs, and retry.
  Its `revocation` module defines the `RevocationVerifier` contract that the
  TLS handshake calls after OpenSSL verifies the server certificate path.
- `tacacsrs-ipc` owns generated `proto` bindings, conversion, the domain handler,
  bounded Unix server, standard and detailed health, and `ServiceClient`. The client retains a reusable tonic channel.
  Optional read-only routes join the listener through `ListenerServices`.
- `tacacsrs-unix-socket` owns trusted-directory binding, advisory locks, and owned-path cleanup.
- `tacacsrs-agent` owns source supervision, revision-fenced publication, health,
  domain operation ingress, raw proxying, and coordinated shutdown. Its `host`
  module declares the host inputs, roles, and deferred values, and runs
  `AgentRuntime` from components. Its `components` module holds the standard
  components: datastore source, client API over IPC, statistics, systemd,
  upstream watchdog, and invalid-source shutdown. A host injects a revocation
  verifier through `UpstreamRevocation`.
- `tacacsrs-lifecycle` owns `HostedService`, `ShutdownSignal`, and typed
  `HealthGroup` contracts over `health-checks`. It has no workspace dependencies.
- `tacacsrs-composition` owns the `Component` contract and the checked Dill
  `Composition` and `Graph`. Only `tacacsrs-composition`, `tacacsrs-agent`, and
  the source component crates use Dill.
- `tacacsrs-config` contains generated RFC 7951/YANG JSON model types,
  builders, validation options, server enumeration, and credential reference
  validation for `ietf-system-tacacs-plus`.
- Configuration's `source` module owns `ConfigDatastore`, observations, and static/file backends.
  Its `input` module normalizes CLI inputs. Parsing functions are re-exported at the crate root.
- `tacacsrs-credential-resolution` owns provider-neutral material and resolver contracts.
- `tacacsrs-revocation` provides `CrlVerifier`, the CRL implementation of
  `tacacsrs_networking::RevocationVerifier`. It fetches and caches CRLs only
  from allowed HTTP distribution points. `tacacsrs-agentd` and `tacon` direct
  mode inject it into the networking stack.
- `tacacsrs-sonic` maps SONiC ConfigDB `TACPLUS` / `TACPLUS_SERVER` data into
  the YANG model and implements SONiC-backed configuration loading and watching.
  `SonicSource` is its source component.
- `tacacsrs-kubesonic` maps `TACACSD_` environment variables, Redis server rows,
  and mounted credentials. `components` returns its source and registration components.
- `tacacsrs-agent-ipc-emulator` provides OPA/Rego-driven local IPC emulation for
  integration and scenario testing.
- `tacacsrs-testkit` provides shared test PKI/CRL generation, TLS 1.3 PSK server
  callbacks, and scripted TACACS+ upstream fault-injection peers. It is excluded
  from `default-members` and forbidden from production crates.
- `tacacsrs-bash-plugin` exposes the SONiC Bash `execve` plugin surface and must
  keep FFI, runtime, configuration, logging, authorization, and session concerns
  separated.

### Executables

- `tacon` is the CLI client. It supports direct server mode and agent IPC mode,
  accounting, authorization, fixed PAP authentication, and batch execution.
  Its man page is generated from clap definitions in `executables/tacon/src/cli.rs`.
- `tacacsrs-agentd` is the local central agent daemon. It can load static JSON or
  SONiC ConfigDB-backed configuration and proxies IPC operations to upstream
  TACACS+ servers. Its profiles convert arguments to component settings and
  select components, and `tacacsrs_agent::host` runs them. The only component
  of the daemon is `RevocationComponent`, which injects the CRL verifier and
  runs the CRL refresh service. Add sources, startup checks,
  listeners, hosted services, and health members as components, not as
  host code changes.
- `tacacsrs-agent-ipc-emulatord` runs the OPA/Rego-driven IPC emulator as a process.
- `session-wrapper` is a Linux x86_64 login session wrapper proof of concept.
  When you change it on Windows, use the session-wrapper WSL testing instructions.

## Versioning and Release

Manifests on `main` use `0.0.0-dev`. CI computes real versions from git tags.
The `.github/steps/inject-versions` action hydrates the manifests and
`Cargo.lock` before CI validates the generated source commit.

- Libraries receive semver versions and tags of the form `<crate>-vX.Y.Z`.
  The compute step can run `cargo-semver-checks` and cascades dependency-aware
  version bumps.
- The managed executables share CalVer versions of the form `YYYY.MMDD.BUILD`.
  Repository tags use `tacacs-rs-YYYY.MMDD.BUILD`.
  GitHub Release titles use `TACACS-RS YYYY.MMDD.BUILD` and list every workspace crate version.
  Historical `tacon-*` tags remain CalVer baselines.
- The append-only `release` branch contains the hydrated source for each release.
  Release tags point to these generated commits. Each commit records its source
  commit from `main`.
- CI requires a GitHub-verified signature and validates the exact hydrated SHA before publication.
  The Git Database REST API preserves the two-parent release history.
  Releases contain source only. CI does not publish binaries or product containers.
  See `docs/release-rehearsal.md` for candidate verification and retry rules.

## Feature Flags and Platforms

- Default builds use dynamically linked OpenSSL for certificate-based TLS and
  TLS 1.3 pre-shared key support.
- Library features must be additive: enabling a feature can add capability, but
  must not remove or change unrelated public API behavior.
- The complete workspace supports Linux GNU. Product crates do not provide
  unsupported-platform fallback implementations.
- Windows supports `tacon` direct mode and its dependency crates only.
- Use the development container for complete workspace development on Windows.
- Source consumers supply the OpenSSL runtime for their target platform.
  Local container recipes remain available without CI image publication.
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
  `FixedExchange`, `ClientConversation`, `ConfigDatastore`,
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
- Preserve the service failover model: per-server reconnects are serialized and
  new sessions use the active server index.
- An unavailable configuration source is never fatal. The agent starts its
  listeners and hosted services, reports the state through runtime health, and
  retries. Hosts and orchestrators act on health. Do not add fail-fast startup.
  A rejected configuration from a source without change notifications is
  final. The runtime reports `SourceConfigurationInvalid`, and a host component
  stops the application through the injected `ApplicationLifetime`.
- The optional upstream watchdog sends accounting `WATCHDOG` records. Readiness
  waits for the first probe of each server set, and a failed probe withdraws
  readiness. Systemd `READY=1` follows bound listeners, not
  readiness.

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
  tests, `tacacsrs_testkit` for shared PKI, TLS/PSK peers, and scripted upstream
  wire fault injection, and `tests/e2e/` (`pytest`) for black-box multi-process,
  signal, Redis, and CLI workflows.
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
- For protobuf IPC changes, keep `libraries/tacacsrs_ipc/proto` as the
  source contract, update domain/protobuf conversions together, and run or note
  the `buf breaking` compatibility check.
