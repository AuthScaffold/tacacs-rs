# tacacsrs-agentd

`tacacsrs-agentd` is the central TACACS+ service daemon. It maintains upstream TACACS+ connections and exposes a local IPC endpoint for clients such as `tacon`.

For full deployment and failover guidance, see [../../docs/tacacsrs-agentd.md](../../docs/tacacsrs-agentd.md).

## KubeSONiC containers

Use `tacacsrs-agentd --kubesonic` for the environment-only KubeSONiC profile. It reads existing server rows without requiring SONiC forwarder or TLS tables. All supported runtime controls use grouped `TACACSD_` variables. Server and credential updates use native supervision without child-process restarts.

The profile defaults to both local services, mounted kubelet identity, explicit mounted CA trust, and disabled loopback registration. See the [KubeSONiC guide](../../libraries/tacacsrs_kubesonic/README.md) for the full input inventory, clear-list policy, registration ownership, and migration rules.

## Source registration and ownership

The [source registry](src/source_registry.rs) lists inline CLI, YANG file, SONiC, and KubeSONiC profiles. That list supplies source selectors, profile parsers, and arguments for the generated man page. Every profile returns a `SelectedProfile` with process controls and a list of [components](../../libraries/tacacsrs_composition/README.md). The [agent host](../../libraries/tacacsrs_agent/README.md#component-host) prepares, validates, and runs these components. The daemon does not select providers by concrete type. The daemon supplies no components of its own. It converts its arguments to settings for the library components.

A profile parses its startup inputs before Tokio starts. `SelectedProfile::new` puts the components in this order:

1. The host components from `HOST_COMPONENTS`. These are the [standard components](../../libraries/tacacsrs_agent/README.md#standard-components) of `tacacsrs-agent`, for example systemd, statistics, the client API, and HTTP credential evidence.
2. The runtime policy and the certificate verification values.
3. The source components.

The source components supply the datastore, the credential provider, and the local services. The SONiC and KubeSONiC sources come from their provider crates. The inline and YANG file profiles use `DatastoreSourceComponent` from `tacacsrs-agent`.

To add a source:

1. Implement a source component in a provider crate, or reuse `DatastoreSourceComponent`.
2. Implement a profile module under [profiles](src/profiles/) that returns `SelectedProfile`.
3. Add its selector, CLI arguments, and module name to the source registry.

Keep vendor parsing and I/O in the provider crate. Keep executable argument handling in the profile module.

Datastore observation owns the baseline, notifications, and any background workers. Observation must start before the baseline read. Cancelling an observation poll must preserve pending work. Dropping the session must stop notification delivery and cancel its workers. Credential providers use their independent change-source contract, so credential refresh does not depend on ConfigDB changes.

## Components

A component adds inputs, credential layers, local services overlays, startup checks, listeners, hosted services, or health members. The host code does not know the concrete component types. The daemon supplies no components of its own. Its [selection list](src/components/mod.rs) converts the arguments to settings for these [standard components](../../libraries/tacacsrs_agent/README.md#standard-components) of `tacacsrs-agent`:

- `SystemdComponent` sends systemd notifications. `--host-integration auto` selects `SystemdMode::Auto`, and `systemd` selects `SystemdMode::Required`. `none` selects no component.
- `StatisticsComponent` writes the statistics file. Its startup check protects the statistics file from the listener paths. The daemon selects it when `--statistics-file` is set.
- `ClientApiComponent` adds the listener factory for the client API. The factory returns no listener when the client API is disabled.
- `TacacsProxyComponent` adds the listener factory for the TACACS+ proxy. The factory returns no listener when the proxy is disabled.
- `HttpCredentialComponent` adds the HTTP credential layer when HTTP evidence retrieval is configured. Only the inline, file, and SONiC profiles supply these settings.
- `UpstreamWatchdogComponent` sends periodic upstream probes when a watchdog interval is set.
- `InvalidSourceShutdownComponent` stops the daemon with an error when the runtime reports `SourceConfigurationInvalid`. The daemon always selects it.

The inline and file profiles convert the listener arguments to a `LocalServicesPatch` for `DatastoreSourceComponent`. The SONiC profile gives the same patch to `SonicSource::with_listener_patch`, which applies it to the SONiC local services. The SONiC forwarder row supplies the proxy endpoint later.

To add a host component, implement it in a library crate. Then add a selection function to `HOST_COMPONENTS` that gives the component its settings. A source returns its components from its profile. Do not change the host code. The [agent host guide](../../libraries/tacacsrs_agent/README.md#component-host) shows how a component registers a hosted service and which deferred values it can inject.

All hosted services share one captured shutdown budget with domain drain. A service must finish its cleanup before it returns after shutdown. At the deadline, the agent aborts and joins pending services and awaits the domain's forced listener and upstream cleanup. Forced cancellation can interrupt external cleanup. Providers must not leave detached workers or child processes outside their ownership. Datastore and credential observations retain their own drop-based worker cancellation contracts.

## Health and Host Integration

When the Client API is enabled, its existing endpoint also serves standard `grpc.health.v1.Health` names for startup, liveness, readiness, the overall empty name, and `tacacsrs.agent.v1.TacacsAgent`. Use the separate `tacacsrs-agent-health` executable:

```bash
tacacsrs-agent-health \
    --endpoint /run/tacacs/tacacs.sock \
    --check readiness \
    --timeout-seconds 2
```

Outside KubeSONiC mode, use `--host-integration none` in containers. KubeSONiC defaults `TACACSD_PROCESS_HOST_INTEGRATION` to `none`. `auto` selects systemd only when `NOTIFY_SOCKET` is present. Explicit `systemd` requires the notification socket and helper, sends `READY=1` once after the enabled listeners bind, and sends `STOPPING=1` before listener drain. `READY=1` does not wait for configuration or upstream health. The systemd status text reports them.

The daemon supervises SONiC ConfigDB startup and notification subscriptions.
In SONiC mode, it loads the forwarder profile before binding listeners. It retries unavailable configuration with capped backoff.
It applies valid snapshots without a restart and retains known-good configuration after invalid reloads or subscription outages.

The process registers SIGINT and SIGTERM once, before asynchronous bootstrap.
Either signal cancels startup or requests listener drain through the signal-free agent API.
An unavailable bootstrap dependency does not prevent signal handling. Requested shutdown exits successfully after cleanup.
Unexpected host or configuration task exit is fatal, but the daemon still requests service drain and joins its other tasks.

Startup uses the agent-owned `AgentRuntime`. It constructs the service and retains one `ConfigSupervisor` for the initial configuration and all later server updates. The listeners, the hosted services, and the configuration supervisor start together. An unavailable source does not stop the daemon. The daemon binds its listeners, reports that it is not ready, and retries the source with capped backoff. A request that arrives before the first configuration receives a retryable unavailable error. Bootstrap reads only the command line and the local services. It does not read the configuration datastore. If the runtime rejects a static server configuration, `InvalidSourceShutdownComponent` stops the daemon with an error.

A static source has no change notifications, so a rejected static configuration cannot become valid. For this source, the runtime adds the final `SourceConfigurationInvalid` degradation reason and stops its retries. `InvalidSourceShutdownComponent` then stops the daemon through the injected `ApplicationLifetime`. The daemon drains its listeners and exits with a failure status. A credential resolver failure does not stop the daemon, because the resolver can recover. A source with change notifications, for example SONiC ConfigDB, keeps its retries.

Runtime health reports this state. The gRPC health service, the `tacacsrs-agent-health` probe, and the systemd status show it. The host or the orchestrator decides what to do when the daemon stays not ready, for example restart the daemon.

## Upstream Watchdog

The upstream watchdog is optional and is disabled by default. Use `--upstream-watchdog-interval-seconds SECONDS` to enable it. In KubeSONiC mode, use `TACACSD_PROCESS_UPSTREAM_WATCHDOG_INTERVAL_SECONDS` instead of that flag.

The watchdog sends one RFC 8907 accounting record with the `WATCHDOG` flag after each new server set and then once in each interval. Readiness waits for the first successful probe of each new server set. A policy reload does not start a new server set. The probe tries every eligible accounting server once, independent of the configured failover strategy. The probe does not use client admission slots. A reply with any accounting status counts as a success. An error status still proves the connection, the transport security, and the shared secret. If no server replies, the daemon adds the `UpstreamWatchdogFailed` degradation reason and withdraws readiness. A later successful probe restores readiness. Thus the host can see an upstream failure before the first client request.

Watchdog records count in the accounting statistics of each server. A strict server can reject a `WATCHDOG` record that has no earlier `START` record. This rejection does not withdraw readiness. If the active server set has no accounting server, the watchdog sends nothing.

The independent `PolicySupervisor` submits canonical policy through `apply_policy_candidate`. Configuration supervision runs in the agent. Host integration, statistics export, and profile services run as separately named hosted services. Agentd retains process controls, signal handling, and component selection. The [agent embedding guide](../../libraries/tacacsrs_agent/README.md#embedding) documents the runtime contract.

Outside KubeSONiC mode, use `--runtime-policy <FILE>` to load live failover strategies and request limits. The daemon keeps the last-known-good policy after an invalid update. KubeSONiC uses the startup `TACACSD_POLICY_` inputs instead.

Set `shutdown-timeout-seconds` in that canonical policy resource to bound graceful service cleanup. Its default is 30 seconds; zero is invalid.
The daemon captures the applied value once when cleanup begins. Later policy updates do not renew the deadline.
At expiry it cancels pending work and exits with an error. An earlier failure remains the primary reported error.
Systemd notifications use owned asynchronous child processes, so a stalled helper is terminated when teardown aborts its task.

## Operational Statistics

Outside KubeSONiC mode, use `--statistics-file FILE` for private, atomically replaced read-only YANG statistics once per second. In KubeSONiC mode, use `TACACSD_PROCESS_STATISTICS_FILE` instead of that flag.

The report identifies the runtime generation and each counter epoch. It never includes credentials or command data. Unchanged endpoints retain counters across reloads. Replacements start a new counter lifetime. The last report remains after shutdown.

Before you use the last report as current data, verify process health. See [operational statistics](../../docs/tacacsrs-agentd.md#operational-statistics) for counter semantics and failure behavior.

## Optional Profiling

Tokio Console profiling requires the `console` feature and `RUSTFLAGS="--cfg tokio_unstable"` when building Tokio and the daemon.
Without that instrumentation cfg, a `console` build reports that profiling is disabled and uses normal logging instead of panicking.

## Runtime Service Modes

Use `--service-mode client-api`, `--service-mode tacacs-proxy`, or
`--service-mode both` to choose which local runtime services the daemon hosts. If the
flag is omitted, the daemon runs `client-api` by default and runs `both` when
`--proxy-endpoint` is supplied. Proxy modes require `--proxy-endpoint`.

When the raw TACACS+ proxy listens on a TCP endpoint, do not configure that same
endpoint as an upstream TACACS+ server. Doing so sends client traffic back into
the proxy itself and can create a packet storm. To guard against this, the
daemon removes upstream entries whose address and port parse or resolve to the
local TCP proxy endpoint. This includes loopback IPv4, loopback IPv6, and
hostnames such as `localhost`.

If the daemon removes one or more local proxy endpoint rows this way, the raw
proxy uses a shared secret for downstream TACACS+ obfuscation. It takes this
secret from the highest-priority matching row, including secrets inherited from
global configuration. If that highest-priority local proxy row has no shared
secret, local clients must send unobfuscated TACACS+ packets to the proxy. This
applies even when lower-priority local rows or real upstream servers have
shared secrets.

Outside SONiC mode, if raw TACACS+ proxy clients send obfuscated packets to the
proxy, use `--proxy-shared-secret` with `--proxy-endpoint`. If the flag is
omitted, local proxy clients must send unobfuscated packets. If both are
present, a filtered local proxy endpoint row takes precedence over this CLI
fallback.

## TLS Client Certificates and Keys

When the upstream TACACS+ server requires the daemon to present a TLS client identity, use `--client-certificate` and `--client-key` with `--use-tls`.

KubeSONiC uses `TACACSD_TLS_CLIENT_CERTIFICATE` and `TACACSD_TLS_CLIENT_KEY` instead of these flags. Its key path defaults to the certificate path.

- Provide both flags together.
- Both files can be PEM or DER. The daemon detects PEM input and converts it to DER before it builds the runtime connection configuration.
- Windows "export with private key" workflows commonly produce PKCS#12 (`.pfx` / `.p12`) bundles. These flags do not accept that container format. Provide PEM or DER certificate and private-key material instead.
- This PEM-or-DER behavior applies only to the CLI flags. If upstream TLS material comes from `--config`, the YANG-backed `tacacsrs-config` path remains DER-only.

## HTTP CRL Registration

Use `--http-crl-source REFERENCE URL` to register public HTTP(S) CRL locations at startup.
Repeat the reference to supply an ordered issuer set. Canonical `tacacsrs:require-crls` policy retains the opaque reference.
Registration does not enable verification by itself. URL-map changes require a process restart.

The provider uses a whole-set timeout and byte and concurrency limits. HTTPS requires trusted, matching certificates.
Locations must contain no secrets. URL credentials, queries, fragments, redirects, and environment proxies are not supported.
The existing supervisor refreshes evidence and enforces failure and expiry policy. Host signals cancel pending retrieval.
SONiC credential resolution and notifications remain available through provider composition.
See [HTTP CRL registration](../../docs/tacacsrs-agentd.md#http-crl-registration) for limits and examples.

## TLS 1.3 PSK

When built with the `psk` feature, use `--psk-identity` and `--psk-key` with
`--use-tls` to configure TLS 1.3 PSK upstream connections. The default
key-exchange mode is PSK-DHE with the preferred group order
`secp384r1,secp256r1`.

Use `--psk-key-exchange-groups` to constrain the PSK-DHE groups offered in
ClientHello. Supplying groups implies PSK-DHE mode. If a peer cannot negotiate
PSK-DHE, use `--psk-key-exchange psk-only` for interoperability. PSK-only mode
cannot be combined with `--psk-key-exchange-groups`.

### Example

```bash
tacacsrs-agentd \
    --server-addr tacacs1.example.com:449 \
    --server-addr tacacs2.example.com:449 \
    --use-tls \
    --client-certificate /etc/tacacs/client.crt.pem \
    --client-key /etc/tacacs/client.key.pem \
    --listen-endpoint /run/tacacs/tacacs.sock
```

The daemon also supports DER files:

```bash
tacacsrs-agentd \
    --server-addr tacacs1.example.com:449 \
    --server-addr tacacs2.example.com:449 \
    --use-tls \
    --client-certificate /etc/tacacs/client.crt.der \
    --client-key /etc/tacacs/client.key.der \
    --listen-endpoint /run/tacacs/tacacs.sock
```

TLS PSK-DHE uses the default group order unless you constrain the groups:

```bash
tacacsrs-agentd \
    --server-addr tacacs1.example.com:449 \
    --server-addr tacacs2.example.com:449 \
    --use-tls \
    --psk-identity client@example.com \
    --psk-key "$TACACS_TLS_PSK" \
    --psk-key-exchange-groups secp384r1,secp256r1 \
    --listen-endpoint /run/tacacs/tacacs.sock
```

For PSK-only interoperability mode:

```bash
tacacsrs-agentd \
    --server-addr legacy-tacacs.example.com:449 \
    --use-tls \
    --psk-identity client@example.com \
    --psk-key "$TACACS_TLS_PSK" \
    --psk-key-exchange psk-only \
    --listen-endpoint /run/tacacs/tacacs.sock
```
