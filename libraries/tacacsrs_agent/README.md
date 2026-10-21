# tacacsrs-agent

Reusable building blocks for the central TACACS+ client service introduced for
local IPC consumers such as TACON.

The crate owns configuration supervision, published routing generations, health,
admission, shutdown, and the raw TACACS+ proxy. Networking owns upstream execution
and conservative failover. The protocol crate owns transport-independent operations.
The daemon composes the agent with the client and server transport from
[`tacacsrs-ipc`](../tacacsrs_ipc/), which owns the protobuf contract.
The agent has no production dependency on IPC bindings or tonic.

## Embedding

`TacacsClientService::new` validates startup controls and creates an empty runtime.
`ServiceConfig` contains no upstream source. The canonical `ConfigDatastore` owns that source.
Create one `ConfigSupervisor` per service. Retain it from initialization through shutdown.
Do not create another supervisor for each update. That discards source history and preparation ownership.
The agent exposes no unmanaged construction or server-update mode.

Give the supervisor the health publisher of the service.
Take `ServiceConfig::validation_options` from the datastore.
Give `NoopTacacsPlusFilter::new` the `LocalServices` value of the service.
`NoopTacacsPlusFilter::default()` derives an unobfuscated downstream proxy policy, which replaces a configured proxy secret at publication.

Server updates use the retained datastore observation and supervisor.
`apply_policy_candidate` is the only public policy-update method. It accepts canonical YANG policy, not prepared values.
`PolicySupervisor` uses that same method for an independent policy observation.
Server updates preserve applied policy. Policy updates preserve the server catalog, counter epochs, and materialization metadata.

The public construction and update surface changed as follows:

| Before | After |
| --- | --- |
| `new(ServiceConfig, health)` immediately prepares supplied servers | `new(ServiceConfig, health)` starts empty; the supervisor prepares the source |
| `waiting_for_configuration(ServiceConfig, health)` | Removed |
| `ServiceConfig::tacacs_plus` | Removed; supply the canonical source through a datastore |
| `reload_tacacs_plus` | Removed; update the observed source |
| `reload_tacacs_plus_with_proxy_downstream_obfuscation` | Removed; the host filter derives proxy policy within supervised preparation |
| `reload_materialized_servers_with_proxy_downstream_obfuscation` | Removed; materialization and publication remain private |
| `reload_runtime_policy` | Removed; submit canonical policy to `apply_policy_candidate` |
| `apply_policy_candidate` | Retained; admission fences validation and publication |

No compatibility aliases remain. Diagnostic handles, domain operations, listener settings, `serve_until`, and `close_and_join` remain public.
The host owns signals, listener adapters, and task supervision. A stopped runtime cannot restart.
This example uses the built-in raw proxy. A client API host injects its `RuntimeListenerService` adapters instead.

```rust,no_run
use std::sync::Arc;

use anyhow::Context;
use tokio_util::sync::CancellationToken;

use tacacsrs_agent::{RuntimeHealthPublisher, RuntimePolicy, ServiceConfig, TacacsClientService};
use tacacsrs_agent::runtime::{ConfigSupervisor, NoopTacacsPlusFilter};
use tacacsrs_config::TacacsPlus;
use tacacsrs_config::source::{ConfigDatastore, StaticDatastore};
use tacacsrs_config::tacacsrs::LocalServices;
use tacacsrs_networking::{CertificateVerification, RequestDeadline};

async fn run(source: TacacsPlus, stop: CancellationToken) -> anyhow::Result<()> {
  let datastore = Arc::new(StaticDatastore::new(source));
  let local_services = LocalServices {
    client_api_enabled: false,
    tacacs_proxy_enabled: true,
    tacacs_proxy_endpoint: Some("127.0.0.1:0".to_owned()),
    ..Default::default()
  };
  let config = ServiceConfig {
    local_services: local_services.clone(),
    validation_options: datastore.validation_options(),
    runtime_policy: RuntimePolicy::default(),
    certificate_verification: CertificateVerification::Required,
  };
  let health = RuntimeHealthPublisher::new(config.enabled_services());
  let service = Arc::new(TacacsClientService::new(config, health.clone())?);
  let mut supervisor = ConfigSupervisor::new(
    datastore,
    service.clone(),
    health,
    Arc::new(NoopTacacsPlusFilter::new(local_services)),
  );
  let initialized = supervisor.initialize_until(stop.cancelled()).await;
  if initialized.is_err() || stop.is_cancelled() {
    let deadline = RequestDeadline::after(service.shutdown_timeout())?;
    return initialized.and(service.close_and_join(deadline).await);
  }
  let peers = async {
    tokio::join!(
      async {
        let result = supervisor.run_until(stop.cancelled()).await;
        let requested = stop.is_cancelled();
        stop.cancel();
        if requested { result } else {
          result.and(Err(anyhow::anyhow!("Configuration supervisor stopped unexpectedly")))
        }
      },
      async {
        let result = service.serve_until(stop.cancelled(), Vec::new()).await;
        stop.cancel();
        result
      },
    )
  };
  tokio::pin!(peers);
  let completed = tokio::select! {
    biased;
    () = stop.cancelled() => None,
    result = &mut peers => Some(result),
  };
  stop.cancel();
  let deadline = RequestDeadline::after(service.shutdown_timeout())?;
  let (source_result, service_result) = match completed {
    Some(result) => result,
    None => tokio::time::timeout_at(deadline.expires_at(), peers)
      .await.context("Shutdown deadline elapsed")?,
  };
  let cleanup = service.close_and_join(deadline).await;
  source_result.and(service_result).and(cleanup)
}
```

The host cancels `stop` when it receives its terminal shutdown request.
Initialization completes before listeners bind. An already-cancelled host or failed initialization never binds listeners.
Peer failure also cancels the shared stop token. Cleanup uses one captured shutdown budget.
Deadline expiry cancels owned futures and returns an error. Native work cannot be forcibly interrupted.
Use a continuously observed datastore for live server updates. `StaticDatastore` supplies one immutable baseline.

## Design goals

- Expose domain operations independently of the local RPC transport.
- Keep upstream TACACS+ connections persistent and reusable across IPC requests.
- Support ordered failover independently for each TACACS+ operation.
- Accept host-composed listeners without moving routing or materialization into the host.
- Make the same architecture documentation visible in both rustdoc and GitHub.

## Module hierarchy

```text
tacacsrs_agent
├── config           - public runtime configuration
│   └── policy       - failover strategies and operation limits
├── runtime          - TacacsClientService lifecycle, hot reload, and drains
├── services         - internal service boundaries
│   ├── client_api   - transport-independent operation ingress
│   │   ├── handle   - concrete public operation handle for host adapters
│   │   └── upstream_bridge
│   │                - client API operation/protocol mapping and failover bridge
│   └── tacacs_proxy - raw TACACS+ proxy service
│       ├── service   - TacacsProxyService runtime dependency owner
│       ├── listener  - endpoint dispatch, accept loop, and shutdown drain
│       │   ├── tcp   - loopback TCP binding
│       │   └── unix  - Unix socket binding and cleanup
│       └── upstream_bridge
│           ├── packet_io
│           │          - downstream/upstream TACACS+ packet read/write helpers
│           ├── reply_action
│           │          - reply status classification for session completion
│           ├── session
│           │          - initial packet execution and conversation pinning
│           ├── session_mapping
│           │          - TACACS+ session-id rewriting
│           └── error - downstream/upstream connection error boundary
├── upstream         - TACACS+ upstream service boundary
│   ├── router       - per-service facade over the upstream manager
│   ├── admission    - shared operation-size and concurrency admission
│   ├── attempt      - transmission-aware request failures
│   ├── proxy_transport
│   │                - downstream settings published with the server set
│   ├── manager      - source snapshots, policy publication, and health
│   │   ├── publication - commits one generation with generation-scoped availability
│   │   ├── binding  - networking bindings paired with source metadata
│   │   ├── server_set
│   │   │            - generic request snapshots and networking catalog handles
│   │   └── prepared_server
│   │                - source metadata and prepared endpoint identity
│   ├── connection   - agent exchange interface
│   └── network      - production TCP/TLS upstream connector
└── test_support     - fake upstream fixtures for tests
```

## Failover ownership

`config::RuntimePolicy` projects canonical service policy into a `FailoverPlan` attempt budget.
`tacacsrs_networking::retry` applies the conservative replay rules and owns the retry loop.
The networking `routed` module owns endpoint catalogs, operation identities, circuits, reconnect serialization, and lifecycle state.
The agent does not keep duplicate routing or retry state.

Each ingress path implements `FailoverAttempt` and returns one `Attempt` value for each try.
The networking executor decides whether another attempt is permitted. Unknown outcomes are never replayed automatically.

Services reach routing and admission through `upstream::OperationRouter`. The
router binds one `PolicyService` identity at construction. A service therefore
cannot read another service's state, cannot change the runtime configuration,
and does not pass a service identity on each call.

`OperationRouter::capture_request` captures one runtime snapshot, operation, retry plan, and absolute deadline.
`RequestRouting` owns the resulting `RoutingLease`. The lease reserves and admits work from those captured inputs.
The request retains the manager for binding and generation-aware availability publication, not for admission or outcomes.
`BoundServer` records success and failure through its networking binding. Typed attempts and raw conversations do not retain a router for outcomes.

```text
OperationRouter -- service identity --> RequestRouting
                 |-- RoutingLease: snapshot, plan, deadline, admission
                 `-- manager: bind + availability publication
                    |
                    v
                  BoundServer
                    |
                    v
                networking BoundEndpoint: fenced outcomes
```

Networking retains the generation-fenced failure guard and bounded cleanup owner after request expiry.
Cleanup does not renew the request deadline or permit replay. Downstream continuation waits do not arm an upstream failure guard.

## Connector Composition

`TacacsClientService` is the public, nongeneric service facade.
It contains `ServiceRuntime<NetworkUpstreamConnector>`, whose connector returns the concrete `TacacsUpstreamConnection` type.
Snapshots, request routers, both ingress services, listeners, and exchange adapters remain generic over the connector internally.
This keeps the async `Send` proof in generic implementations and avoids the specialized erased shape described in the architecture investigation.

Production and fake factories implement networking's `EndpointConnector` contract.
The former agent `UpstreamConnector` trait is removed; that name now identifies a test-only trait-object alias.
The erased `ServiceConnector` adapter also compiles only in tests. No dynamic connector or dynamic connection is stored on the production routing path.
The agent exchange interface remains because it owns protocol-to-service error conversion and operation-specific diagnostics.

## Generation Readiness

`RuntimeHealthSnapshot::runtime_generation()` identifies the currently published routing and policy snapshot.
`RuntimeGeneration` values are scoped to one runtime instance. They are not source or credential revisions.
Catalog replacement, applied-configuration status, eligible-server count, and availability reset now commit under the same publication lock.
Health readers cannot observe a partially updated publication. Policy-only updates advance the runtime generation without resetting availability or replacing global admission.
An unchanged catalog reload preserves observed upstream availability. A rejected replacement leaves the published generation and applied-health metadata unchanged.
Publication fences each prepared candidate against its captured catalog identity.
A concurrent catalog or proxy-policy replacement rejects a stale candidate before publication.

Materialized updates also commit the coordinator's active-server set and active source generation inside the runtime publication boundary.
Cancellation before publication leaves the prior runtime and active material unchanged.
Cancellation during later connection retirement retains matching runtime, health, and coordinator state.
The coordinator releases its state lock at commit, before asynchronous retirement. Canonical source snapshots and credential references remain unchanged.

`RuntimeHealthSnapshot::materialization_revision()` reports the applied `SourceRevision` and `CredentialRevision` for coordinated materialization.
The source counter advances at admission before asynchronous host filtering, including repeated candidates and source rejection notifications.
The credential counter advances independently when an invalidation schedules materialization.
These counters belong to one controller instance. They are not content hashes, provider versions, or globally comparable identifiers.
Policy-only updates preserve the applied pair. Every public server update uses coordinated materialization.

Successful materialization clears credential-resolution failure in the publication commit.
Failure reporting checks the attempt revision under the coordinator lock, so an old result cannot change health for newer work.
If a newer credential invalidation supersedes incomplete work, it refreshes all dependencies before targeted selection resumes.

`runtime::ConfigSupervisor` owns source recovery, credential notifications, and materialization coordination.
The host supplies a `ConfigDatastore`, service, health publisher, and `TacacsPlusFilter`.
`NoopTacacsPlusFilter` preserves every upstream. Host-specific filters can derive a working candidate without changing the retained authoritative snapshot.

All supervised sources use the same coordinator, including inline configuration without a credential resolver.
An older filter result cannot replace a newer admitted source or update its health. Source recovery commits with the accepted runtime generation.
A pending or rejected source cannot trigger credential refresh against an older filtered candidate.
Credential invalidations during filtering are retained in the revision used for the eventual prepared candidate.
During source unavailability, credential refresh can use retained configuration without marking the source current.
Source observation continues while one owned candidate future filters, resolves, or publishes.
A newer source event cancels and replaces that future, so disconnection and rejection remain observable.

`ConfigSupervisor` enforces canonical `source-stale-timeout-seconds`, which defaults to 300 seconds and rejects zero.
Its owned monitor captures the applied budget when it first observes a stale published source.
Repeated failures, credential refreshes, and policy updates do not renew that interval.
Health records the source revision that last established a current runtime.
Credential publication during a source outage preserves that recovery identity, even when it applies a different source revision.
At expiry, a generation-checked transaction withdraws upstreams and marks `SourceExpired`. Readiness stops while liveness and source observation continue.
Removed endpoints receive an immediate retirement cutoff. A valid source publication can restore service without replacing shared admission or restarting the process.
Credential refresh cannot revive an expired unavailable source.

`credential-stale-timeout-seconds` independently limits stale referenced credentials and defaults to 300 seconds, with a minimum of one second.
Relevant invalidation marks material stale before resolution starts. Notification loss also starts grace when the applied catalog uses credential references.
Inline-only catalogs do not expire because an unused credential watcher is unavailable.
At expiry, the runtime withdraws the entire catalog and reports `CredentialsExpired`, while source observation and liveness remain active.
An attempt started before expiry cannot revive the old material. Complete revalidation can restore service without changing canonical source references.
Repeated failures and policy changes do not renew grace. Source and credential expiry remain independently enforced after either withdraws the catalog.
Provider validity and revocation-evidence freshness remain separate limits.
Authentication certificate dates apply to each new TLS connection.
Established connections and catalogs continue after those certificate dates expire.

Use `with_credential_resolver` and `with_credential_changes` to configure credential providers.
Notifications require a resolver. Provider configuration is checked before source I/O.
`initialize_until(stop)` optionally prepares the initial configuration before listeners start.
`run_until(stop)` consumes the supervisor and runs both source and credential supervision, without repeating successful initialization.
The stop future belongs to the host. The supervisor installs no process signal handlers.

Cancellation drops pending load, filter, resolution, and publication futures. It preserves the last successfully published configuration.
The runtime uses `ConfigDatastore::observe()` for both initial configuration and later changes.
Successful initialization retains the same session. Interrupted initialization starts a fresh session before retry or serving.
File observations own their watcher and coalesce invalidations without a detached reload worker.
All retained configuration sources implement owned observation. The transitional adapter and datastore subscription method are removed.
Source, credential, and policy decisions use revision checks and the shared generation/health publication boundary.

`TacacsClientService::apply_policy_candidate` accepts a borrowed canonical policy, or `None` for a rejected source observation.
It assigns `PolicyRevision` before validation or publication waits. The canonical value remains unchanged.
This method returns `PolicyUpdate`: `Applied(revision)`, `Rejected(revision)`, or `Superseded`.
Runtime closure remains an error. A superseded candidate cannot change policy, global admission, or health.

`RuntimeHealthSnapshot::applied_policy_revision()` records the last committed policy update, or `None` before the first update.
Policy, runtime generation, shared admission limits, and rejection recovery commit together without an asynchronous wait.
Rejected or cancelled candidates preserve the applied policy revision and generation. Revision numbers can therefore have gaps.
Server updates preserve the policy revision. Policy updates preserve materialization revisions, applied source status, and upstream availability.
`PolicySupervisor::new(observation, service)` no longer accepts a separate health publisher or writes health after publication.

## Candidate Preparation

Canonical `runtime-policy/candidate-preparation` controls supervised startup, source reloads, and credential refreshes.
Generated defaults supply 30 seconds, 256 resolver slots, and 67108864 decoded payload bytes.
`config::RuntimeCandidateLimits` is a derived value, not another configuration resource.
An absent container stays absent in the canonical source.

The supervisor captures policy and one admission instant before filtering or waiting for preparation capacity.
One absolute deadline covers cooperative filtering, provider calls, and publication-lock waits through commit.
Success, retries within the attempt, and looser policy do not renew it.
The final fence uses the tighter captured and applied limits before retirement cutoffs or publication change.
Retirement after commit has a separate cleanup budget. Its completion cannot turn a committed update into candidate rejection.

Each coordinator admits one preparation scope, including cancelled registered provider work.
Its three existing loops retain at most three unexpanded records and three waiter futures in total.
Source observations replace their pending record. Credential events coalesce to full refresh when necessary.
No notification spawns a preparation task. Revision checks follow capacity acquisition and each provider handoff.

One publication owner carries model payload, prepared server references, and commit captures through service and catalog waits.
Cancellation disposes all those owners before it releases the preparation lease.
Successful atomic publication releases the lease before asynchronous retirement. Payload shared with the committed active catalog needs no additional ownership charge.

The decoded payload charge is `L + E`.
`L` includes every logical destination, repeated bundle installations, retained servers during partial refresh, and the downstream proxy secret.
`E` includes additional owned configuration payload, retained filtered projections, and newly prepared Rust payload.
Prepared payload includes DNS address text, routed names, peer identity, SNI, packet keys, PSK callback identity and keys, and group text.
It also includes trust callback DER, fetched OCSP bytes, certificate comparison buffers, and CRL scope and delta metadata buffers.
Reused prepared endpoints contribute their retained payload to `L`. Reuse does not remove a destination from the candidate charge.
Known copies are reserved before cloning. Moves transfer charges, and shared allocation owners add no duplicate allocation charge.
All selected plans pass request admission before the first provider call, in canonical server and plan order.
Repeated references count separately. Each provider return passes byte admission before result buffering or the next call.
Resolver slots are not HTTP URL requests. Provider response and fan-out limits remain independent.

The raw datastore snapshot, opaque producer internals, existing active and retiring catalogs, allocator overhead, and RSS are outside this measure.
An opaque result can already own a large allocation at handoff. Rejection prevents retention and further candidate copies, not that earlier allocation.
Native allocator internals are excluded, but Rust payload owned by a native callback is included.
CRL metadata encodings reserve the enclosing DER size before allocation. Their live charge then contracts to the returned size.
The high-water check includes these conservative reservations. It measures admitted payload, not process memory.

### Rust Payload Owners

All byte totals use checked `u64` arithmetic. String costs use their UTF-8 byte lengths, without allocator capacity or terminators.
The following costs describe supervised preparation, not unmanaged direct helpers.

| Owner | Candidate charge and allocation boundary |
| --- | --- |
| Materialized configuration | `L` counts each destination's secret, key, certificate, intermediate, trust, CRL, and OCSP bytes. Partial refresh includes unchanged destinations. |
| Proxy policy | `L` includes its downstream secret. Policy clones share the secret allocation. |
| Filtered projection and provider staging | `E` includes retained decoded copies. Known copies reserve before cloning; unknown producer results pass admission at handoff. |
| Prepared address and names | `E` reserves DNS address bytes, one routed name, and one lifecycle name before construction. IP addresses use fixed-layout storage. |
| Packet obfuscation key | `E` reserves the copied key length before constructing `SecretBytes`. The source key remains in `L`. |
| PSK context | `E` reserves callback identity bytes, callback key bytes, optional SNI bytes, and the colon-separated native group string before allocation. |
| Certificate TLS context | `E` reserves peer identity and optional SNI. Private keys and decoded certificates live in native objects; their canonical DER remains in `L`. |
| Trust callbacks | Accounted DER owners reserve each authority and exact-peer certificate length before copying. Callback captures retain those owners. |
| Fetched OCSP | `E` reserves the encoded response before constructing its shared byte owner. Config and connection clones share that allocation. |
| Certificate comparisons | Temporary reservations cover DER round trips, explicit public-key comparisons, and all simultaneously retained chain deduplication buffers. Verified input lengths supply the forecasts. |
| CRL comparisons and metadata | Temporary reservations cover DER round trips, scope identities, delta metadata, authority extensions, and integer bytes. Enclosing DER lengths bound native extension encodings. |
| Reused prepared endpoints | Their retained byte cost contributes to the new candidate's `L`. Endpoint identities, contexts, callback DER, and keys share existing allocations rather than creating another `E` copy. |
| Native input, partial output, and queued result | One worker moves or shares these owners. It retains the shared ledger and registered work lease until input, result, and callback payload disposal. |
| Committed historical endpoints | History shares endpoint and source owners until networking reports completed retirement. The next publication prunes completed entries. This ownership belongs to the committed catalog, not unpublished candidate work. |

Temporary byte buffers drop before their reservation guards. Endpoint and native callback owners share one `PreparationPayload` owner.
Lifecycle names retain that same accounting owner through their disposal.
Discarding the final unpublished catalog unregisters its idle, unshared lifecycle entries before candidate capacity returns.
The final shared owner releases retained reservations. Temporary release reduces live bytes but never reduces the candidate high-water mark.
Known conservative forecasts can reject a candidate before its eventual retained size reaches the limit.
Collection headers, fixed-layout metadata, reference counts, native allocator internals, connection execution, raw ingestion, opaque SDK internals, filter DNS, and RSS remain excluded.
Rust bytes inside native callback captures are not excluded. Secret owners retain their existing redaction and disposal behavior; this accounting adds no universal zeroization claim.

Native preparation runs outside coordinator state, service publication, catalog reload, and snapshot-write locks.
One registered blocking worker owns its input, partial output, and queued result before its work lease.
The worker shares the ledger without retaining `Preparation`. Cancellation therefore seals registration promptly.
Client catalog setup also runs before publication locks. The coordinator stages a complete catalog from an immutable applied snapshot.
Final publication retains the existing coordinator, service, catalog, snapshot, and health lock order.
These short commit waits are not lock-free.

The final fence checks source and credential revisions, source expiry, closure, both validity clocks, current limits, and catalog identity.
A changed committed catalog rejects a prepared reuse hint. It cannot revive an earlier identity or counter epoch.
An unchanged catalog can reuse an established connection after its authentication certificate expires.
Provider and evidence validity still restrict publication. Their earlier monotonic cutoffs cannot renew through wall-clock changes.
All fallible checks precede retirement cutoffs, snapshot replacement, health, and coordinator bookkeeping.
The commit does not await. Later retirement cannot undo it.

Providers receive one `WorkScope`. They must register owned work before queueing it and retain the lease through unconsumed results.
Cancellation seals the scope and drops cooperative work. Registered blocking work keeps capacity until its last lease drops.
Permanently stuck registered work keeps the slot. Expiry and host stop do not wait for that slot or for provider quiet.
Native OpenSSL and OS calls cannot be forcibly cancelled. A permanently stuck worker can prevent Tokio runtime or process exit.
Service withdrawal and cooperative host-stop completion do not promise termination of that native worker.
Unobservable OS, SDK, and filter DNS internals are not a hard-cancellation guarantee.
Direct configuration helpers do not acquire this supervisor-owned budget. The public agent API does not expose unmanaged reloads.

`ServiceConfig::validation_options` carries the schema policy selected by the configuration source.
Supervised preparation applies the shared configuration checks with that policy.
The daemon obtains the policy from `ConfigDatastore::validation_options`, including explicit migration relaxations.

The service prepares native transport contexts before publishing changed server slots.
Invalid DER material or a short PSK rejects the candidate before it can replace the active routing snapshot.
Failure preserves the old routes, proxy policy, cached connections, and applied health state.
An empty replacement remains valid for a runtime that waits for new configuration.

Each server slot retains one prepared endpoint for its lifetime.
Connectors receive clones of that endpoint for operation-specific clients and reconnects. They do not interpret YANG or parse credentials.
An unchanged server reuses its existing slot and native contexts.
Changed credential material creates a new slot while bound requests retain the previous generation.

## Tower Boundary

The upstream failover plan is domain code. It interprets TACACS+ `ERROR`
responses, uncertain accounting outcomes, and authentication session pinning.
Tower retry and balancing layers do not model these rules directly.

Tower can wrap the local gRPC transport, but it does not own upstream routing.
The runtime uses one shared failover plan for typed IPC operations and proxy
initial packets. Networking admission pools enforce shared operation capacity.

## Architecture overview

```text
┌──────────────────┐
│ Local Consumer   │
│ such as TACON    │
└──────┬───────────┘
       │ protobuf request / response
       v
┌──────────────────┐
│ ServiceClient    │
│ (client crate)   │
└──────┬───────────┘
       │ gRPC over Unix socket
       v
┌──────────────────────────────┐
│ TacacsClientService          │
│ - service orchestration      │
│ - hot reload                 │
│ - local shutdown tracking    │
└──────┬───────────────────────┘
  │ starts client API service
       v
┌──────────────────────────────┐
│ services::client_api         │
│ - gRPC transport             │
│ - typed operation execution  │
│ - ServiceError mapping       │
└──────┬───────────────────────┘
  │ binds requests
  v
┌──────────────────────────────┐
│ UpstreamManager              │
│ - catalog/policy publication │
│ - generation-aware health    │
│ - captured request binding   │
└──────┬───────────────────────┘
       │ creates / reuses sessions
       v
┌──────────────────────────────┐
│ UpstreamConnection           │
│ - persistent TACACS+ socket  │
│ - accounting transaction API │
└──────┬───────────────────────┘
       │ TACACS+ protocol (RFC 8907)
       v
┌──────────────────────────────┐
│ TACACS+ Server(s)            │
└──────────────────────────────┘
```

The client API gRPC service accepts only Unix domain socket endpoints.
The raw TACACS+ proxy is a sibling runtime service with its own endpoint policy.
When `EnabledServices` includes the proxy service, `TacacsClientService` starts
`services::tacacs_proxy`. When it includes both services, the proxy runs
alongside `services::client_api`. The proxy can bind either a Unix domain
socket or loopback TCP endpoint. The proxy uses its own
`upstream_bridge` because it forwards packet sessions rather than typed RPC
operations.

## Request activity diagram

The runtime uses unary accounting and authorization RPCs over the local IPC
endpoint.

```text
Client
  |
  v
connect to IPC endpoint
  |
  v
send Accounting RPC
  |
  v
local IPC listener accepts client
  |
  v
GrpcService decodes the request
  |
  v
client_api::upstream_bridge maps the typed operation
  |
  v
RequestRouting binds its captured catalog through the manager
  |
  +--> no responsive server
  |      |
  |      v
  |   return ServiceError (Unavailable, Routing, NotSent)
  |
  v
reuse or establish upstream connection
  |
  v
create upstream session
  |
  v
send TACACS+ accounting request
  |
  +--> upstream error
  |      |
  |      v
  |   BoundServer records the generation-fenced failure
  |   networking retires the failed connection and advances the operation cursor
  |   return ServiceError with the original delivery facts
  |
  v
map reply to the operation-specific response
  |
  v
return protobuf response envelope
```

## Failover state chart

Each operation has an independent ordered server catalog. IPC and proxy requests
share one cursor for each operation. A retryable failure opens the applicable
server-operation circuit and advances only that operation cursor.

```text
active operation route
        |
        | retryable failure
        v
open server-operation circuit
        |
        v
select next eligible server
        |
        | recovery interval expires
        v
one real recovery trial
        |
        +-- success --> restore higher-priority route
        |
        +-- failure --> reopen circuit
```

## Listener lifecycle and shutdown

The listener follows this startup sequence:

```text
1. create the parent directory if it does not exist
2. inspect the socket path if it already exists
3. if the path accepts connections → fail (another instance is running)
4. if the path is stale → remove and bind a new socket
5. apply the configured socket mode
6. begin serving IPC clients
```

All hosts use `serve_until(stop_future)`. The former signal-owning `serve()` method is removed.
The library installs no process signal handlers. The daemon registers SIGINT and SIGTERM before asynchronous bootstrap and supplies the stop future.
A stop future that is already ready prevents listener binding and closes the runtime without touching the configured socket path.
Shutdown changes health to `Draining`, closes admission and upstream connection creation, and stops listeners from accepting new work.
Listener and upstream drain use the smaller of the maximum current operation budget and canonical `shutdown-timeout-seconds`.
The shutdown policy defaults to 30 seconds and rejects zero. It does not change request deadlines or endpoint retirement during reload.
Embedding hosts can read the applied budget through `TacacsClientService::shutdown_timeout()` and capture a deadline when cleanup begins.
At expiry, remaining listener tasks are cancelled and joined, and upstream sockets are forced closed.
Owned Unix socket paths are removed before successful shutdown publishes `Stopped`.
A listener failure cancels its siblings and uses the same cleanup path.

Reload schedules removed endpoints for terminal retirement under one cutoff derived from the maximum operation budget at preparation start.
Captured requests can still use their old endpoints before that cutoff; the retirement owner then cancels setup, closes sockets, and joins drivers.
Unchanged endpoint identities retain their caches. A later reload cannot extend an earlier retirement cutoff.
Terminal shutdown also reaches retired endpoints retained by old requests. A stopped service rejects reload and cannot be served again.

Cancelling the serving future schedules immediate upstream cleanup and drops listener-owned transport guards.
Use `close_and_join(deadline)` to confirm upstream cleanup after cancellation or when the service has not started listeners.
For an active listener run, request shutdown through the future passed to `serve_until` and await that run's result.

The daemon captures one absolute deadline across service drain, configuration supervision, and host-task cleanup.
At expiry it drops the service future, aborts and joins pending peer tasks, and reports failed shutdown without hiding the original failure.
This bounds graceful asynchronous waits. Arbitrary non-yielding Rust code or an already-started blocking filesystem operation is not preemptible by a future timeout.

The same typed watch-backed snapshot drives startup, liveness, readiness, datastore freshness, upstream availability, standard gRPC health, host integration, and operator status. It contains only typed flags and counts. Configuration values, server identities, credential references, and raw errors stay outside the shared state.

## Configuration details

### IPC endpoint format

`ServiceConfig::endpoint` is explicit rather than permissive:

- Values containing `/` are treated as Unix domain socket paths, for
  example `/run/tacacs/tacacs.sock`.
- Values that parse as `SocketAddr` identify TCP endpoints for the TACACS+
  proxy or IPC emulator. The client API rejects TCP endpoints.
- An empty string is rejected as invalid configuration. It does **not** fall
  back to the default endpoint.

The only way to opt into the built-in default endpoint is to call
`IpcEndpoint::default_local()`.

### Upstream warm-up behavior

At startup the service performs a best-effort warm-up pass across the configured
TACACS+ servers until it finds the first responsive server. Once the warm-up
caches one usable upstream connection, it stops immediately. It does **not**
establish full TACACS+ connections to every configured server.

This keeps startup load bounded in large deployments where many clients can
start at once against a relatively small TACACS+ server pool. If no server is
reachable during startup, the service still starts and later IPC requests retry
failover on demand.

Per-server reconnect attempts are serialized inside the upstream manager. When
many IPC requests arrive at once, they share one in-flight reconnect attempt for
a given TACACS+ server instead of generating a burst of duplicate TLS handshakes.
After that reconnect attempt finishes, queued callers reuse the cached
connection if it succeeded. If it failed, they fail over without an immediate
retry against the same server for that burst of IPC work.

### Per-client request handling

Each accepted IPC connection currently carries a single unary RPC exchange:

1. Decode one protobuf accounting or authorization request.
2. Map the typed operation through `services::client_api::upstream_bridge`.
3. Select the upstream server for that request through `UpstreamManager`.
4. Encode one protobuf reply envelope.

## Protocol source of truth

The protocol and IPC crates own separate contracts:

- Keep transport-independent domain operations in the protocol crate's
  [`operations`](../tacacsrs_protocol/src/operations.rs) module.
- Define the IPC wire contract in the IPC crate's
  [`proto/tacacsrs_agent.proto`](../tacacsrs_ipc/proto/tacacsrs_agent.proto).
- Generate the Rust gRPC/protobuf bindings at build time in the IPC crate.
- Keep domain-to-protobuf conversions and their focused tests in the IPC crate.

The agent consumes the protocol crate's domain operations without a production
dependency on IPC. The checked-in `.proto` defines the local IPC wire contract.
The build step generates Rust transport bindings from that contract.

There is also no compatibility promise for this IPC protocol today. When the
contract changes, the `.proto`, generated transport bindings, and domain-type
conversions must change together in the same patch.
