# Runtime and Boundary Contracts

## Status

These are proposed acceptance contracts for the [target architecture](target-architecture.md).
They are not claims about the current implementation.
The [current-state findings](current-state.md) identify existing gaps and useful mechanisms.

Normative terms apply to the future design: a component must satisfy its contract before its migration stage is complete.
Some policies remain configurable, but their meaning and ownership are fixed here.

## Ownership Model

| Resource or decision | Owner | Release or transition |
| --- | --- | --- |
| Process signals and exit status | Executable | Process host translates signals into shutdown requests |
| Canonical YANG snapshot revisions | Configuration controller | A newer accepted source revision supersedes prior preparation |
| Credential preparation tasks | Configuration controller | Completion, supersession, deadline, or shutdown |
| Published routing generation | Routed client | Atomic replacement for new request leases |
| Request lease | One admitted operation | Success, terminal failure, cancellation, or deadline |
| Global capacity | Admission controller | Permit release or explicit limit update |
| Endpoint circuit and reconnect state | Client endpoint slot | Generation-aware success, failure, or retirement |
| Connection driver | Client connection owner | Explicit close, drain completion, fatal I/O, or last-owner cancellation |
| Session ID and reply route | Session guard | Completion or guard drop |
| Source watcher | Source observation session | Session close or drop triggers cancellation and cleanup |
| Listener socket and accepted tasks | Ingress adapter | Stop accepting, drain, abort at deadline, cleanup |
| Native TLS callback material | Prepared TLS context | Last context reference release |
| Health projection | Read-only adapter | Projection of the controller's typed snapshot |

An owner can delegate work without transferring its lifetime obligation.
A detached task is not a completed resource-management design.
Every long-lived task must have a termination signal and an observable completion path.

## Protocol Boundaries

### Packet construction and decoding

A valid packet contains exactly the body length declared by its header.
Construction computes the body length or rejects disagreement.
Complete-buffer parsing rejects both truncated and surplus input.
Prefix parsing returns consumed length explicitly and does not masquerade as complete-buffer parsing.

The decoder rejects an oversized declared body before allocating that body.
An incomplete read never becomes a complete packet.
When cancellation interrupts a partial frame, the connection retains decoder state or closes.
It must not restart at a false frame boundary on the same stream.

The packet type distinguishes the body protection state sufficiently to prevent accidental double processing.
Obfuscation remains TACACS+ body obfuscation, not encryption.
TLS endpoints obey their transport specification and do not inherit legacy obfuscation through unrelated source fields.

### Session state

A conversation has one session ID, packet type, protocol version, and sequence progression.
Client and server sequence numbers advance in the protocol-defined order.
Sequence exhaustion terminates the conversation rather than wrapping.
The fixed-exchange path validates the complete reply header before body interpretation.

A session route remains registered until its operation releases ownership.
Cancellation releases the route and its ID reservation.
A late packet cannot be delivered to a different live session through immediate ID reuse.
The allocator must state its collision and reuse policy for the lifetime of one connection.

Unknown-session replies are distinguishable from malformed replies for a live session.
An invalid live-session header triggers the documented connection failure policy.
The implementation must not silently reinterpret it as a successful response.

## Request Execution

### Request lease

A request lease captures these immutable inputs once:

- Operation kind and validated request.
- Routing generation ID and ordered eligible endpoint set.
- Retry policy and replay permissions.
- Absolute request deadline.
- Credential/context references needed by its eligible endpoints.

Mutable circuit observations can influence endpoint selection within that captured set.
The lease cannot silently switch to a newly published endpoint set between attempts.
Failure and success reports carry the endpoint and connection generation they describe.
Old reports cannot reset a newer connection's state.

For a raw proxy, the first packet creates the lease.
After the proxy forwards an accepted reply, the conversation remains pinned to its upstream endpoint and session.
Continuation packets cannot fail over.
A retryable first `ERROR` reply can trigger another attempt only before any reply reaches the downstream caller.

### Deadline and cancellation

One absolute deadline bounds admission, DNS, connection setup, TLS, transmission, and response wait.
Each stage receives the remaining budget instead of resetting the timeout.
Attempt-specific limits can shorten that budget but cannot extend it.

Cancellation means that the caller no longer waits or authorizes further work.
It does not prove that a transmitted operation did not execute remotely.
The client must stop additional attempts, release admission, and remove the session route.
It must also classify any exposed failure conservatively.

| Cancellation point | Required cleanup | Delivery fact |
| --- | --- | --- |
| Before admission | Remove waiter | `NotSent` |
| During DNS, connection, or TLS setup | Cancel setup and close incomplete transport | `NotSent` |
| Before the writer accepts a request | Remove pending work only if removal is proven | `NotSent` when proven |
| After writer acceptance | Stop waiting and prevent replay unless policy permits it | `OutcomeUnknown` unless non-transmission is proven |
| During reply wait | Remove route and release permit | `OutcomeUnknown` |
| During a conversation continuation | Terminate local conversation state | Do not restart on another server |

Drop provides local cleanup even when asynchronous completion cannot run.
Explicit close remains necessary when the caller needs proof that transport resources are gone.

### Retry matrix

The default policy is conservative across all operation kinds.
This intentionally changes the current policy that can retry unknown authentication and authorization outcomes.

| Result | Default action | Optional policy |
| --- | --- | --- |
| Invalid local request | Return failure | None |
| No eligible endpoint | Return unavailable | A later independent request can retry after configuration changes |
| Capacity deadline | Return capacity/deadline failure | Caller can submit a later request |
| Proven not sent | Try the next eligible endpoint within the lease budget | Deferred failover can stop after one attempt |
| Valid server denial | Return denial | Never convert denial into ordinary failover |
| Valid operation-specific server error | Return response or use an explicitly selected failover policy | Policy names the operation and acceptable replay semantics |
| Unknown accounting outcome | Return unknown outcome | No automatic replay |
| Unknown authentication or authorization outcome | Return unknown outcome | Explicit opt-in with documented side effects |
| Accepted conversation reply followed by failure | Terminate that conversation | No continuation failover |

No API promises exactly-once execution over a failed network connection.
Accounting deduplication needs a separate protocol/application contract before it can justify retry.
Authentication is not assumed side-effect-free because it can affect lockout counters and audit records.

## Admission and Backpressure

Capacity belongs to the running client/application instance, not to a configuration generation.
Old and new request leases consume the same applicable global operation budget.
Reload cannot double capacity by constructing a second independent semaphore.

Reducing a limit does not cancel existing operations by default.
New admissions wait until outstanding work falls below the new limit.
Increasing a limit makes only the added capacity available.
Waiters have deadlines and a documented fairness rule.

The design separately bounds:

- Active local operations.
- Pending admission waiters.
- Connections accepted from each local peer and in total.
- Active sessions per upstream connection.
- Outbound packets per connection.
- Inbound packets per conversation.
- Frame body size and decoded attribute sizes.

Fixed replies use one-shot routes where possible.
A slow conversation must not indefinitely block the connection reader for unrelated sessions.
The reader uses bounded dispatch with an explicit overflow result.
If isolation cannot preserve protocol state, the connection closes and all affected operations receive classified failures.

Default profile values must be finite and defined once in the canonical configuration contract.
Product-specific admission defaults belong to documented YANG augmentations, not independent runtime policy definitions.
Initial tuning can preserve suitable current limits, but tests must prove the limits rather than depend on undocumented constants.
Benchmarks determine later tuning. They do not determine ownership semantics.

## Configuration Publication

### Configuration authority

YANG is the authoritative configuration model, not merely one interchangeable input format.
CLI and SONiC adapters normalize their inputs into canonical YANG snapshots before preparation.
The [canonical YANG contract](target-architecture.md#canonical-yang-contract) defines the standards baseline and preparation boundary.

The source snapshot retains its configuration values, credential references, and provenance throughout resolution and publication.
Prepared credentials and native contexts are derived artifacts with their own lifetimes.
They never overwrite the snapshot, become a second editable configuration source, or introduce independent defaults.
Credential rotation can create a new runtime generation from the same unchanged YANG snapshot.

The pipeline preserves supported YANG choices, defaults, units, user ordering, identities, references, and constraints.
Product-specific configuration uses documented namespaced augmentations instead of a parallel desired-configuration schema.
Preparation rejects unsupported configured features explicitly and reports their paths without exposing secret values.
Runtime observations can influence execution only within the policy established by the canonical configuration.
They do not silently rewrite server ordering, credential choices, or the security policy.

### Observation session

Starting an observation session establishes a watch and an authoritative snapshot as one defined operation.
A backend can satisfy this with a revision cursor or with watch-first, reload, and reconciliation.
It cannot rely on unrelated future changes to repair a startup race.

An event contains a source revision and either a complete canonical YANG snapshot or an explicit invalidation.
The revision identifies ordering within that source session.
A reconnect has an epoch so revisions from a previous session cannot appear newer accidentally.

Backends without atomic storage snapshots state that limitation.
For file groups, a before/after revision check rejects a candidate changed during its own read.
The contract guarantees convergence to a stable readable snapshot, not a fictitious cross-file transaction.
File notifications are hints, and periodic reconciliation handles missed hints.

The source session owns watcher tasks and native watcher objects.
Closing it releases those resources even if no more file or Redis events arrive.
Watcher errors reach supervision as typed availability events.

### Preparation and commit

Preparation follows this sequence:

1. Accept a canonical YANG snapshot and assign a preparation ticket.
2. Validate the snapshot against the supported schema and feature set.
3. Expand local credential bundles in staged work without changing the snapshot.
4. Resolve every required credential for the candidate.
5. Validate provider result matching, material revisions, and credential validity.
6. Prepare native transport contexts and endpoint definitions.
7. Compare the ticket with the current source and relevant credential and policy revisions.
8. Publish the complete generation or discard the superseded candidate.

Expensive parsing and provider I/O happen outside the publication critical section.
The commit does not await I/O while it holds the state-publication lock.
Only the controller can authorize publication.
It publishes routing inputs and corresponding applied-health metadata in a coordinated transition.

Each supported YANG field has a documented mapping to a prepared value or runtime behavior and an acceptance test.
Schema checks and runtime checks have distinct responsibilities, not competing configuration rules.
Runtime tests enforce RFC 9887 transport requirements even when the input document passes YANG validation.
Those requirements include TLS version policy, mutual authentication, no obfuscation over TLS, and no TLS-to-plaintext fallback.

A failed candidate does not partially replace active endpoints.
An old successful preparation cannot replace a newer authoritative YANG revision.
A schema-valid empty server set publishes successfully and withdraws readiness for operations without routes.
The applicable system authentication constraints still determine whether an empty set is valid.
Invalid input is not treated as an empty set.

The published identity includes source revisions, credential revisions, and routing-policy revision.
Independent sources can advance independently, but each generation records the exact combination that it uses.
Administrative limits have a separate live revision because their scope spans generations.

### Reuse and retirement

Unchanged prepared endpoints can reuse cached connections and circuit state.
Reuse requires equality of connection-relevant values, including credential revision and peer-verification policy.
A server name alone is not a sufficient reuse key.
Public logs must not expose a hash of low-entropy secret material as a convenient fingerprint.

New leases use the new generation.
Existing leases can finish against their captured endpoints within their deadlines and the retirement bound.
Retired endpoint slots reject new leases but can serve already-authorized work.
The endpoint closes after its last lease, or at the bounded forced-retirement deadline.

Removing an endpoint is ordinary retirement unless the change explicitly declares revocation.
Revocation is a separate administrative action with stronger semantics.

## Credential Lifecycle

The controller distinguishes source freshness, credential freshness, and remote server availability.
These are not one stale/not-stale flag.

| Event | Default behavior |
| --- | --- |
| Ordinary source outage | Keep the known-good generation and report source degradation |
| Invalid source candidate | Reject candidate, keep known-good state, report rejection |
| Routine credential rotation failure | Keep usable old material only within the configured stale-material policy |
| Known expiry | Stop admitting work that requires expired material |
| Explicit revocation | Block new leases immediately and terminate affected active connections under the revocation policy |
| Recovery after notification loss | Resolve affected material again before clearing the freshness fault |
| Superseded resolver completion | Discard it without changing applied state or current health |

The daemon profile requires an explicit stale-material budget and a retirement bound.
Their values are deployment policy, not implicit retry-loop behavior.
A library caller can select unbounded source retention explicitly for non-expiring static configuration.
That choice does not override known credential expiry or revocation.

Providers that cannot report revocation cannot claim immediate revocation support.
Periodic refresh bounds the detection delay for such providers.
The operational documentation must state that delay and the provider's revision guarantees.

Old secret material remains alive only while prepared contexts or authorized leases require it.
Drop releases protected buffers and native contexts according to their ownership rules.
The design makes external-library zeroization limits explicit.

## Process Lifecycle

The runtime receives cancellation from its host.
It does not register SIGTERM or Ctrl-C handlers itself.
The process host owns exactly one signal policy and one final exit result.

| State | Meaning | Allowed transition |
| --- | --- | --- |
| Created | Components exist but own no listening endpoints | Starting or Stopped |
| Starting | Sources and listeners initialize | Serving, WaitingForConfiguration, Draining, or Failed |
| WaitingForConfiguration | Health can respond, but operation readiness is false | Serving, Draining, or Failed |
| Serving | Selected listeners accept operations under an applied generation | Draining or Failed. Degradation stays a separate dimension. |
| Draining | No new work enters | Stopped or Failed after bounded cleanup |
| Stopped | Owned tasks and listeners are closed | Terminal |
| Failed | Unrecoverable component failure prevents normal service | Cleanup, then terminal process result |

Shutdown has one order:

1. Mark the runtime as draining and withdraw operation readiness.
2. Stop new source publications and listener admissions.
3. Cancel observation and preparation work.
4. Let admitted operations finish within the remaining drain deadline.
5. Abort remaining operations and classify unknown outcomes conservatively.
6. Close and join connection drivers, listener tasks, and provider work that can be joined.
7. Remove only local resources owned by this runtime instance.
8. Publish stopped state and return control to the process host.

Already-running blocking work cannot be forcibly canceled safely by dropping its Tokio handle.
Blocking provider and host operations therefore need bounded operations and a documented shutdown treatment.
The runtime must not claim complete cleanup while unbounded owned work remains.

A fatal listener or driver owner failure follows the same cleanup discipline.
Process exit is not the only available resource cleanup mechanism.
Embedded hosts need a complete shutdown result without terminating their process.

## Health and Diagnostics

Health reflects typed state, not arbitrary log text.
The application publishes a consistent snapshot with generation identity, listener state, operation eligibility, freshness, and degradation reasons.
Adapters do not independently infer readiness from unrelated fields.

| View | Contract |
| --- | --- |
| Startup | The runtime applied its first valid generation and completed required initialization |
| Liveness | The control loop can make progress and has no fatal internal failure |
| Readiness per operation | Required ingress is active, usable configuration exists, and the operation has an eligible route |
| Aggregate readiness | All operations declared required by the deployment satisfy readiness |
| Degradation | Source staleness, credential problems, upstream failures, or restart requirements without conflating them with process death |

An ordinary upstream outage does not fail liveness or automatically cause a restart storm.
Unknown upstream reachability does not require synthetic AAA requests to obtain readiness.
Observed upstream failures remain visible as operation-specific degradation.
Expired or revoked required credentials make the affected operation unready.

During bounded drain, readiness is false while the control loop can remain live.
This differs from the current model, which withdraws every health view during draining.
Process-manager behavior must be tested with the new definition before deployment.

Log events use stable operation, endpoint, request, and generation identifiers.
They do not contain passwords, keys, raw credential references, or complete command arguments.
Returned server messages are untrusted text and do not bypass redaction policy.
Metrics avoid unbounded user names, session IDs, and credential identifiers as labels.

## Adapter Contracts

### Local IPC

Protobuf conversion validates domain values at ingress and preserves typed result distinctions at egress.
IPC carries delivery state and retry advice separately.
Caller deadlines and cancellation reach the handler and client request lease.
Disconnect cleanup does not imply that remote execution was undone.

The client owns a reusable channel with explicit connection and call bounds.
Unix socket ownership and permissions belong to the listener adapter.
TCP exposure remains loopback-only unless a separate authenticated remote API is designed.
The redesign does not turn the local service into a network-wide unauthenticated endpoint.

### Raw proxy

Downstream and upstream session identities remain distinct.
Mapping is scoped to each downstream connection and preserves packet order per session.
Transport protection is interpreted independently on each side.
Closing a downstream connection releases every associated lease and route.

The proxy preserves protocol conversation semantics instead of reducing every packet to a unary domain request.
It shares endpoint routing and replay classification with the client without sharing an inappropriate unary RPC lifecycle.

### Host enforcement

An adapter cannot allow a command solely because the server returned a pass status.
It must interpret effective attributes and demonstrate that it can apply required changes.
Service failure, protocol error, denial, and unsupported mandatory changes remain distinguishable.
Fail-open policy applies only to the explicitly configured unavailable-service case.

Argument truncation cannot silently authorize a different command from the one executed.
Byte limits apply to the encoded wire values, not only to Unicode character counts.
Unsupported arguments produce a clear local failure.

The Bash ABI must not unwind across C.
Its runtime must have an explicit post-fork policy and bounded IPC calls.
The wrapper's mutable-memory and process-interception limitations require a separate threat model before supported deployment.

## Required Contract Tests

| Scenario | Observable assertion |
| --- | --- |
| Truncated or surplus complete packet | Parser rejects it without panic |
| Cancel partial read or write | Route closes and no subsequent frame is misparsed |
| Idle connection retirement | Driver and socket close without peer cooperation |
| Slow conversation consumer | Unrelated sessions do not wait indefinitely |
| Source update during observation setup | Applied state converges without a second update |
| Source stream loss | Runtime resynchronizes before reporting current state |
| Equivalent CLI, SONiC, and YANG inputs | Normalization preserves equivalent canonical values and prepared behavior |
| Supported YANG field changes | Preparation preserves choices, defaults, units, ordering, identities, references, and constraints |
| Unsupported configured YANG feature | Explicit path-specific rejection occurs before publication, without exposing secrets |
| Credential rotation or failed preparation | The authoritative YANG snapshot and its credential references remain unchanged |
| Empty YANG server set | Acceptance obeys the applicable system authentication constraints |
| Valid YANG with invalid runtime TLS behavior | RFC 9887 behavior tests reject protocol violations and downgrade fallback |
| Old materialization finishes last | The newer authoritative YANG snapshot remains current |
| Reload during retry | One lease uses one captured endpoint set and policy |
| Admission limit falls during load | Existing work continues. New work respects the lowered global budget. |
| Unknown accounting outcome | Neither client routing nor IPC advice authorizes automatic replay |
| Mandatory authorization changes | Adapter applies them or denies the operation |
| Credential revocation during work | New work stops and active connections follow explicit revocation policy |
| Shutdown during provider resolution | No candidate publishes after shutdown starts |
| Embedded runtime shutdown | No process signal interception and no owned task remains unaccounted for |

These tests are release criteria for the relevant migration stages.
They supplement existing RFC examples, serialization tests, transport mocks, and process smoke tests.