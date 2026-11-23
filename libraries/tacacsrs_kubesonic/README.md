# tacacsrs-kubesonic

This crate supplies the native KubeSONiC profile for `tacacsrs-agentd`. ConfigDB supplies upstream servers. Mounted files supply the mTLS identity and CA trust. The profile does not use a Kubernetes API client or require new ConfigDB tables.

Start the daemon with `tacacsrs-agentd --kubesonic`. Configure runtime behavior through `TACACSD_<AREA>_<SETTING>` variables. Other runtime flags and configuration files conflict with this profile. Existing daemon modes keep their interfaces.

## Configuration ownership

The environment adapter creates canonical `LocalServices` and `RuntimePolicy` values. It also creates typed source, credential, and process inputs. It does not construct CLI arguments or maintain another server configuration model.

The daemon registers this profile through its [source registry](../../executables/tacacsrs_agentd/src/source_registry.rs). The profile calls `components`, which returns the components of this crate for the [agent host](../tacacsrs_agent/README.md#component-host):

- `KubeSonicSource` shares the datastore, the mounted credential provider, and the local services. It does not change external state. The datastore owns Redis observation, and the credential provider owns file observation.
- `RegistrationComponent` adds the loopback registrar as a `HostedService`. `components` adds it only when registration is enabled. The registrar waits for its `RegistrationReadiness` health group before it registers. The component adds the `application-readiness` member to that group, so the registrar waits until the agent is ready. If the upstream watchdog is enabled, the first registration also waits for a successful probe. A later readiness loss does not remove a registered row. The component also adds the `kubesonic-loopback-registration` member to the `component` health group. This check is healthy while the loopback row has the port and priority of the local proxy. It is degraded while the registrar starts or waits for readiness. It is unhealthy after a Redis error, or when another writer owns a loopback row with a different Redis type, port, or priority. The registrar does not change a row that another writer owns. The health registry of the host reports the check in `AgentHealth.Details`, so the gRPC handler does not need a list of components.

The read-only datastore loads only `TACPLUS_SERVER|*`. It reads `tcp_port` (default `49`) and `priority` (default `1`, range `1..=64`). Higher priorities come first. Endpoint text breaks ties. Other row fields do not configure this profile.

The KubeSONiC profile excludes loopback IPv4, IPv6, IPv4-mapped loopbacks, and localhost names on every port. This discovery rule preserves the addon behavior. The [shared listener check](../tacacsrs_config/src/local_services.rs) compares each destination with the bound proxy address and port. Other profiles can use a separate loopback server on another port. Runtime guards also inspect resolved destinations and the connected peer.

Upstream connections require TLS 1.3, a client identity, and server certificate verification.

Environment values are startup inputs. Changes require a process restart. Server rows and mounted credential contents remain live inputs.

## Environment

Names use uppercase words and underscores. Booleans accept only `true` and `false`. Numbers use unsigned decimal notation, except socket permissions, which use octal notation. Unknown `TACACSD_` names, empty supplied values, and invalid combinations stop startup. The profile ignores environment variables outside that namespace. Errors do not echo environment values.

### Source and upstreams

| Variable | Default | Meaning |
| --- | --- | --- |
| `TACACSD_CONFIGDB_SOCKET` | `/var/run/redis/redis.sock` | Redis Unix socket. |
| `TACACSD_CONFIGDB_DATABASE` | `4` | Snapshot and notification database. |
| `TACACSD_CONFIGDB_CONNECT_TIMEOUT_SECONDS` | `5` | Redis connection budget. |
| `TACACSD_CONFIGDB_COMMAND_TIMEOUT_SECONDS` | `5` | Redis command budget. |
| `TACACSD_CONFIGDB_EMPTY_SERVER_POLICY` | `retain` | `retain` or `clear`. |
| `TACACSD_UPSTREAM_CONNECT_TIMEOUT_SECONDS` | `5` | Per-server timeout, `1..=65535`. |
| `TACACSD_UPSTREAM_SINGLE_CONNECTION` | `true` | Persistent single-connection mode. |
| `TACACSD_CONFIGDB_WATCH_DEBOUNCE_MILLISECONDS` | `500` | Notification quiet period. |
| `TACACSD_CONFIGDB_WATCH_MAX_DELAY_MILLISECONDS` | `2000` | Maximum burst delay. |
| `TACACSD_CONFIGDB_WATCH_RETRY_INTERVAL_SECONDS` | `5` | Rejected-read retry interval. |
| `TACACSD_CONFIGDB_WATCH_RECONCILE_INTERVAL_SECONDS` | `60` | Full-read interval without notifications. |
| `TACACSD_CONFIG_RETRY_INITIAL_MILLISECONDS` | `250` | Initial native observation recovery delay. |
| `TACACSD_CONFIG_RETRY_MAX_MILLISECONDS` | `30000` | Maximum native observation recovery delay. |

Durations must be positive and fit the platform clock. The initial retry cannot exceed its maximum. The debounce cannot exceed the maximum burst delay. One atomic Redis snapshot accepts at most 4096 rows.

### Mounted credentials

| Variable | Default | Meaning |
| --- | --- | --- |
| `TACACSD_TLS_CLIENT_CERTIFICATE` | `/run/certificates/kubelet/pki/kubelet-client-current.pem` | Watched absolute PEM or DER certificate path. |
| `TACACSD_TLS_CLIENT_KEY` | The certificate path | Absolute PEM or DER private-key path. |
| `TACACSD_TLS_CA_FILE` | `/etc/ssl/certs/ca-certificates.crt` | Watched PEM CA bundle. |
| `TACACSD_TLS_CA_DIRECTORY` | `/etc/ssl/certs` | OpenSSL-style hashed certificate directory. |
| `TACACSD_TLS_WATCH_DEBOUNCE_MILLISECONDS` | `200` | Credential notification delay. |
| `TACACSD_TLS_WATCH_RECONCILE_INTERVAL_SECONDS` | `60` | Credential reconciliation interval. |
| `TACACSD_TLS_MAX_IDENTITY_BYTES` | `1048576` | Maximum bytes per identity file. |
| `TACACSD_TLS_MAX_CA_FILE_BYTES` | `4194304` | Maximum bytes per CA file. |
| `TACACSD_TLS_MAX_TRUST_BYTES` | `16777216` | Maximum distinct DER bytes in the CA set. |
| `TACACSD_TLS_MAX_DIRECTORY_ENTRIES` | `4096` | Maximum trust-directory entries. |
| `TACACSD_TLS_MAX_CERTIFICATES` | `4096` | Maximum distinct CA certificates. |

Paths must be absolute. Read limits must be positive. The certificate and key can share one kubelet PEM file.

The credential provider monitors the client certificate, private key, CA bundle, and hashed CA directory throughout runtime. Parent-directory observation detects in-place writes, file replacement, and identity symlink rotation. Credential changes trigger native refresh independently of ConfigDB notifications. Periodic reconciliation recovers missed notifications.

For `TACACSD_TLS_CA_FILE` and `TACACSD_TLS_CLIENT_CERTIFICATE`, changing file contents triggers reload without a daemon restart. Changing the environment paths requires a restart.

The provider reads the CA bundle and hashed files such as `012abcde.0`. It does not trust arbitrary un-hashed PEM files from the directory. It deduplicates certificates before native preparation. An explicitly configured CA file or CA directory must exist on disk, while an unset default path can be absent when the other trust source supplies at least one valid certificate. Missing explicit paths, invalid PEM inputs, and empty combined trust sets fail closed.

Canonical snapshots contain opaque credential references, not private-key bytes. The provider authorizes only those references and the configured paths. Blocking work retains its native work lease through result consumption or disposal.

Rotation changes new upstream handshakes. Existing sessions follow native retirement and drain rules. Invalid replacements retain permitted known-good material without extending certificate validity or credential grace periods.

### Certificate revocation

The optional `TACACSD_REVOCATION_` variables map to the global `tacacsrs:certificate-revocation` container. The profile copies that container into every ConfigDB snapshot. When no `TACACSD_REVOCATION_` variable is set, the snapshots contain no container, and revocation stays disabled.

| Variable | Canonical default | Meaning |
| --- | --- | --- |
| `TACACSD_REVOCATION_ENFORCEMENT` | `disabled` | `disabled`, `hard-fail`, `soft-fail`, or `warn-only`. |
| `TACACSD_REVOCATION_SOFT_FAIL_GRACE_SECONDS` | `86400` | Time after `nextUpdate` during which `soft-fail` accepts a validated CRL. |
| `TACACSD_REVOCATION_ALLOWED_DISTRIBUTION_POINTS` | Absent | Whitespace-separated `http://` URL patterns that the agent can fetch CRLs from. |
| `TACACSD_REVOCATION_PREFETCH_DISTRIBUTION_POINTS` | Absent | Whitespace-separated exact CRL URLs that the agent fetches at startup and keeps fresh. |
| `TACACSD_REVOCATION_ALLOW_PRIVATE_ADDRESSES` | `true` | Allows CRL fetches to RFC 1918 and unique local addresses. |
| `TACACSD_REVOCATION_FETCH_TIMEOUT_SECONDS` | `5` | Maximum time for one CRL fetch. |
| `TACACSD_REVOCATION_MAX_CRL_BYTES` | `16777216` | Maximum size of one fetched CRL. |
| `TACACSD_REVOCATION_CACHE_DIRECTORY` | Absent | Absolute directory for the persistent CRL cache. |

Canonical validation applies to these values. An enabled enforcement requires at least one allowed pattern. Each prefetch URL must match an allowed pattern. An empty list, a relative cache directory, an unknown enforcement value, or an unknown `TACACSD_REVOCATION_` name stops startup. See [certificate revocation](../../docs/yang-config-guide.md#certificate-revocation) for the pattern syntax and the enforcement modes.

```bash
TACACSD_REVOCATION_ENFORCEMENT=soft-fail
TACACSD_REVOCATION_ALLOWED_DISTRIBUTION_POINTS="http://**.pki.core.windows.net/** http://crl.microsoft.com/**"
TACACSD_REVOCATION_PREFETCH_DISTRIBUTION_POINTS=http://primary-cdn.pki.core.windows.net/eastus2/crls/ccmeeastus2pki/ccmeeastus2ica01/22/current.crl
TACACSD_REVOCATION_CACHE_DIRECTORY=/var/cache/tacacsrs/crl
```

### Local services and process

| Variable | Default |
| --- | --- |
| `TACACSD_SERVICES_CLIENT_API_ENABLED` | `true` |
| `TACACSD_SERVICES_CLIENT_API_ENDPOINT` | `/run/tacacs/tacacs.sock` |
| `TACACSD_SERVICES_TACACS_PROXY_ENABLED` | `true` |
| `TACACSD_SERVICES_TACACS_PROXY_ENDPOINT` | `127.0.0.1:49` |
| `TACACSD_SERVICES_UNIX_SOCKET_MODE` | `0666` |
| `TACACSD_SERVICES_MAX_CONNECTIONS` | `64` |
| `TACACSD_SERVICES_MAX_CLIENT_API_STREAMS` | `64` |
| `TACACSD_SERVICES_CONNECTION_LIFETIME_SECONDS` | `300` |
| `TACACSD_PROCESS_WORKER_THREADS` | `1` |
| `TACACSD_PROCESS_HOST_INTEGRATION` | `none` |
| `TACACSD_PROCESS_STATISTICS_FILE` | Absent |
| `TACACSD_PROCESS_UPSTREAM_WATCHDOG_INTERVAL_SECONDS` | Absent (watchdog disabled) |
| `TACACSD_LOG_FILTER` | `info` |
| `TACACSD_LOG_STYLE` | `auto` |

Canonical validation applies to endpoints, service selection, and limits. At least one service must remain enabled. An explicitly configured proxy endpoint conflicts with a disabled proxy. Socket permissions accept `0000..0777`. Worker count must be positive.

Host integration accepts `none`, `auto`, or `systemd`. Explicit systemd integration retains its notification-socket and helper requirements. The optional statistics path must be absolute and distinct from protected inputs and listeners.

Logging uses the existing filter syntax, including per-target filters. Style accepts `auto`, `always`, or `never`. KubeSONiC logging does not read `RUST_LOG` or `RUST_LOG_STYLE`.

### Native runtime policy

Each canonical policy path maps to `TACACSD_POLICY_<PATH>`. Replace hyphens and path separators with underscores.

| Variable | Canonical default |
| --- | --- |
| `TACACSD_POLICY_SHUTDOWN_TIMEOUT_SECONDS` | `30` |
| `TACACSD_POLICY_SOURCE_STALE_TIMEOUT_SECONDS` | `300` |
| `TACACSD_POLICY_CREDENTIAL_STALE_TIMEOUT_SECONDS` | `300` |
| `TACACSD_POLICY_CREDENTIAL_REFRESH_INTERVAL_SECONDS` | `60` |
| `TACACSD_POLICY_FAILOVER_RECOVERY_INTERVAL_SECONDS` | `30` |
| `TACACSD_POLICY_CLIENT_API_FAILOVER_STRATEGY` | `deferred-failover` |
| `TACACSD_POLICY_TACACS_PROXY_FAILOVER_STRATEGY` | `deferred-failover` |
| `TACACSD_POLICY_CONNECT_PREFLIGHT` | `disabled` |
| `TACACSD_POLICY_CANDIDATE_PREPARATION_TIMEOUT_SECONDS` | `30` |
| `TACACSD_POLICY_CANDIDATE_PREPARATION_MAX_RESOLUTION_REQUESTS` | `256` |
| `TACACSD_POLICY_CANDIDATE_PREPARATION_MAX_RETAINED_MATERIAL_BYTES` | `67108864` |

The `TACACSD_POLICY_AUTHENTICATION_`, `TACACSD_POLICY_AUTHORIZATION_`, and `TACACSD_POLICY_ACCOUNTING_` families each support these suffixes:

| Suffix | Authentication default | Authorization and accounting default |
| --- | --- | --- |
| `REQUEST_TIMEOUT_SECONDS` | `30` | `30` |
| `MAX_BODY_LENGTH` | `4096` | `16384` |
| `MAX_CONCURRENT_REQUESTS` | `64` | `64` |

Limits must be positive. Body length cannot exceed the protocol maximum. Failover strategy accepts `deferred-failover` or `ordered-safe-retry`. Connect preflight accepts `disabled` or `accounting-watchdog`. Canonical validators and generated types own defaults and ranges.

## Empty lists and recovery

The default `retain` policy preserves the last successfully published canonical list after a valid empty read. It does not retain a rejected replacement. Retention survives observation reconnects but does not survive process restart. The typed health diagnostic `RetainedAfterClear` identifies this state.

The `clear` policy publishes an empty catalog and withdraws readiness. The process and listeners remain available for recovery. Without a previously published list, retain mode waits for usable configuration.

A confirmed empty read can recover source freshness in retain mode. Redis outages and malformed rows still use the configured source-stale budget. Credential refresh does not reset that budget. Credential expiry remains active during retention.

Unavailable startup dependencies cause retries rather than process restarts. Liveness remains independent of upstream availability. Readiness requires a published eligible server. Readiness also requires a successful upstream request only when the upstream watchdog is enabled.

## Optional loopback registration

| Variable | Default | Meaning |
| --- | --- | --- |
| `TACACSD_LOOPBACK_REGISTRATION_ENABLED` | `false` | Enable the separate ConfigDB writer. |
| `TACACSD_LOOPBACK_PRIORITY` | `64` | Registration priority, `1..=64`. |
| `TACACSD_LOOPBACK_RETRY_INTERVAL_SECONDS` | `5` | Registration and repair retry interval. |

Registration requires an enabled TCP proxy on `127.0.0.1` with a nonzero port. It registers the configured proxy port. Disabled registration performs no loopback mutations.

CAUTION: If unconditional startup loopback removal is unacceptable, keep registration disabled. Enabled registration preserves the previous addon startup policy.

After local readiness succeeds, an atomic comparison creates the row only while it remains absent. Cleanup removes only an owned row with exactly the registered fields. External edits remain intact. Missing rows can be repaired after readiness succeeds.

Upstream errors and clear-list readiness changes do not erase an existing row. Shutdown attempts owned-row cleanup within the shared host deadline. The runtime can abort cleanup at that deadline. An interrupted or uncertain Redis write can leave a row for the next opt-in startup cleanup.

## Validation

Run the unit tests:

```bash
cargo test -p tacacsrs-kubesonic
```

With `redis-server` installed, run the isolated Redis tests:

```bash
cargo test -p tacacsrs-kubesonic --test redis -- --include-ignored
```

The tests create their own Unix-socket Redis processes. They do not use host ConfigDB.
