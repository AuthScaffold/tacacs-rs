# tacacsrs-kubesonic

This crate supplies the native KubeSONiC profile for `tacacsrs-agentd`. ConfigDB supplies upstream servers. Mounted files supply the mTLS identity and CA trust. The profile does not use a Kubernetes API client or require new ConfigDB tables.

Start the daemon with `tacacsrs-agentd --kubesonic`. Configure runtime behavior through `AAAAGENT_<AREA>_<SETTING>` variables. Other runtime flags and configuration files conflict with this profile. Existing daemon modes keep their interfaces.

## Configuration ownership

The environment adapter creates canonical `LocalServices` and `RuntimePolicy` values. It also creates typed source, credential, and process inputs. It does not construct CLI arguments or maintain another server configuration model.

The read-only datastore loads only `TACPLUS_SERVER|*`. It reads `tcp_port` (default `49`) and `priority` (default `1`, range `1..=64`). Higher priorities come first. Endpoint text breaks ties. Other row fields do not configure this profile.

The mapper excludes loopback IPv4, IPv6, IPv4-mapped loopbacks, and localhost names. The native runtime also guards resolved and connected destinations against the local proxy. Upstream connections require TLS 1.3, a client identity, and server certificate verification.

Environment values are startup inputs. Changes require a process restart. Server rows and mounted credential contents remain live inputs.

## Environment

Names use uppercase words and underscores. Booleans accept only `true` and `false`. Numbers use unsigned decimal notation, except socket permissions, which use octal notation. Unknown names, empty supplied values, and invalid combinations stop startup. Errors do not echo environment values.

### Source and upstreams

| Variable | Default | Meaning |
| --- | --- | --- |
| `AAAAGENT_CONFIGDB_SOCKET` | `/var/run/redis/redis.sock` | Redis Unix socket. |
| `AAAAGENT_CONFIGDB_DATABASE` | `4` | Snapshot and notification database. |
| `AAAAGENT_CONFIGDB_CONNECT_TIMEOUT_SECONDS` | `5` | Redis connection budget. |
| `AAAAGENT_CONFIGDB_COMMAND_TIMEOUT_SECONDS` | `5` | Redis command budget. |
| `AAAAGENT_CONFIGDB_EMPTY_SERVER_POLICY` | `retain` | `retain` or `clear`. |
| `AAAAGENT_UPSTREAM_CONNECT_TIMEOUT_SECONDS` | `5` | Per-server timeout, `1..=65535`. |
| `AAAAGENT_UPSTREAM_SINGLE_CONNECTION` | `true` | Persistent single-connection mode. |
| `AAAAGENT_CONFIGDB_WATCH_DEBOUNCE_MILLISECONDS` | `500` | Notification quiet period. |
| `AAAAGENT_CONFIGDB_WATCH_MAX_DELAY_MILLISECONDS` | `2000` | Maximum burst delay. |
| `AAAAGENT_CONFIGDB_WATCH_RETRY_INTERVAL_SECONDS` | `5` | Rejected-read retry interval. |
| `AAAAGENT_CONFIGDB_WATCH_RECONCILE_INTERVAL_SECONDS` | `60` | Full-read interval without notifications. |
| `AAAAGENT_CONFIG_RETRY_INITIAL_MILLISECONDS` | `250` | Initial native observation recovery delay. |
| `AAAAGENT_CONFIG_RETRY_MAX_MILLISECONDS` | `30000` | Maximum native observation recovery delay. |

Durations must be positive and fit the platform clock. The initial retry cannot exceed its maximum. The debounce cannot exceed the maximum burst delay. One atomic Redis snapshot accepts at most 4096 rows.

### Mounted credentials

| Variable | Default | Meaning |
| --- | --- | --- |
| `AAAAGENT_TLS_CLIENT_CERTIFICATE` | `/run/certificates/kubelet/pki/kubelet-client-current.pem` | Absolute PEM or DER certificate path. |
| `AAAAGENT_TLS_CLIENT_KEY` | The certificate path | Absolute PEM or DER private-key path. |
| `AAAAGENT_TLS_CA_FILE` | `/etc/ssl/certs/ca-certificates.crt` | PEM CA bundle. |
| `AAAAGENT_TLS_CA_DIRECTORY` | `/etc/ssl/certs` | OpenSSL-style hashed certificate directory. |
| `AAAAGENT_TLS_WATCH_DEBOUNCE_MILLISECONDS` | `200` | Credential notification delay. |
| `AAAAGENT_TLS_WATCH_RECONCILE_INTERVAL_SECONDS` | `60` | Credential reconciliation interval. |
| `AAAAGENT_TLS_MAX_IDENTITY_BYTES` | `1048576` | Maximum bytes per identity file. |
| `AAAAGENT_TLS_MAX_CA_FILE_BYTES` | `4194304` | Maximum bytes per CA file. |
| `AAAAGENT_TLS_MAX_TRUST_BYTES` | `16777216` | Maximum distinct DER bytes in the CA set. |
| `AAAAGENT_TLS_MAX_DIRECTORY_ENTRIES` | `4096` | Maximum trust-directory entries. |
| `AAAAGENT_TLS_MAX_CERTIFICATES` | `4096` | Maximum distinct CA certificates. |

Paths must be absolute. Read limits must be positive. The certificate and key can share one kubelet PEM file. Parent-directory observation detects file replacement and identity symlink rotation. Periodic reconciliation recovers missed notifications.

The provider reads the CA bundle and hashed files such as `012abcde.0`. It does not trust arbitrary un-hashed PEM files from the directory. It deduplicates certificates before native preparation. Missing or invalid configured trust fails closed.

Canonical snapshots contain opaque credential references, not private-key bytes. The provider authorizes only those references and the configured paths. Blocking work retains its native work lease through result consumption or disposal.

Rotation changes new upstream handshakes. Existing sessions follow native retirement and drain rules. Invalid replacements retain permitted known-good material without extending certificate validity or credential grace periods.

### Local services and process

| Variable | Default |
| --- | --- |
| `AAAAGENT_SERVICES_CLIENT_API_ENABLED` | `true` |
| `AAAAGENT_SERVICES_CLIENT_API_ENDPOINT` | `/run/tacacs/tacacs.sock` |
| `AAAAGENT_SERVICES_TACACS_PROXY_ENABLED` | `true` |
| `AAAAGENT_SERVICES_TACACS_PROXY_ENDPOINT` | `127.0.0.1:49` |
| `AAAAGENT_SERVICES_UNIX_SOCKET_MODE` | `0666` |
| `AAAAGENT_SERVICES_MAX_CONNECTIONS` | `64` |
| `AAAAGENT_SERVICES_MAX_CLIENT_API_STREAMS` | `64` |
| `AAAAGENT_SERVICES_CONNECTION_LIFETIME_SECONDS` | `300` |
| `AAAAGENT_PROCESS_WORKER_THREADS` | `1` |
| `AAAAGENT_PROCESS_HOST_INTEGRATION` | `none` |
| `AAAAGENT_PROCESS_STATISTICS_FILE` | Absent |
| `AAAAGENT_LOG_FILTER` | `info` |
| `AAAAGENT_LOG_STYLE` | `auto` |

Canonical validation applies to endpoints, service selection, and limits. At least one service must remain enabled. An explicitly configured proxy endpoint conflicts with a disabled proxy. Socket permissions accept `0000..0777`. Worker count must be positive.

Host integration accepts `none`, `auto`, or `systemd`. Explicit systemd integration retains its notification-socket and helper requirements. The optional statistics path must be absolute and distinct from protected inputs and listeners.

Logging uses the existing filter syntax, including per-target filters. Style accepts `auto`, `always`, or `never`. KubeSONiC logging does not read `RUST_LOG` or `RUST_LOG_STYLE`.

### Native runtime policy

Each canonical policy path maps to `AAAAGENT_POLICY_<PATH>`. Replace hyphens and path separators with underscores.

| Variable | Canonical default |
| --- | --- |
| `AAAAGENT_POLICY_SHUTDOWN_TIMEOUT_SECONDS` | `30` |
| `AAAAGENT_POLICY_SOURCE_STALE_TIMEOUT_SECONDS` | `300` |
| `AAAAGENT_POLICY_CREDENTIAL_STALE_TIMEOUT_SECONDS` | `300` |
| `AAAAGENT_POLICY_CREDENTIAL_REFRESH_INTERVAL_SECONDS` | `60` |
| `AAAAGENT_POLICY_FAILOVER_RECOVERY_INTERVAL_SECONDS` | `30` |
| `AAAAGENT_POLICY_CLIENT_API_FAILOVER_STRATEGY` | `deferred-failover` |
| `AAAAGENT_POLICY_TACACS_PROXY_FAILOVER_STRATEGY` | `deferred-failover` |
| `AAAAGENT_POLICY_CANDIDATE_PREPARATION_TIMEOUT_SECONDS` | `30` |
| `AAAAGENT_POLICY_CANDIDATE_PREPARATION_MAX_RESOLUTION_REQUESTS` | `256` |
| `AAAAGENT_POLICY_CANDIDATE_PREPARATION_MAX_RETAINED_MATERIAL_BYTES` | `67108864` |

The `AAAAGENT_POLICY_AUTHENTICATION_`, `AAAAGENT_POLICY_AUTHORIZATION_`, and `AAAAGENT_POLICY_ACCOUNTING_` families each support these suffixes:

| Suffix | Authentication default | Authorization and accounting default |
| --- | --- | --- |
| `REQUEST_TIMEOUT_SECONDS` | `30` | `30` |
| `MAX_BODY_LENGTH` | `4096` | `16384` |
| `MAX_CONCURRENT_REQUESTS` | `64` | `64` |

Limits must be positive. Body length cannot exceed the protocol maximum. Failover strategy accepts `deferred-failover` or `ordered-safe-retry`. Canonical validators and generated types own defaults and ranges.

## Empty lists and recovery

The default `retain` policy preserves the last successfully published canonical list after a valid empty read. It does not retain a rejected replacement. Retention survives observation reconnects but does not survive process restart. The typed health diagnostic `RetainedAfterClear` identifies this state.

The `clear` policy publishes an empty catalog and withdraws readiness. The process and listeners remain available for recovery. Without a previously published list, retain mode waits for usable configuration.

A confirmed empty read can recover source freshness in retain mode. Redis outages and malformed rows still use the configured source-stale budget. Credential refresh does not reset that budget. Credential expiry remains active during retention.

Unavailable startup dependencies cause retries rather than process restarts. Liveness remains independent of upstream availability. Readiness requires a published eligible server, not a successful upstream request.

## Optional loopback registration

| Variable | Default | Meaning |
| --- | --- | --- |
| `AAAAGENT_LOOPBACK_REGISTRATION_ENABLED` | `false` | Enable the separate ConfigDB writer. |
| `AAAAGENT_LOOPBACK_PRIORITY` | `64` | Registration priority, `1..=64`. |
| `AAAAGENT_LOOPBACK_RETRY_INTERVAL_SECONDS` | `5` | Registration and repair retry interval. |

Registration requires an enabled TCP proxy on `127.0.0.1` with a nonzero port. It registers the configured proxy port. Disabled registration performs no loopback mutations.

CAUTION: If unconditional startup loopback removal is unacceptable, keep registration disabled. Enabled registration preserves the previous addon startup policy.

After local readiness succeeds, an atomic comparison creates the row only while it remains absent. Cleanup removes only an owned row with exactly the registered fields. External edits remain intact. Missing rows can be repaired after readiness succeeds.

Upstream errors and clear-list readiness changes do not erase an existing row. Shutdown attempts owned-row cleanup within the shared host deadline. An interrupted or uncertain Redis write can leave a row for the next opt-in startup cleanup.

## Migration and validation

The old `AAAAGENT_REDIS_SOCKET`, `AAAAGENT_CLIENT_CERTIFICATE`, `AAAAGENT_CLIENT_KEY`, and `AAAAGENT_REGISTER_LOOPBACK` names are not aliases. Replace them with their grouped counterparts. Replace `SSL_CERT_FILE` and `SSL_CERT_DIR` with the namespaced CA inputs. Replace `RUST_LOG` and `RUST_LOG_STYLE` with the namespaced logging inputs.

Run the unit tests:

```bash
cargo test -p tacacsrs-kubesonic
```

With `redis-server` installed, run the isolated Redis tests:

```bash
cargo test -p tacacsrs-kubesonic --test redis -- --include-ignored
```

The tests create their own Unix-socket Redis processes. They do not use host ConfigDB.
