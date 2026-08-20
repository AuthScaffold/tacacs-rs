# tacacsrs-agentd

`tacacsrs-agentd` is the central TACACS+ service daemon. It maintains upstream TACACS+ connections and exposes a local IPC endpoint for clients such as `tacon`.

For full deployment and failover guidance, see [../../docs/tacacsrs-agentd.md](../../docs/tacacsrs-agentd.md).

## Health and Host Integration

When the Client API is enabled, its existing endpoint also serves standard `grpc.health.v1.Health` names for startup, liveness, readiness, the overall empty name, and `tacacsrs.agent.v1.TacacsAgent`. Use the separate `tacacsrs-agent-health` executable:

```bash
tacacsrs-agent-health \
    --endpoint /run/tacacs/tacacs.sock \
    --check readiness \
    --timeout-seconds 2
```

Use `--host-integration none` in containers. `auto` selects systemd only when `NOTIFY_SOCKET` is present. Explicit `systemd` requires the notification socket and helper, sends `READY=1` once, and sends `STOPPING=1` before listener drain.

The daemon supervises SONiC ConfigDB startup and notification subscriptions. It can bind listeners before Redis exists, and it retries with capped jittered backoff. It applies valid snapshots without a restart. It keeps the previous known-good configuration after invalid reloads or subscription outages.

Use `--runtime-policy <FILE>` to load live failover strategies and request
limits. The daemon keeps the last-known-good policy after an invalid update.

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

- Provide both flags together.
- Both files can be PEM or DER. The daemon detects PEM input and converts it to DER before it builds the runtime connection configuration.
- Windows "export with private key" workflows commonly produce PKCS#12 (`.pfx` / `.p12`) bundles. These flags do not accept that container format. Provide PEM or DER certificate and private-key material instead.
- This PEM-or-DER behavior applies only to the CLI flags. If upstream TLS material comes from `--config`, the YANG-backed `tacacsrs-config` path remains DER-only.

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
