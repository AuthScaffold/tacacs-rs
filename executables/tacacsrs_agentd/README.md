# tacacsrs-agentd

`tacacsrs-agentd` is the central TACACS+ service daemon. It maintains upstream TACACS+ connections and exposes a local IPC endpoint for clients such as `tacon`.

For full deployment and failover guidance, see [../../docs/tacacsrs-agentd.md](../../docs/tacacsrs-agentd.md).

## Health and Host Integration

When the Client API is enabled, its existing endpoint also serves standard `grpc.health.v1.Health` names for startup, liveness, readiness, the overall empty name, and `tacacsrs.agent.v1.TacacsAgent`. Use the packaged probe:

```bash
tacacsrs-agent-health \
    --endpoint /run/tacacs/tacacs.sock \
    --check readiness \
    --timeout-seconds 2
```

Use `--host-integration none` in containers. `auto` selects systemd only when `NOTIFY_SOCKET` is present. Explicit `systemd` requires the notification socket and helper, sends `READY=1` once, and sends `STOPPING=1` before listener drain.

SONiC ConfigDB startup and notification subscriptions are supervised. The daemon may bind listeners before Redis exists, retries with capped jittered backoff, applies valid snapshots without restarting, and retains the previous known-good configuration after invalid reloads or subscription outages.

## Runtime Service Modes

Use `--service-mode client-api`, `--service-mode tacacs-proxy`, or
`--service-mode both` to choose which local runtime services are hosted. If the
flag is omitted, the daemon runs `client-api` by default and runs `both` when
`--proxy-endpoint` is supplied. Proxy modes require `--proxy-endpoint`.

When the raw TACACS+ proxy listens on a TCP endpoint, do not configure that same
endpoint as an upstream TACACS+ server. Doing so would cause the proxy to send
client traffic back into itself and can create a packet storm. To guard against
this, the daemon removes upstream entries whose address and port parse or resolve
to the local TCP proxy endpoint, including loopback IPv4, loopback IPv6, and
hostnames such as `localhost`.

If one or more local proxy endpoint rows are removed this way, the raw proxy
uses the highest-priority matching row's resolved shared secret for downstream
TACACS+ obfuscation. This includes secrets inherited from global configuration.
If that highest-priority local proxy row has no shared secret, local clients are
expected to send unobfuscated TACACS+ packets to the proxy even when lower-
priority local rows or real upstream servers have shared secrets.

Outside SONiC mode, use `--proxy-shared-secret` with `--proxy-endpoint` when
raw TACACS+ proxy clients send obfuscated packets to the proxy. If the flag is
omitted, local proxy clients are expected to send unobfuscated packets. A
filtered local proxy endpoint row takes precedence over this CLI fallback if
both are present.

## TLS Client Certificates and Keys

Use `--client-certificate` and `--client-key` with `--use-tls` when the upstream TACACS+ server requires the daemon to present a TLS client identity.

- Provide both flags together.
- Both files may be PEM or DER. PEM input is detected at runtime and normalized to DER internally before the daemon builds its runtime connection settings.
- Windows "export with private key" workflows commonly produce PKCS#12 (`.pfx` / `.p12`) bundles. Those container formats are not accepted by these flags; provide PEM or DER certificate/key material instead.
- This PEM-or-DER behavior applies only to the CLI flags. If upstream TLS material comes from `--config`, the YANG-backed `tacacsrs-config` path remains DER-only.

## TLS 1.3 PSK

When built with the `psk` feature, use `--psk-identity` and `--psk-key` with
`--use-tls` to configure TLS 1.3 PSK upstream connections. The default
key-exchange mode is PSK-DHE with the preferred group order
`secp384r1,secp256r1`.

Use `--psk-key-exchange-groups` to constrain the PSK-DHE groups offered in
ClientHello. Supplying groups implies PSK-DHE mode. Use
`--psk-key-exchange psk-only` only for interoperability with peers that cannot
negotiate PSK-DHE; PSK-only mode cannot be combined with
`--psk-key-exchange-groups`.

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

DER files are also supported:

```bash
tacacsrs-agentd \
    --server-addr tacacs1.example.com:449 \
    --server-addr tacacs2.example.com:449 \
    --use-tls \
    --client-certificate /etc/tacacs/client.crt.der \
    --client-key /etc/tacacs/client.key.der \
    --listen-endpoint /run/tacacs/tacacs.sock
```

TLS PSK-DHE uses the default group order unless groups are constrained:

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
