# tacacsrs-agentd

`tacacsrs-agentd` is the central TACACS+ service daemon. It maintains upstream TACACS+ connections and exposes a local IPC endpoint for clients such as `tacon`.

For full deployment and failover guidance, see [../../docs/tacacsrs-agentd.md](../../docs/tacacsrs-agentd.md).

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
    --listen-endpoint /run/tacacs.sock
```

DER files are also supported:

```bash
tacacsrs-agentd \
    --server-addr tacacs1.example.com:449 \
    --server-addr tacacs2.example.com:449 \
    --use-tls \
    --client-certificate /etc/tacacs/client.crt.der \
    --client-key /etc/tacacs/client.key.der \
    --listen-endpoint /run/tacacs.sock
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
    --listen-endpoint /run/tacacs.sock
```

For PSK-only interoperability mode:

```bash
tacacsrs-agentd \
    --server-addr legacy-tacacs.example.com:449 \
    --use-tls \
    --psk-identity client@example.com \
    --psk-key "$TACACS_TLS_PSK" \
    --psk-key-exchange psk-only \
    --listen-endpoint /run/tacacs.sock
```
