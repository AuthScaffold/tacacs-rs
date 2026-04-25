# tacacsrs-agentd

`tacacsrs-agentd` is the central TACACS+ service daemon. It maintains upstream TACACS+ connections and exposes a local IPC endpoint for clients such as `tacon`.

For full deployment and failover guidance, see [../../docs/tacacsrs-agentd.md](../../docs/tacacsrs-agentd.md).

## TLS Client Certificates and Keys

Use `--client-certificate` and `--client-key` with `--use-tls` when the upstream TACACS+ server requires the daemon to present a TLS client identity.

- Provide both flags together.
- Both files may be PEM or DER. PEM input is detected at runtime and normalized to DER internally before the daemon builds its runtime connection settings.
- Windows "export with private key" workflows commonly produce PKCS#12 (`.pfx` / `.p12`) bundles. Those container formats are not accepted by these flags; provide PEM or DER certificate/key material instead.
- This PEM-or-DER behavior applies only to the CLI flags. If upstream TLS material comes from `--config`, the YANG-backed `tacacsrs-config` path remains DER-only.

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
