# Transition Plain TACACS+ Clients to TACACS+ over TLS

This guide is for hosts that already use local TACACS+ clients, such as
[`pam_tacplus`](https://github.com/kravietz/pam_tacplus) or
[`audisp-tacplus`](https://github.com/daveolson53/audisp-tacplus). These hosts need to
move the network path to TACACS+ over TLS.

Those clients speak classic TACACS+ over TCP. `tacacsrs-agentd` can run on the
same host as a local TACACS+ proxy. It accepts the existing client traffic on
loopback, and opens protected upstream connections to TACACS+ servers.

```text
pam_tacplus / audisp-tacplus
        |
        |  TACACS+ over loopback TCP
        v
  tacacsrs-agentd --service-mode tacacs-proxy
        |
        |  TACACS+ over TLS 1.3
        v
  upstream TACACS+ servers
```

## When to Use This

Use this transition path when:

- Existing consumers are hard-wired to `pam_tacplus`, `audisp-tacplus`, or another client that already emits TACACS+ packets.
- You want to avoid changing PAM or auditd integration code during the TLS cutover.
- You can install and run `tacacsrs-agentd` on the same host as the legacy client.
- The local host boundary is acceptable for the temporary plain TACACS+ hop.

Do not use this as proof that the legacy client itself supports TLS. The legacy
client still speaks plain TACACS+ to localhost. The TLS security boundary starts
at `tacacsrs-agentd` and covers the upstream network path.

## What Changes

Move these responsibilities from each legacy client into `tacacsrs-agentd`:

| Concern | Before | After |
|---------|--------|-------|
| Upstream server list | Repeated `server=` entries in PAM or audisp configuration | `--server-addr` flags or `--config` in `tacacsrs-agentd` |
| Upstream transport security | None, because the client only speaks classic TACACS+ | `--use-tls`, mTLS, TLS PSK-DHE, or TLS PSK-only in `tacacsrs-agentd` |
| Failover | Client-specific server-list behavior | Ordered upstream failover in `tacacsrs-agentd` |
| Local client target | Remote TACACS+ server | Loopback TACACS+ proxy endpoint |

Keep these in the legacy client configuration:

- PAM stack placement and control flags.
- TACACS+ `service`, `protocol`, `login`, timeout, and accounting options that describe the local request.
- The downstream TACACS+ shared secret, unless the client and server are configured to use the TACACS+ unencrypted flag.

## Shared Secret Compatibility

The downstream client hop has its own TACACS+ obfuscation policy and does not follow the selected upstream server:

- Outside SONiC mode, keep the legacy client `secret=` value aligned with `tacacsrs-agentd --proxy-shared-secret`.
- In SONiC mode, configure the local loopback proxy row with the legacy client secret. The daemon filters that self-targeting row from the upstream set and uses its resolved `passkey` for downstream obfuscation.
- If neither source provides a downstream secret, make sure that the legacy client can send TACACS+ packets with the unencrypted flag.
- Upstream servers can use different classic shared secrets or TLS credentials. Failover does not change the local client secret.

TLS protects the upstream connection, but it does not replace the downstream
TACACS+ packet format expected by `pam_tacplus` or `audisp-tacplus`.

## Start the Local Proxy

Use a loopback TCP endpoint for `pam_tacplus` and `audisp-tacplus` because these
clients are normal TACACS+ TCP clients. Port `9049` is useful for testing because
it does not require privileged bind rights. If the legacy client cannot be
pointed at a non-standard port and the daemon has the required permissions,
use `127.0.0.1:49`.

PAP places the password in the TACACS+ Authentication START body. The proxy and
typed `AuthenticatePap` RPC permit PAP over the operator-configured upstream
transport for interoperability, but classic TACACS+ obfuscation is not
confidentiality. Use TLS 1.3 upstream and restrict the local proxy endpoint to
the host. The proxy can multiplex multiple downstream TACACS+ session IDs on
one local connection while preserving each authentication conversation's
sequence order.

### TLS Server Authentication

```bash
# Load this value from the host's secret manager.
TACACS_SHARED_SECRET='replace-with-secret-from-secret-store'

sudo tacacsrs-agentd \
    --server-addr tacacs1.example.com:449 \
    --server-addr tacacs2.example.com:449 \
    --service-mode tacacs-proxy \
    --proxy-endpoint 127.0.0.1:9049 \
    --shared-secret "$TACACS_SHARED_SECRET" \
    --use-tls \
    -vv
```

### TLS mTLS

```bash
# Load this value from the host's secret manager.
TACACS_SHARED_SECRET='replace-with-secret-from-secret-store'

sudo tacacsrs-agentd \
    --server-addr tacacs1.example.com:449 \
    --server-addr tacacs2.example.com:449 \
    --service-mode tacacs-proxy \
    --proxy-endpoint 127.0.0.1:9049 \
    --shared-secret "$TACACS_SHARED_SECRET" \
    --use-tls \
    --client-certificate /etc/tacacs/client.crt.pem \
    --client-key /etc/tacacs/client.key.pem \
    -vv
```

### TLS PSK-DHE

TLS PSK support requires a build with the `psk` feature. PSK-DHE is the preferred
PSK mode because it adds ephemeral key exchange. If no PSK key-exchange mode is
specified, `tacacsrs-agentd` defaults to PSK-DHE with the preferred group order
`secp384r1,secp256r1`.

```bash
# Load these values from the host's secret manager.
TACACS_SHARED_SECRET='replace-with-secret-from-secret-store'
TACACS_TLS_PSK='replace-with-tls-psk-from-secret-store'

sudo tacacsrs-agentd \
    --server-addr tacacs1.example.com:449 \
    --server-addr tacacs2.example.com:449 \
    --service-mode tacacs-proxy \
    --proxy-endpoint 127.0.0.1:9049 \
    --shared-secret "$TACACS_SHARED_SECRET" \
    --use-tls \
    --psk-identity host01@example.com \
    --psk-key "$TACACS_TLS_PSK" \
    --psk-key-exchange-groups secp384r1,secp256r1 \
    -vv
```

### TLS PSK-only

Use PSK-only only for interoperability with a peer that cannot negotiate
PSK-DHE. PSK-only cannot be combined with `--psk-key-exchange-groups`.

```bash
# Load these values from the host's secret manager.
TACACS_SHARED_SECRET='replace-with-secret-from-secret-store'
TACACS_TLS_PSK='replace-with-tls-psk-from-secret-store'

sudo tacacsrs-agentd \
    --server-addr legacy-tacacs.example.com:449 \
    --service-mode tacacs-proxy \
    --proxy-endpoint 127.0.0.1:9049 \
    --shared-secret "$TACACS_SHARED_SECRET" \
    --use-tls \
    --psk-identity host01@example.com \
    --psk-key "$TACACS_TLS_PSK" \
    --psk-key-exchange psk-only \
    -vv
```

## Repoint `pam_tacplus`

Change only the TACACS+ server target first. Keep the PAM control flow and the
request-shaping options that already work in the environment.

Before:

```text
auth    required pam_tacplus.so server=tacacs1.example.com:49 secret=<existing-shared-secret> login=pap
account required pam_tacplus.so server=tacacs1.example.com:49 secret=<existing-shared-secret> service=shell protocol=ssh
session required pam_tacplus.so server=tacacs1.example.com:49 secret=<existing-shared-secret> service=shell protocol=ssh
```

After:

```text
auth    required pam_tacplus.so server=127.0.0.1:9049 secret=<existing-shared-secret> login=pap
account required pam_tacplus.so server=127.0.0.1:9049 secret=<existing-shared-secret> service=shell protocol=ssh
session required pam_tacplus.so server=127.0.0.1:9049 secret=<existing-shared-secret> service=shell protocol=ssh
```

If the existing PAM configuration repeats several `server=` values for failover,
replace them with the one local proxy endpoint. Put the ordered upstream list in
`tacacsrs-agentd` instead.

For validation, use the same PAM test tool and PAM service file already used for
local changes. `pamtester` is useful for proving authenticate, account, open
session, and close session behavior before editing production PAM services.

## Repoint `audisp-tacplus`

`audisp-tacplus` uses a TACACS+ accounting configuration with options derived
from `pam_tacplus`. Keep the auditd plugin wiring and audit rules unchanged, and
move only the TACACS+ server target to the local proxy.

Before:

```text
server=tacacs1.example.com:49
secret=<existing-shared-secret>
service=shell
protocol=ssh
```

After:

```text
server=127.0.0.1:9049
secret=<existing-shared-secret>
service=shell
protocol=ssh
```

Then restart or reload auditd/audisp using the operating-system procedure for the
host. Validate by producing a known audited command event, then make sure that
the upstream TACACS+ server receives the accounting record through `tacacsrs-agentd`.

## Rollout Plan

1. Inventory every `pam_tacplus` and `audisp-tacplus` configuration file on the host. Record `server=`, `secret=`, `service`, `protocol`, `login`, timeout, and any `acct_all` use.
2. Deploy `tacacsrs-agentd` in proxy-only mode on a loopback test port such as `127.0.0.1:9049`.
3. Configure the upstream TLS mode that matches the TACACS+ server: server-auth TLS, mTLS, PSK-DHE, or PSK-only.
4. Test with a non-production PAM service or a controlled auditd event.
5. Repoint one production consumer at a time to the local proxy endpoint.
6. After confidence is established, remove direct outbound access from the host to the old plain TACACS+ server path. Only `tacacsrs-agentd` can then reach upstream TACACS+ servers.

## Behavioral Differences

- `acct_all` fan-out is not the same as agent failover. Proxy mode sends each downstream connection to one selected upstream server. If accounting must be written to multiple collectors, plan a separate fan-out path.
- `pam_tacplus` records the successful authentication server for later account/session phases. After the cutover, that server is always the local proxy. Upstream server choice is owned by `tacacsrs-agentd`.
- Debug logging in these legacy clients can include passwords or secrets. Use debug briefly, collect logs carefully, and disable it after validation.
- Local loopback TACACS+ is still plain TACACS+. Bind the proxy to loopback. Avoid exposing the proxy endpoint on non-loopback interfaces. Restrict host access to the process and configuration files that need it.

## Rollback

Keep a copy of the previous PAM and audisp configuration. Roll back by restoring
the previous remote `server=` entries. Alternatively, leave the clients pointed
at the local proxy, and start `tacacsrs-agentd` against the old plain upstream
server without `--use-tls`. The second option keeps the local configuration
stable while isolating the rollback to the daemon command line or service unit.
