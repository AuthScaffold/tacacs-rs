# YANG Configuration Guide

`tacacsrs-config` provides TACACS+ configuration support using the RFC 7951 JSON encoding of the `ietf-system-tacacs-plus` YANG module. The crate owns parsing, generated model types, validation, local credential bundle enumeration, and helper APIs used by `tacon` and `tacacsrs-agentd`.

If you need to author, validate, or consume TACACS+ server configuration from JSON, use this guide.

## What the configuration crate provides

- Generated Rust types that mirror the expanded TACACS+ YANG tree.
- RFC 7951 JSON parsing into the generated TACACS+ model.
- Validation for required server data, unique addresses, TLS choice constraints, SNI requirements, key format identities, base64-encoded key material, and configuration-local credential references.
- Bundle enumeration helpers that inline local `client-credentials` and `server-credentials` references onto server entries.
- Secret-free inspection of central keystore and truststore references.
- A `TacacsPlusServerBuilder` for constructing valid server definitions in Rust.
- A project-owned TACACS+/TLS augmentation for TLS 1.3 PSK-DHE key exchange group selection.

Central references remain opaque in this crate. Parse and enumerate configuration first, then use `tacacsrs-credential-resolution` to build provider-neutral requests, validate resolved results, and materialize generated inline fields. Provider-specific retrieval remains a separate integration concern.

## Basic JSON shape

Both `tacon` and `tacacsrs-agentd` can load TACACS+ server definitions from an RFC 7951 JSON document:

```json
{
  "ietf-system-tacacs-plus:tacacs-plus": {
    "server": [
      {
        "name": "primary",
        "server-type": "authentication authorization accounting",
        "address": "192.0.2.2",
        "port": 49,
        "shared-secret": "example-shared-secret",
        "timeout": 10
      }
    ]
  }
}
```

Use `--config <file>` with `tacon` or `tacacsrs-agentd` to load the configuration.

## Local TCP binding

Linux applies the same local binding controls to plain TCP, certificate TLS, mTLS, and PSK TLS.
The canonical YANG server remains authoritative. Endpoint preparation does not require interfaces or routes to exist.
Each new connection reads current interfaces and addresses. Existing connections retain their original binding.

| Server leaf | Behavior |
| --- | --- |
| `source-ip` | Binds a concrete local IPv4 or IPv6 source address. |
| `source-interface` | Derives a usable address from this interface, as RFC 9950 specifies. It does not force egress. |
| `vrf-instance` | Selects a Linux VRF device and its routing table. |
| `tacacsrs:egress-interface` | Forces egress through this Linux device with `SO_BINDTODEVICE`. |
| `tacacsrs:binding-policy` | Selects `best-effort` or `strict`. The default is `best-effort`. |

The `source-ip` and `source-interface` leaves remain mutually exclusive.
An explicit source choice is independent of `tacacsrs:egress-interface`.
Without a source choice, the kernel selects an address for the destination family.
With `source-interface`, the client selects the lowest usable same-family address in numeric order.
The client excludes tentative addresses, deprecated addresses, and addresses that fail duplicate address detection.
It excludes IPv6 link-local addresses for non-link-local destinations.
The client prefers the local address, not the peer address, on point-to-point interfaces.

RFC `source-interface` can select a loopback address while traffic exits through another device.
It does not select a VRF implicitly.
In contrast, `tacacsrs:egress-interface` forces egress and lets Linux derive the VRF of that interface.
When both interface and VRF are explicit, the interface must belong to that VRF.
The same membership rule applies to RFC `source-interface` with an explicit VRF.
An existing device that is not a VRF, or an interface in another VRF, causes an error in both policies.
The client binds one device only. It never overwrites a VRF binding with an unchecked interface binding.

### Named management deployment

This example forces egress through `mgmt0`. The operator does not need its source IP.
The destination uses a numeric IP. DNS and a hostname are not required.
The example selects strict mode to prevent traffic from leaving through a different interface.

```json
{
  "ietf-system-tacacs-plus:tacacs-plus": {
    "server": [{
      "name": "management",
      "server-type": "authentication authorization accounting",
      "address": "192.0.2.49",
      "port": 300,
      "server-authentication": {},
      "tacacsrs:egress-interface": "mgmt0",
      "tacacsrs:binding-policy": "strict",
      "timeout": 5
    }]
  }
}
```

Certificate TLS still requires a trusted server certificate with a matching IP subject alternative name.
The egress policy does not relax TLS identity, certificate, PSK, or TACACS+ checks.
If `mgmt0` belongs to a VRF, Linux uses that VRF.
An optional `vrf-instance` provides an additional membership check.

### Local availability and fallback

`best-effort` warns before each retry that removes unavailable local constraints.
This policy can send traffic outside the requested management interface or VRF.
For mandatory isolation, select `strict`.

- An unavailable source address removes only the source choice. Available egress and VRF constraints remain.
- An unavailable egress device or its device-binding capability removes only the egress request.
  An available explicit VRF and source remain in effect.
- An unavailable VRF removes the VRF and egress requests together.
  It also removes an interface-derived source that depends on explicit VRF membership.
  An independent explicit source IP remains.
- Verified local route absence removes the egress constraint first.
  A retained explicit VRF receives its own route check on the next attempt.
  The VRF is removed only if that independent check also fails.
  An independent explicit source IP remains until a separate availability check fails.
  With only a source choice left, verified route absence permits a retry without that source.
- TCP error numbers alone never authorize fallback.
  A fresh socket must report `ENETUNREACH`, `EHOSTUNREACH`, or `ENETDOWN` and a complete `TCP_INFO` counter of zero transmitted segments.
  This proves a local failure before any TCP packet left that socket.
  Remote ICMP errors follow transmitted segments and do not permit fallback.
  Connection refusal, connection reset, and generic timeouts do not permit fallback.
  DNS errors, host-guard errors, TLS errors, and authentication errors do not permit fallback.

The client applies `SO_BINDTODEVICE` and checks the full route and resolved route for the pinned TCP flow.
Before Linux 5.18, a VRF-member socket binding alone does not enforce physical egress.
Linux commit [`40867d74c374`](https://github.com/torvalds/linux/commit/40867d74c374) preserves the original member during route selection.
The full-route query uses `RTM_F_FIB_MATCH`. Every live multipath hop must use the requested member before the resolved output can pass.
Mixed-device multipath fails without fallback, even when the resolved query selects the requested member.
Nexthop-ID routes and incomplete full-route replies fail without fallback because they do not prove physical egress.
IPv6 source-bearing queries do not model the socket's strict physical-device selection.
For a different output device, source-free queries can supply physical evidence within the same policy table.
This alternate evidence requires a source-independent pinned route.
A source-specific pinned route through another member fails explicitly, without fallback, because physical egress is unverifiable.
Source-free errors permit fallback only when no IPv6 policy rule has a source prefix.
The pinned table must also lack a possible member route for the destination.
An available member route with an inconclusive lookup produces an explicit error, not a missing-route classification.
Source-free table differences never permit fallback.
These checks preserve valid nonpreferred IPv6 routes without a kernel-version assumption.
The source-specific regression runs on the current kernel. Legacy-kernel runtime behavior remains untested.

For automatic selection, a short-lived local socket reserves the TCP port before the source lookup.
The connection socket then binds that source and port before the reservation closes.
It then checks the VRF table with that concrete source, TCP protocol, destination port, and reserved source port.
All queries use the actual socket device, not a substituted VRF master.
Thus, source-plus-member policy rules cannot escape the selected VRF table.
The preliminary automatic-source query also uses the reserved port, including for VRF-master-only bindings.
This check prevents main-table fall-through even when the VRF has no unreachable default.
The application does not require the operator to install an unreachable default.

An inconclusive route query never permits route-based fallback.
Device type and VRF membership errors remain invalid configuration, even when a device is down.
Without a routing constraint, an unavailable route-inspection capability retains the enforced source binding and emits a warning.
Unknown or truncated `TCP_INFO` evidence also retains the requested constraints.
No UDP probe stands in for TCP routing. Protocol-specific and port-specific rules apply to the real TCP socket.

Every retry creates a fresh socket. Each destination permits at most four socket attempts.
DNS resolution, destination attempts, and local fallback share the canonical TCP connection timeout.
An enclosing request deadline can shorten this interval. Fallback does not restart either deadline.
Malformed names, malformed source addresses, and inconsistent canonical choices always fail validation.
Missing OS resources are connection-time availability errors, not invalid canonical configuration.

### Host requirements and validation

The host supplies devices, VRFs, addresses, and routes. The client never installs routes or changes network namespaces.
Linux device names use the OS name, not a display alias. Names must contain 1–15 bytes.
Windows direct mode remains available without local binding constraints.
On other platforms, strict binding returns an unsupported error. Best-effort warns and retries without local binding.

Native Linux Docker deployments can use `--network host`.
The application does not require `--privileged` or `CAP_NET_ADMIN`.
Recent Linux kernels permit the initial device binding without `CAP_NET_RAW`.
Older kernels and capability or seccomp restrictions can reject device binding.
These errors follow the selected binding policy. Strict deployments need the required host permission.

DNS resolution still uses the process resolver. VRF-aware DNS and scoped destination addresses are not supported.
Address-plus-port uniqueness remains unchanged. Overlapping server addresses in different VRFs are not supported.

The reproducible Linux lab uses disposable user and network namespaces:

```bash
python3 libraries/tacacsrs_networking/tests/linux_binding_lab.py
```

The lab requires Python 3, `iproute2`, `nft`, `unshare`, `setpriv`, and permission to create user namespaces.
The lab captures peer-side SYN packets to verify actual source addresses and egress for IPv4 and IPv6.
It also covers membership, source changes, local-route fallback, missing devices, and connection refusal.
Regression cases cover VRFs without unreachable defaults, independent egress failures, remote ICMP errors, and deadline expiry.
They also cover source-plus-member policy rerouting, UP unused VRF members, IPv6 output mismatches, and ordinary local-address paths.
Metric and prefix cases compare all three source choices and both policies against independent bound Rust TCP controls.
TCP-only route rules also disagree deliberately with no-send UDP probes.
The peer uses nftables to generate remote ICMP errors while the client retains a valid local route.
The lab repeats read-only connection cases without effective capabilities.
It does not change host interfaces or routes.

Validation ran on Linux 6.18.33 under WSL2. SONiC 5.10 was not tested.
VRF validation requires selected-source and table metadata, plus TCP protocol and port lookup support.
Local routing-error classification requires the Linux `TCP_INFO.tcpi_segs_out` field and its complete ABI prefix.
That counter exists in Linux 5.10, but the implementation checks the returned length instead of assuming a kernel version.
QEMU 7.2 linux-user treats `SOL_TCP` replies as four-byte integers and truncates `TCP_INFO`.
The socket regression reports this unsupported result explicitly and still exercises socket ownership transfer.
Unsupported or inconclusive evidence does not authorize fallback.

## Parsing API

For simple application code, parse the JSON and enumerate per-server entries:

```rust
use tacacsrs_config::{enumerate_servers, parse_yang_json};

let config = parse_yang_json(json_str)?;
let servers = enumerate_servers(&config)?;
# anyhow::Ok::<()>(())
```

The primary entry points are:

| Function | Purpose |
| --- | --- |
| `parse_yang_json(&str)` | Parse and structurally validate a JSON string without mutating credential references. |
| `parse_yang_json_file(&Path)` | Parse a JSON file from disk. |
| `validate_credential_references(&TacacsPlus)` | Validate configuration-local credential bundle references. |
| `enumerate_servers(&TacacsPlus)` | Inline shared credential bundles onto every server. |
| `enumerate_server(&TacacsPlus, &str)` | Inline shared credential bundles for one named server. |
| `inspect_central_references(&TacacsPlusServer)` | Inspect typed central usages without retrieving material. |

The module-oriented API is also available for callers that want grouped imports:

- `builders` - programmatic construction helpers.
- `model` - generated YANG model types and namespaces.
- `extensions` - helper traits layered over generated model types.
- `pipeline` - step-by-step parsing and processing.
- `runtime` - bundle enumeration helpers.
- `stats` - runtime statistics types.

## Certificate Peer Identity

For certificate TLS, `domain-name` selects the expected peer identity when configured. Otherwise, verification uses `address`.
DNS names match certificate DNS SANs, and numeric addresses match IP SANs.
The client also performs its existing certificate trust verification. Setting SNI alone is not identity verification.

`sni-enabled` controls the DNS name sent in the TLS `ClientHello`, not whether the peer identity is verified.
When it is true, `domain-name` is required and sent as SNI. An omitted or false value sends no SNI.
A configured domain remains the verification identity even when SNI is disabled.
IP addresses are not sent as certificate-TLS SNI names.

The implementation disables CN fallback and partial-label wildcards. A complete leftmost-label wildcard can match one label, not multiple nested labels.
This follows the DNS/IP identity rules referenced by RFC 9887 Section 3.4.2 and RFC 9525.
Full RFC 9887 conformance remains unclaimed. Revocation coverage and other profile requirements remain incomplete.

Migration can require certificates with matching SAN entries. Chain trust alone no longer permits a certificate for a different identity.
The explicit development-only verification override still bypasses certificate verification and permits server impersonation.

## Certificate Trust

The pinned TLS YANG model gives CA and end-entity bags different meanings:

| Selection | Accepted certificate |
| --- | --- |
| `server-authentication/ca-certs` | A peer with a valid path to a configured authority |
| `server-authentication/ee-certs` | A peer whose DER certificate exactly matches a configured entry |
| Both | A peer accepted by either trust rule |

An end-entity entry is not a CA grant. It cannot authorize another leaf, including a renewed certificate with the same public key.
A CA-signed exact entry works without its issuer in the authority bag. Identity, time validity, and server-purpose checks still apply.
When both bags are configured, a separate valid authority path remains sufficient even if an exact entry shortens OpenSSL's initial path.

Explicitly selected bags must contain materialized certificates. Empty selections fail during preparation and cannot silently enable platform trust.
With neither bag selected, the existing server-authentication-only API retains its platform-trust behavior.
Configured trust excludes platform roots. Preparation does not modify the authoritative bags or their references.

This replaces the old combined-root behavior. Certificate renewal can require updating an exact `ee-certs` entry.
Use CA trust only when authorizing other valid certificates issued by that authority is intended.
For CRL checks, see [certificate revocation](#certificate-revocation). Full RFC 9887 conformance remains unclaimed.

## Certificate Input Boundary

Each `cert-data` value must contain exactly one DER certificate. Concatenated certificates and trailing bytes fail before runtime publication.
This rule also applies to each CA or end-entity trust-bag entry. Multiple entries remain supported.
CLI client certificate files accept a PEM chain or one DER certificate. Each individual DER value must still contain exactly one certificate.
The development verification override does not relax certificate framing.

If separate `public-key` metadata is supplied, `public-key-format` must also be present, and vice versa.
TLS preparation supports `ietf-crypto-types:subject-public-key-info-format` with exactly one DER SPKI value that matches the certificate's public key.
The private key must still match the certificate. SSH public-key encoding is explicitly unsupported for TLS certificate metadata.
Malformed, incomplete, mismatched, and trailing public-key data fail before publication, including when certificate verification is disabled for development.

### Client Certificate Chains

During mutual TLS, the TACACS+ server verifies the client's identity. A common certificate hierarchy is:

```text
Root CA --signs--> Intermediate CA --signs--> Client certificate
```

The server can trust the root without already having the intermediate certificate.
The client certificate identifies its issuer, but does not contain that issuer's certificate or public key.
Sending the intermediate lets the server verify the signatures along the path to its trusted root.
The client must not assume that the server will download missing certificates.

Supplying an intermediate does not make it trusted. The server still requires a valid path to a trust anchor it already accepts.
The client sends public certificates, never their private keys. This configuration omits the root because sending it cannot establish trust.

An intermediate chain is optional. A leaf alone can suffice when a trusted root signs it directly or the server already has the intermediates.
Client-chain provisioning does not affect server-only TLS or PSK authentication.

Inline client identities use the following fields under `certificate/inline-definition`:

| Field | Content |
| --- | --- |
| `cert-data` | One base64-encoded DER leaf certificate |
| `tacacsrs:intermediate-certificate` | An ordered JSON array of base64-encoded DER intermediate certificates |
| `cleartext-private-key` | The private key that matches the leaf, using the declared key format |

The intermediate list starts with the leaf's issuer and proceeds toward the root. Do not include the leaf again or a self-signed root.
The same fields work in per-server identities and reusable `client-credentials` bundles. Omit the list when no intermediates are needed.
Each list entry must be nonempty and unique. Native preparation checks framing, issuer order, signatures, client purpose, and certificate validity.
Malformed, duplicate, out-of-order, or unrelated intermediates fail before publication. The development peer-verification override does not bypass these local checks.

For CLI PEM files, put the leaf first and append intermediates in issuer order. Do not append the root or concatenate DER certificates.
The file loader preserves this order in canonical configuration. Native preparation sends the leaf and supplied intermediates to the peer.
The peer still decides whether the supplied path reaches one of its trust anchors; a missing intermediate can cause handshake rejection.

Credential providers return ordered intermediate bytes with the leaf and key. Materialization installs them only in a derived server value.
Authoritative snapshots and provider references remain unchanged.
Preparation validates all supplied certificate dates. Each connection validates them before TCP setup and again before the TLS handshake.
An established connection continues after a client or server authentication certificate expires.
Certificate dates do not limit the prepared identity, the agent catalog, or a request deadline.
See [certificate revocation](#certificate-revocation) for CRL checks of server certificates.

## Certificate Revocation

The global `tacacsrs:certificate-revocation` container configures certificate revocation list (CRL) checks for certificate TLS servers. The container is a member of `ietf-system-tacacs-plus:tacacs-plus`, so one policy applies to all servers. The configuration has no per-server revocation settings. OCSP, both stapled and fetched, is not supported.

The agent reads the CRL distribution points from each server certificate path. It fetches only allowed CRLs and caches them. Revocation is checked only when a connection is established. An established connection is not closed when a CRL expires, when a refresh fails, or when a refreshed CRL lists the server. A configuration change that changes only this policy applies to future handshakes. It retires no connection and no server.

The container has these leaves:

| Leaf | Default | Meaning |
| --- | --- | --- |
| `enforcement` | `disabled` | The policy: `disabled`, `hard-fail`, `soft-fail`, or `warn-only`. |
| `soft-fail-grace-seconds` | `86400` | Time after the `nextUpdate` of a CRL during which `soft-fail` still accepts that CRL. The range is 1 to 2592000. |
| `allowed-distribution-point` | none | Ordered URL patterns for CRLs that the agent can fetch. At least one pattern is required when `enforcement` is not `disabled`. |
| `prefetch-distribution-point` | none | Exact CRL URLs that the agent fetches at startup and keeps fresh. Each URL must match an allowed pattern. |
| `allow-private-addresses` | `true` | Allows CRL fetches to RFC 1918 and unique local addresses. |
| `fetch-timeout-seconds` | `5` | Maximum time for one CRL fetch, including DNS, connect, and the complete body. The range is 1 to 60. |
| `max-crl-bytes` | `16777216` | Maximum size of one fetched CRL. The range is 1024 to 67108864. |
| `cache-directory` | none | Absolute directory for a persistent CRL cache. |

The `enforcement` values have these effects:

- `disabled` does not check revocation.
- `hard-fail` rejects the server when no valid current CRL is available.
- `soft-fail` accepts a validated CRL for `soft-fail-grace-seconds` after its `nextUpdate` when a fresh CRL cannot be obtained. After that time, or without a validated CRL, it rejects the server. The grace never excuses a listed certificate or an invalid CRL.
- `warn-only` accepts the server and logs a warning when CRL evidence is unavailable. It still rejects a certificate that a valid CRL lists.

An allowed pattern has the form `http://HOST[:PORT]/PATH`. Patterns must use `http://`. In the host, the leftmost label can be `*`, which matches exactly one label, or `**`, which matches one or more labels. At least two literal labels must follow the wildcard. In the path, a `**` segment matches zero or more whole segments, and `*` matches characters inside one segment. Host names match without regard to case, and paths match exactly. The agent fetches a distribution point only when it is an `http://` URL that matches a pattern. It ignores LDAP distribution points.

A prefetched CRL is used only for a certificate whose distribution points reference the same URL. Loopback, link-local, unspecified, and multicast addresses are always rejected, also when `allow-private-addresses` is `true`. When `cache-directory` is set, the agent stores validated CRLs and loads them at startup. The agent validates each loaded CRL again before use. Thus `soft-fail` works after a restart while the CRL server is unreachable.

Some issuers, for example Azure, publish CRLs below host names that you cannot know in advance. Use a host wildcard for such an issuer, and prefetch a URL that you know:

```json
{
  "ietf-system-tacacs-plus:tacacs-plus": {
    "tacacsrs:certificate-revocation": {
      "enforcement": "soft-fail",
      "soft-fail-grace-seconds": 86400,
      "allowed-distribution-point": [
        "http://**.pki.core.windows.net/**",
        "http://crl.microsoft.com/**"
      ],
      "prefetch-distribution-point": [
        "http://primary-cdn.pki.core.windows.net/eastus2/crls/ccmeeastus2pki/ccmeeastus2ica01/22/current.crl"
      ],
      "cache-directory": "/var/cache/tacacsrs/crl"
    }
  }
}
```

The example shows only the revocation container. Add it next to the `server` list of a complete configuration.

The check applies to CA-authenticated certificate TLS servers. Exact pinned end-entity trust skips the check, and the agent counts each skip. Disabled `certificate-verification` also skips the check. TCP and TLS-PSK servers are not affected.

The host must supply a revocation verifier. `tacacsrs-agentd` always supplies the CRL verifier of [`tacacsrs-revocation`](../libraries/tacacsrs_revocation/README.md). When `enforcement` is not `disabled` and the host supplies no verifier, the agent refuses new certificate TLS connections. `tacon` direct mode also supplies the CRL verifier. It shares one verifier across the connections of a run, fetches missing CRLs during the handshake, and does not prefetch. Set `cache-directory` to keep CRLs between `tacon` runs.

## Provider Refresh

The agent supervisor periodically revalidates provider-backed credentials, even without credential notifications.
The separate canonical runtime-policy resource controls the maximum scheduled interval:

```json
{
  "tacacsrs:runtime-policy": {
    "credential-refresh-interval-seconds": 60
  }
}
```

The value must be positive and defaults to 60 seconds.
When prepared material has an earlier expiry, the supervisor schedules refresh at half its remaining lifetime, with at least one second between attempts.
Health updates and longer policy intervals do not postpone an already scheduled refresh. A shorter interval can bring it forward.
The next interval starts after an attempt completes. This interval is not a provider I/O timeout; providers must bound their own retrieval operations.

A scheduled attempt does not mark still-valid material stale. Failed revalidation uses the existing credential-failure and stale-grace rules.
Repeated failures do not renew stale grace. Provider validity expiry still withdraws the catalog while a resolver is pending.
Successful revalidation can recover an expired credential catalog, but cannot revive an expired configuration source.
Unchanged provider validity bounds retain their earlier monotonic cutoff; rereading the same material cannot extend its lifetime.

Refresh uses the existing credential revision and atomic publication path without changing canonical references or source revisions.
The supervisor owns the refresh future and cancels it on host stop. It creates no detached refresh worker.
Without a resolver, or when the accepted source has no provider references, no automatic resolution occurs.
Inline-only material still requires a new source snapshot. CRL refresh is separate. See [certificate revocation](#certificate-revocation).

## EPSK Presence

`server-authentication/tls13-epsks` is a YANG `empty` leaf, not a boolean.
A present leaf uses RFC 7951 JSON `[null]`. Omit the field when it is absent.
Boolean values, bare `null`, and arrays with the wrong shape are rejected for direct fields and server-credential bundles.
Rust callers use `Some(YangEmpty::default())` for presence.

```json
{
  "server-authentication": {
    "tls13-epsks": [null]
  }
}
```

This selector requires a client EPSK identity after credential-bundle expansion. It cannot select certificate TLS implicitly.
Client EPSK configuration still works without the optional server selector.
The current PSK transport cannot apply CA or end-entity trust bags alongside a client EPSK identity, so preparation rejects that combination.
Root configuration parsing also rejects trailing JSON after the first complete document.

## Three-layer processing model

The crate separates parsing and runtime preparation into three layers.

### Raw YANG model

If you need the submitted YANG model preserved exactly for round-tripping or reporting, use the raw pipeline:

```rust
use tacacsrs_config::parse_root_json;

let raw_config = parse_root_json(json_str)?;
# anyhow::Ok::<()>(())
```

### Configuration-local bundle enumeration

Credential references can point to bundles in the same configuration. Validate those references, then enumerate the selected server:

```rust
use tacacsrs_config::{enumerate_server, parse_yang_json, validate_credential_references};

let config = parse_yang_json(json_str)?;
validate_credential_references(&config)?;

let server = enumerate_server(&config, "primary")?;
# anyhow::Ok::<()>(())
```

### Central credential resolution

Build `tacacsrs_credential_resolution::ResolutionPlan` values after enumeration. The resolution crate emits deterministic requests for central certificate-with-key, TLS 1.3 symmetric key, CA bag, and end-entity bag usages. Its async resolver contract returns secret-safe typed material, and `resolve_plan` rejects incomplete or mismatched result sets.

Neither generic crate interprets a central string as a SONiC identifier or filesystem path. P3 supplies provider retrieval, refresh behavior, and projection into networking inputs.

## Programmatic server construction

When code needs to construct server definitions directly instead of parsing RFC 7951 JSON, use `TacacsPlusServerBuilder`:

```rust
use tacacsrs_config::{TacacsPlusServerBuilder, TacacsPlusServerExt, TacacsPlusServerType};

let server = TacacsPlusServerBuilder::new(
    "primary",
    TacacsPlusServerType::ACCOUNTING,
    "192.0.2.10",
    49,
)
.with_timeout(10)
.with_shared_secret("example-shared-secret")
.build();

assert_eq!(server.address, "192.0.2.10");
assert_eq!(server.port, 49);
assert!(server.is_obfuscation());
# anyhow::Ok::<(), anyhow::Error>(())
```

The builder is for runtime construction of valid server shapes. It is not a replacement for schema validation of submitted YANG JSON.

## Inline key format identities

TLS inline key material uses YANG `identityref` fields from `ietf-crypto-types`. RFC 7951 JSON represents those values as module-qualified strings.

### Private key format

| JSON value | Meaning |
| --- | --- |
| `ietf-crypto-types:rsa-private-key-format` | DER-encoded RSAPrivateKey. |
| `ietf-crypto-types:ec-private-key-format` | DER-encoded ECPrivateKey. |
| `ietf-crypto-types:one-asymmetric-key-format` | DER-encoded CMS OneAsymmetricKey. |

### Public key format

| JSON value | Meaning |
| --- | --- |
| `ietf-crypto-types:subject-public-key-info-format` | DER-encoded SubjectPublicKeyInfo. |
| `ietf-crypto-types:ssh-public-key-format` | SSH public key format. |

The TACACS+ YANG model constrains TLS client identity and server authentication paths to `subject-public-key-info-format`.

### Symmetric key format

| JSON value | Meaning |
| --- | --- |
| `ietf-crypto-types:octet-string-key-format` | Raw octet string. |
| `ietf-crypto-types:one-symmetric-key-format` | DER-encoded CMS OneSymmetricKey. |

## TLS with inline certificate material

```json
{
  "ietf-system-tacacs-plus:tacacs-plus": {
    "server": [
      {
        "name": "tls-inline",
        "server-type": "authentication",
        "address": "192.0.2.1",
        "port": 49,
        "domain-name": "tacacs.example.com",
        "sni-enabled": true,
        "client-identity": {
          "certificate": {
            "inline-definition": {
              "public-key-format": "ietf-crypto-types:subject-public-key-info-format",
              "public-key": "BASE64VALUE=",
              "private-key-format": "ietf-crypto-types:rsa-private-key-format",
              "cleartext-private-key": "BASE64VALUE=",
              "cert-data": "BASE64VALUE="
            }
          }
        },
        "server-authentication": {
          "ca-certs": {
            "inline-definition": {
              "certificate": [
                {
                  "name": "CA-1",
                  "cert-data": "BASE64VALUE="
                }
              ]
            }
          }
        }
      }
    ]
  }
}
```

## TACACS+/TLS PSK-DHE augmentation

The repository includes a local `tacacsrs` YANG module that augments TACACS+ TLS 1.3 EPSK configuration with `psk-dhe-ke-groups`. RFC 7951 JSON uses the module-qualified key `tacacsrs:psk-dhe-ke-groups`:

```json
{
  "ietf-system-tacacs-plus:tacacs-plus": {
    "server": [
      {
        "name": "tls-psk-dhe",
        "server-type": "accounting",
        "address": "192.0.2.10",
        "port": 49,
        "client-identity": {
          "tls13-epsk": {
            "inline-definition": {
              "cleartext-symmetric-key": "BASE64VALUE="
            },
            "external-identity": "client@example.com",
            "tacacsrs:psk-dhe-ke-groups": [
              "x25519",
              "secp256r1",
              "ffdhe3072"
            ]
          }
        }
      }
    ]
  }
}
```

Supported group values are `x25519`, `secp256r1`, `secp384r1`, `secp521r1`, `ffdhe2048`, `ffdhe3072`, `ffdhe4096`, `ffdhe6144`, and `ffdhe8192`. Unknown values fail during JSON deserialization.

## Code generation workflow

The generated Rust types come from the checked-in YANG tooling under `libraries/tacacsrs_config/yang/`:

- `plugins/yang2rust.py` emits Rust structs, enums, bitflags, and helper methods.
- `expand_yang_tree.py` refreshes the expanded tree reference and generated Rust output.
- `modules/` contains project-owned YANG modules passed to `pyang` alongside the upstream TACACS+ model.
- `generated_types.rs` is copied into `src/generated.rs` after regeneration.

Regenerate after YANG module updates:

```bash
python -m pip install -r requirements.txt

cd libraries/tacacsrs_config/yang
python expand_yang_tree.py --list-features
python expand_yang_tree.py --list-features --list-features-format ini > feature-flags.ini
python expand_yang_tree.py --features-ini feature-flags.ini > expanded-tree.txt
python expand_yang_tree.py \
  -f rust \
  --features-ini feature-flags.ini \
  -o generated_types.rs
cp generated_types.rs ../src/generated.rs
```

Run formatting, clippy, build, and tests after regeneration.
