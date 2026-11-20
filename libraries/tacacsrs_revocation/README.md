# tacacsrs-revocation

`tacacsrs-revocation` checks TACACS+ over TLS server certificates against certificate revocation lists (CRLs). It provides `CrlVerifier`, which implements the `RevocationVerifier` contract of `tacacsrs-networking`. The host, for example `tacacsrs-agentd`, creates one verifier and gives it to the TLS transport.

## Checks happen only when a connection is established

The TLS handshake asks the verifier for a decision once for each new connection. A later CRL, a settings change, or a revoked certificate affects only new connections. The verifier never closes or retires an established connection.

The handshake calls `decide` inside the OpenSSL verify callback. `decide` uses only cached decisions and CRLs whose signatures are already verified. When evidence is missing, `decide` returns `NeedEvidence`. The handshake then awaits `obtain`, which fetches CRLs and verifies their signatures on the blocking thread pool. After `obtain`, the next `decide` returns a final decision.

## Enforcement modes

The `enforcement` field of `RevocationSettings` selects the policy:

| Mode | Fresh CRLs, not listed | Certificate listed | Evidence missing or stale |
| --- | --- | --- | --- |
| `Disabled` | Accept | Accept | Accept. The verifier does no work. |
| `HardFail` | Accept | Reject | Reject. |
| `SoftFail` | Accept | Reject | Accept a validated CRL until `nextUpdate` plus `soft_fail_grace`, with a warning. Reject after that time or without a validated CRL. |
| `WarnOnly` | Accept | Reject | Accept with a warning. |

A certificate that a CRL lists is always rejected, also when the CRL is stale. The verifier checks each certificate in the path except the trust anchor. The CRL for a certificate must have a valid signature from the key of the next certificate in the path. For this reason, a renewed CA key with the same name does not validate CRLs of the old key.

## Distribution point allowlist

The verifier reads the CRL distribution points (CDPs) of each certificate. It fetches a CDP only when the CDP is an `http://` URL that matches a pattern in `allowed_distribution_points`. In the host, a leftmost `*` matches exactly one label and a leftmost `**` matches one or more labels. In the path, a `**` segment matches zero or more segments, and `*` matches characters inside one segment. Example patterns:

```text
http://**.pki.core.windows.net/**/*.crl
http://crl.microsoft.com/**/*.crl
```

A host such as `crl.microsoft.com.example.net` does not match `http://crl.microsoft.com/**/*.crl`. The verifier tries the URIs of a CDP in certificate order and uses the first mirror that returns a CRL. A mirror that failed is skipped during its back-off time. The back-off starts at 30 seconds and doubles up to 10 minutes.

The verifier ignores `ldap://` and other non-HTTP CDPs. A certificate whose first CDP is an LDAP URL can still use a later HTTP URL.

## Fetch limits

Each fetch uses the local binding and connection guard of the TACACS+ server. The verifier does not fall back to an unbound connection. It rejects these addresses:

- Loopback, link-local (including `169.254.169.254` and `fe80::/10`), unspecified, multicast, and broadcast addresses.
- RFC 1918 and `fc00::/7` addresses, unless `allow_private_addresses` is `true`.

`fetch_timeout` limits DNS resolution, the connection, and the complete body. `max_crl_bytes` limits the body size. The verifier does not follow redirects. It accepts DER and PEM CRLs.

## Prefetch and refresh

`CrlVerifier::spawn_refresh` starts a background task. The task fetches the URLs in `prefetch_distribution_points` and refreshes stored CRLs before their `nextUpdate`. A prefetched CRL applies only to a certificate whose CDP contains the same URL. The task also uses the Active Directory Certificate Services (AD CS) "Next CRL Publish" extension as a refresh hint.

## Delta CRLs

The verifier supports delta CRLs, for example from AD CS. The Freshest CRL extension of a certificate or a base CRL names the delta CRL location. When a certificate or its base CRL names a delta CRL, the verifier requires a matching delta CRL. A missing delta CRL counts as missing evidence.

## Disk cache

When `cache_directory` is set, the verifier writes each fetched CRL to that directory. It writes a temporary file and renames it. The file name is a hash of the URL. At startup, the refresh task loads the files. It deletes files with a damaged header, a wrong digest, an invalid CRL, or a size above `max_crl_bytes`. A loaded CRL never replaces a newer CRL in memory. A path uses a loaded CRL only after its signature matches the issuer key in that path.

## Counters

`CrlVerifier::counters` returns `CrlVerifierCounters` with these values: `fetches`, `fetch_failures`, `backoffs`, `stale_grace_accepts`, `warn_only_accepts`, `revoked_rejects`, and `evidence_misses`.
