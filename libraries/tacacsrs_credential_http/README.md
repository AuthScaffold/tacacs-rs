# tacacsrs-credential-http

This internal crate retrieves CRLs from explicitly registered HTTP or HTTPS locations.
Canonical server configuration retains opaque evidence references. The host maps those references to allowed provider locations.
The provider does not discover URLs from certificates or interpret an unknown reference as a URL.

Native preparation and TLS verification remain responsible for CRL signatures, freshness, path coverage, and revocation status.
The provider returns untrusted bytes through the existing credential-resolution contract.

## Registration

```rust,no_run
use std::sync::Arc;
use tacacsrs_credential_http::{CrlFetchLimits, HttpCrlResolver, HttpCrlSource};

let resolver = Arc::new(HttpCrlResolver::new(
	[HttpCrlSource::new(
		"primary-ca-crls",
		["https://pki.example.net/root.crl", "https://pki.example.net/issuer.crl"],
	)?],
	CrlFetchLimits::default(),
)?);
# Ok::<(), anyhow::Error>(())
```

The canonical `tacacsrs:require-crls/evidence-reference` retains `primary-ca-crls`.
An embedding host supplies the resolver to materialization or `ConfigSupervisor::with_credential_resolver`.
The supervisor's existing refresh policy revalidates these references without separate HTTP worker tasks.
The stock daemon does not yet expose production registration of HTTP sources.

`with_fallback` delegates other credential kinds and unregistered references to another provider.
A registered HTTP source never uses the fallback after a failed fetch.
Fallback providers retain their own execution limits; these HTTP limits do not wrap delegated calls.

## Retrieval Policy

Each reference names one ordered set of up to 16 public HTTP(S) locations.
All locations must succeed. The provider returns no partial set and retains no response cache.
Duplicate references, duplicate URLs, URL credentials, queries, and fragments are rejected.
Locations must contain no secrets, including in path components: HTTP backend diagnostics can expose URLs.
Provider errors and `Debug` output omit source URLs, reference values, and response bodies.

Registration authorizes outbound requests to the specified hosts, including their DNS results.
This is not a network sandbox or a DNS-address allowlist. Hosts must restrict registration to trusted location policy.
Certificate extensions and unknown reference strings cannot add retrieval destinations.
Redirects, environment proxies, decompression, and idle connection pooling are disabled.
HTTPS uses platform certificate and hostname verification. HTTP evidence still requires native signature and freshness checks.

Defaults are a 10-second whole-set timeout, 4 MiB of aggregate body bytes, and four active fetches per resolver.
The timeout covers all locations, including response bodies; each location does not receive a new whole-set budget.
The byte cap applies to retained evidence, not total HTTP headers, TLS buffers, allocator overhead, or resolver state.
Oversized declared lengths and streamed bodies fail. Empty bodies and non-identity content encodings also fail.
Concurrency saturation fails immediately without a provider-owned waiting queue.
Dropping a resolution future cancels request I/O and releases capacity. System DNS calls can outlive cancellation inside the runtime's blocking pool.

Only status 200 supplies evidence. Status 404 maps to `NotFound`; 401 and 403 map to `AccessDenied`.
Other statuses, connection errors, truncated bodies, and timeout map to `Unavailable`.
Invalid bodies and size-limit failures map to `InvalidMaterial`.

The provider does not treat HTTP cache headers as signed validity evidence.
It returns unbounded provider validity; native CRL dates and canonical maximum age still constrain preparation and transport lifetime.
It does not implement OCSP queries, certificate-driven distribution-point discovery, scoped CRLs, or delta CRLs.