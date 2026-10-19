# tacacsrs-credential-http

This internal crate retrieves CRLs and OCSP responses from explicitly authorized HTTP or HTTPS locations.
Canonical server configuration retains opaque evidence references. The host maps those references to allowed provider locations.
Certificate discovery uses host-supplied DER certificates and an exact URL allowlist. Unknown references are never interpreted as URLs.

Native preparation and TLS verification remain responsible for CRL signatures, freshness, path coverage, and revocation status.
The provider returns untrusted bytes through the existing credential-resolution contract.

## Registration

```rust,no_run
use std::sync::Arc;
use tacacsrs_credential_http::{EvidenceFetchLimits, HttpEvidenceResolver, HttpCrlSource};

let resolver = Arc::new(HttpEvidenceResolver::new(
	[HttpCrlSource::new(
		"primary-ca-crls",
		["https://pki.example.net/root.crl", "https://pki.example.net/issuer.crl"],
	)?],
	EvidenceFetchLimits::default(),
)?);
# Ok::<(), anyhow::Error>(())
```

The canonical `tacacsrs:require-crls/evidence-reference` retains `primary-ca-crls`.
An embedding host supplies the resolver to materialization or `ConfigSupervisor::with_credential_resolver`.
The supervisor's existing refresh policy revalidates these references without separate HTTP worker tasks.
The daemon exposes startup registration through repeatable `--http-crl-source REFERENCE URL` pairs.
It groups matching references into ordered URL sets and attaches this resolver to its supervisor.
In `SONiC` mode, it retains the `SONiC` provider as the fallback and keeps its credential notifications.

`with_fallback` delegates other credential kinds and unregistered references to another provider.
A registered HTTP source never uses the fallback after a failed fetch.
Fallback providers retain their own execution limits; these HTTP limits do not wrap delegated calls.
The resolver passes the caller's same `WorkScope` to its fallback. It does not create another scope.
Cooperative HTTP cancellation releases request capacity. Unobservable system DNS work remains outside the registered-work guarantee.

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

Only status 200 supplies evidence. For CRLs, status 404 maps to `NotFound`; 401 and 403 map to `AccessDenied`.
For OCSP, non-200 statuses map to `Unavailable`.
Other statuses, connection errors, truncated bodies, and timeout map to `Unavailable`.
Invalid bodies and size-limit failures map to `InvalidMaterial`.

The provider does not treat HTTP cache headers as signed validity evidence.
It returns unbounded provider validity; native CRL dates and canonical maximum age still constrain preparation and transport lifetime.
Native preparation owns scope checks and explicit base/delta pairing; the HTTP provider returns the supplied bytes unchanged.

## Certificate Discovery and OCSP

`HttpCrlSource::from_certificates` extracts full URI distribution points from host-supplied DER certificates.
Every selected location must occur in the supplied allowlist. Repeated locations are fetched once, in certificate order.
The certificate set is limited to sixteen certificates and 4 MiB. Relative distribution points are not supported.
Discovery does not inspect live TLS peers or authorize any new outbound destination.

`HttpOcspSource::new` creates a SHA-256 certificate-ID request for an explicit responder and certificate/issuer pair.
`HttpOcspSource::from_certificate` selects the first authorized AIA responder in a registered certificate.
`HttpEvidenceResolver::with_ocsp_sources` adds these requests to the shared resolver.
Requests use POST and OCSP content types. Responses are capped at 64 KiB, further limited by the configured byte cap.
The same total timeout, concurrency, proxy, redirect, decoding, cancellation, and fallback rules apply.
The provider returns untrusted `OcspResponseMaterial`; native TLS verifies the response against the actual peer before client authentication.
No nonce is used. Signed freshness and certificate binding limit reuse of responses.