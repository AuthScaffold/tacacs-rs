# Previous Findings Status

| ID | Status | Current status / evidence |
|---|---|---|
| R1-1 CA certificates silently discarded | ✅ Fixed | `build_root_cert_store()` now loads both `ca-certs` and `ee-certs` into the TLS root store and feeds them into `TlsConfigurationBuilder` (`libraries\tacacsrs_networking\src\config_connect.rs:170-172`, `307-343`). |
| R1-2 `domain_name` / `sni_enabled` ignored at TLS | ✅ Fixed | `derive_sni_name()` now prefers `domain_name` when `sni_enabled()` is true, with regression tests covering both branches (`libraries\tacacsrs_networking\src\config_connect.rs:164-165`, `295-302`, `428-470`). |
| R1-3 Credential-reference resolver no-op stub | ✅ Fixed | `effective_resolver()` now falls back to `NoOpResolver`, which rejects every external lookup/validation instead of silently succeeding (`libraries\tacacsrs_config\src\resolvers\mod.rs:21-94`). |
| R1-4 IPv6 address parsing broken | ✅ Fixed | `parse_host_port()` and `ResolvedServer::socket_address()` both explicitly handle IPv6, including bracketed output/tests (`libraries\tacacsrs_networking\src\helpers.rs:108-132`, `213-229`; `libraries\tacacsrs_config\src\resolvers\mod.rs:303-314`). |
| R1-5 `raw_private_key` client identity silently dropped | ⚠️ Partial | The silent drop is gone: `config_connect` now has an RPK path and non-`rpk` builds error explicitly (`libraries\tacacsrs_networking\src\config_connect.rs:63-69`, `122-141`). But default builds still accept RPK config at validation time and only fail later unless compiled with `--features rpk` (`libraries\tacacsrs_config\src\validation.rs:147-158`; `executables\tacon\Cargo.toml:26-29`; `executables\tacacsrs_agentd\Cargo.toml:21-25`). |
| R1-6 Secrets in `Debug` output | ✅ Fixed | `ResolvedServer` has a manual `Debug` impl that redacts `client_identity`, `server_authentication`, and `shared_secret` (`libraries\tacacsrs_config\src\resolvers\mod.rs:357-373`). |
| R1-7 `server-type` never used for routing | ❌ Still present | `server_type` is still only parsed/constructed/debugged; there is still no runtime selection/filtering path using it outside tests/examples (`executables\tacacsrs_agentd\src\main.rs:235`, `executables\tacon\src\config.rs:21`, repo-wide `server_type` search). |
| R1-8 `ee_certs` inner choice not validated | ✅ Fixed | `validate_server_authentication()` now validates `ee-certs` with the same inline-vs-truststore choice enforcement as `ca-certs` (`libraries\tacacsrs_config\src\validation.rs:210-221`). |
| R1-9 Example JSON malformed | ✅ Fixed | The README JSON examples are now well-formed and parseable; no stale malformed sample remains in `libraries\tacacsrs_config\README.md`. |
| R2-N1 External resolver `None` leaves unresolved refs | ✅ Fixed | Both validation and resolution now route through the rejecting `NoOpResolver`, so `None` no longer leaves external refs silently unresolved (`libraries\tacacsrs_config\src\resolvers\mod.rs:88-94`, `396-412`, `453-495`). |
| R2-N4 `tls13_epsks` flag ignored in connection | ❌ Still present | `tls13_epsks` is still only parsed/copied/validated; no connection code consults it before taking the EPSK path (`libraries\tacacsrs_config\src\validation.rs:193`, `libraries\tacacsrs_config\src\resolvers\mod.rs:550`, repo-wide `tls13_epsks` search). |
| R2-N5 TLS setup duplicated 3× | ✅ Fixed | The new `config_connect::establish_stream()` centralizes TCP/TLS/PSK/RPK setup and is used by the agent upstream path (`libraries\tacacsrs_networking\src\config_connect.rs:35-150`; `libraries\tacacsrs_agent\src\upstream.rs:299-304`, `357-362`). |
| R2-N6 `Deref` exposes `shared_secret` | ❌ Still present | `ResolvedServer` still implements `Deref<Target = TacacsPlusServer>`, so callers can still access `shared_secret` directly despite the redacted `Debug` wrapper (`libraries\tacacsrs_config\src\resolvers\mod.rs:277-279`, `349-355`). |
| R2-N8 `too_many_lines` in agentd | ⚠️ Partial | `executables\tacacsrs_agentd\src\main.rs` is much more structured than before, but it is still a large single file (~360 lines) mixing CLI, config loading, server construction, and tests. |
| R2-N9 `from_raw` naming | ❌ Still present | The helper is still named `ResolvedServer::from_raw()` (`libraries\tacacsrs_config\src\resolvers\mod.rs:283-292`). |
| R2-GPT-N1 External refs unusable from shipped binaries | ❌ Still present | Both binaries hardcode `None` for parsing and resolution of YANG config files, so configs using external keystore/truststore references still cannot be used from `tacon` or `tacacsrs-agentd` (`executables\tacacsrs_agentd\src\main.rs:253-255`; `executables\tacon\src\config.rs:129-132`). |
| R2-GPT-N2 `--insecure` flag regressed in agentd | ✅ Fixed | The daemon CLI flag is now stored in `ServiceConfig`, propagated into `NetworkUpstreamConnector`, and passed through both persistent and dedicated connection paths (`executables\tacacsrs_agentd\src\main.rs:60`, `310`; `libraries\tacacsrs_agent\src\upstream.rs:131-153`, `285-304`, `342-362`). |
| R2-GPT-N3 Cert keystore resolves only key, not cert | ✅ Fixed | `resolve_keystore_certificate()` now returns `X509CertificateMaterial`, and `resolve_certificate_keystore_ref()` copies both cert and key into inline material (`libraries\tacacsrs_config\src\resolvers\mod.rs:96-107`, `178-200`; `libraries\tacacsrs_config\src\resolvers\tls.rs:17-52`). |
| R2-GPT-N4 README documents wrong `CredentialRefType` enum | ✅ Fixed | The README no longer documents a non-existent `CredentialRefType`; it now documents the actual resolver trait and public API (`libraries\tacacsrs_config\README.md:48-115`, `176-240`). |
| R3-N1 `socket_address()` invalid IPv6 output | ✅ Fixed | `socket_address()` now brackets IPv6 literals (`libraries\tacacsrs_config\src\resolvers\mod.rs:303-314`) and has explicit tests in `config_connect` (`libraries\tacacsrs_config\tests\mapping_integration.rs:79-80`). |
| R3-N2 `CredentialResolver::validate()` default treats `Ok(None)` as success | ✅ Fixed | The old default-validation hole is gone: validation is now explicit per reference type and `NoOpResolver` rejects missing resolver cases outright (`libraries\tacacsrs_config\src\resolvers\mod.rs:57-85`, `453-495`). |
| R3-N3 RPK rejected at connection not validation | ⚠️ Partial | New RPK transport support fixes this for `rpk` builds (`libraries\tacacsrs_networking\src\config_connect.rs:122-141`; `libraries\tacacsrs_networking\src\transport\tls_rpk\*`). But default non-`rpk` builds still accept the config structurally and only reject at connect time (`libraries\tacacsrs_networking\src\config_connect.rs:63-69`). |
| R3-N4 Agent daemon never passes `--insecure` to upstream | ✅ Fixed | Same propagation fix as R2-GPT-N2; the value now reaches `ConnectOptions` in both upstream paths (`executables\tacacsrs_agentd\src\main.rs:310`; `libraries\tacacsrs_agent\src\upstream.rs:299-304`, `357-362`). |
| R3-N5 Dead allocation in `connect_upstream` | ✅ Fixed | The prior redundant allocation is no longer present; the `address` string is used for logging/context and the stream creation is delegated cleanly to `config_connect::establish_stream()` (`libraries\tacacsrs_agent\src\upstream.rs:287-309`). |
| R3-N6 `get_server_addresses` mishandles bare IPv6 | ❌ Still present | `get_server_addresses()` still treats any string containing `:` as already having a port, so a bare IPv6 literal is passed unchanged to `to_socket_addrs()` without appending `:49` (`libraries\tacacsrs_networking\src\helpers.rs:20-28`). |
| R3-N7 README `CredentialRefType` wrong | ✅ Fixed | Same as R2-GPT-N4: the README was rewritten around the actual trait/API surface. |

# New Findings

## R4-N1: TLS-RPK can silently disable all server authentication

- **Severity:** Critical
- **Where:** `libraries\tacacsrs_networking\src\transport\tls_rpk\config_builder.rs:202-205`

If an RPK client identity is configured but no pinned server raw public keys are present, `create_rpk_ssl_context()` sets `SslVerifyMode::NONE`:

```rust
if pinned_keys.is_empty() {
    ctx_builder.set_verify(SslVerifyMode::NONE);
}
```

That means the new RPK transport will happily connect to any server with no server authentication at all. This is not prevented by validation: `config_connect` only populates pinned keys from `server_authentication.raw_public_keys` (`libraries\tacacsrs_networking\src\config_connect.rs:256-273`), while `validate_client_identity()` / `validate_server_authentication()` never require that pairing (`libraries\tacacsrs_config\src\validation.rs:147-158`, `176-236`). The integration suite even accepts an RPK client-identity config with no server-authentication block (`libraries\tacacsrs_config\tests\mapping_integration.rs:790-837`).

**Why this matters:** this is a straight MITM downgrade. A user enabling RPK client auth would reasonably expect authenticated TLS, but the current implementation silently falls back to unauthenticated TLS unless they also happened to configure pinned server keys.

## R4-N2: `credential_references` example is broken at runtime

- **Severity:** Medium
- **Where:** `libraries\tacacsrs_config\examples\credential_references.rs:17`, `53`, `162`, `199`

The example resolver returns `"RESOLVED_PRIVATE_KEY"`, but the example asserts against `"RESOLVED_MATERIAL"`:

- resolver output: `cleartext_private_key: "RESOLVED_PRIVATE_KEY".to_string()`
- assertion: `assert_eq!(rpk_inline, "RESOLVED_MATERIAL");`

I confirmed this by running:

```text
cargo run -q -p tacacsrs-config --example credential_references
```

which panics at `libraries\tacacsrs_config\examples\credential_references.rs:162` with:

```text
left: "RESOLVED_PRIVATE_KEY"
right: "RESOLVED_MATERIAL"
```

So one of the flagship new examples currently does not actually run successfully.

# Overall Assessment

This round meaningfully improves the branch: most of the earlier config-resolution, TLS wiring, CA loading, SNI, debug-redaction, and resolver issues are now genuinely fixed, and the new `config_connect` split is a solid cleanup.

However, I would **not** sign off yet. The new RPK transport introduces a **critical security flaw** (unauthenticated TLS when no pinned server keys are configured), and several previously-known functional issues still remain unresolved:

- `server-type` is still not used operationally
- `tls13_epsks` is still ignored at connection time
- shipped binaries still cannot consume external credential references
- `get_server_addresses()` still mishandles bare IPv6
- the new `credential_references` example currently panics when run

Targeted verification run:

- `cargo test -p tacacsrs-config --tests` ✅
- `cargo test -p tacacsrs-networking --all-features` ✅
- `cargo run -q -p tacacsrs-config --example credential_references` ❌ (panics as described above)
