# Code Review Summary (Round 4): `feature/yang-config-support`

**Reviewers:** Claude Opus 4.6, GPT 5.4 | **Branch:** `feature/yang-config-support` vs `main`
**Scope:** 51 files total, +3,100 new lines since R3 | Key: RPK transport, resolver submodules, cert resolution

---

## Previous Findings Status

| # | Finding | R3 | R4 Opus | R4 GPT | Verdict |
|---|---------|-----|---------|--------|---------|
| R1-1 | CA certs discarded | ✅ | ✅ | ✅ | **✅ Fixed** |
| R1-2 | SNI/domain_name ignored | ✅ | ✅ | ✅ | **✅ Fixed** |
| R1-3 | Credential resolver no-op | ✅ | ✅ | ✅ | **✅ Fixed** |
| R1-4 | IPv6 parsing broken | ✅ | ✅ | ✅ | **✅ Fixed** |
| R1-5 | RPK silently dropped | ⚠️ | ✅ | ⚠️ | **✅ Fixed** (RPK module added; explicit bail without feature) |
| R1-6 | Secrets in Debug | ✅ | ✅ | ✅ | **✅ Fixed** |
| R1-7 | server-type unused | ❌ | ❌ | ❌ | **❌ Unresolved** |
| R1-8 | ee_certs not validated | ✅ | ✅ | ✅ | **✅ Fixed** |
| R1-9 | Example JSON malformed | ✅ | ✅ | ✅ | **✅ Fixed** |
| N1 | Resolver None silent | ✅ | ✅ | ✅ | **✅ Fixed** |
| N4 | tls13_epsks ignored | ❌ | ⚠️ | ❌ | **❌ Accepted** (flag is validation metadata) |
| N5 | TLS setup duplicated | ✅ | ✅ | ✅ | **✅ Fixed** |
| N6 | Deref exposes secrets | ❌ | ❌ | ❌ | **❌ Accepted trade-off** |
| N8 | too_many_lines | ⚠️ | ✅ | ⚠️ | **✅ Resolved** |
| N9 | from_raw naming | ❌ | ❌ | ❌ | **❌ Low priority** |
| GPT-N1 | External refs unusable | ❌ | ❌ | ❌ | **❌ Unresolved** (clear error now, but feature unavailable) |
| GPT-N2 | --insecure regressed agentd | ⚠️ | ⚠️ | ✅ | **✅ Fixed** |
| GPT-N3 | Cert keystore key-only | ❌ | ✅ | ✅ | **✅ Fixed** |
| GPT-N4 | README wrong enum | ❌ | ✅ | ✅ | **✅ Fixed** |
| R3-N1 | socket_address() IPv6 | — | ✅ | ✅ | **✅ Fixed** |
| R3-N2 | validate() accepts None | — | ✅ | ✅ | **✅ Fixed** |
| R3-N3 | RPK rejected late | — | ✅ | ⚠️ | **✅ Fixed** (supported with feature, explicit bail without) |
| R3-N4 | agentd --insecure not wired | — | ✅ | ✅ | **✅ Fixed** |
| R3-N5 | Dead allocation upstream | — | ✅ | ✅ | **✅ Fixed** |
| R3-N6 | get_server_addresses IPv6 | — | ⚠️ | ❌ | **⚠️ Mitigated** (socket_address() pre-formats, pub API still fragile) |

**Score: 19 fixed, 3 accepted trade-offs, 3 still present**

---

## New Consensus Findings (Round 4)

### 🔴 Critical/High: RPK with no pinned server keys silently disables server verification
- **Opus: Low | GPT: Critical**
- `config_builder.rs:202-205` sets `SslVerifyMode::NONE` when `pinned_keys.is_empty()`
- Validation doesn't require pairing RPK client auth with server auth keys
- A user enabling RPK client auth may unknowingly get unauthenticated TLS (MITM risk)
- **Fix:** At minimum warn; ideally require explicit opt-in (`--insecure`) or reject configs without server auth

### 🟡 Medium: `--config` + `--insecure` mutually exclusive in agentd
- **Opus flagged**
- `conflicts_with_all` on `--config` includes `insecure_disable_certificate_verification`
- Operators using YANG config with self-signed certs can't disable verification
- **Fix:** Remove `insecure_disable_certificate_verification` from conflicts list

### 🟡 Medium: RPK path ignores `disable_certificate_verification` option
- **Opus flagged**
- Certificate TLS path checks `options.disable_certificate_verification`; RPK path does not
- `--insecure` has no effect on RPK connections even when pinned keys are present
- **Fix:** Wire the option through to `establish_rpk_stream`

### 🟡 Medium: RPK silently falls through to cert-TLS when cleartext key missing
- **Opus flagged**
- If `raw_private_key` configured but `cleartext_private_key` is `None` (e.g. hidden/encrypted), code silently enters cert-TLS path
- **Fix:** Bail with explicit error if RPK is configured but can't proceed

### 🟡 Medium: `credential_references` example panics at runtime
- **GPT confirmed by running it**
- Resolver returns `"RESOLVED_PRIVATE_KEY"` but assertion expects `"RESOLVED_MATERIAL"`
- **Fix:** Align assertions with resolver output

---

## Additional New Findings

| Sev | Source | Issue |
|-----|--------|-------|
| Low | Opus | `#[allow(unsafe_code)]` at module level in tls_rpk — scope too broad |
| Low | Opus | FFI soundness argument could be strengthened |
| Trivial | Opus | Doc comment says RPK "not yet supported" but it is now |

---

## Overall Progress

### Across 4 rounds: 9 → 25 tracked findings, 19 fully resolved

The branch has matured substantially:
- **config_connect.rs** centralizes all TLS variants (PSK → RPK → cert → TCP)
- **RPK is real** — full transport module with DER key parsing, server pin verification, SNI
- **Resolver architecture** is clean with proper submodules and fail-closed defaults
- **Validation + tests** are comprehensive (~4,000 lines of integration tests)
- **Debug redaction** is thorough across all secret-bearing types

### Priority for this round:

**Must fix:**
1. RPK server verification policy — either require pinned keys or require `--insecure`
2. `--config` + `--insecure` conflict in agentd — one-line clap fix
3. `credential_references` example assertion mismatch — trivial
4. RPK fallthrough to cert-TLS — add explicit bail

**Acceptable as-is:**
5. `server-type` routing — only accounting is implemented; no real routing needed yet
6. `Deref` exposes secrets — documented trade-off, mitigated by Debug redaction
7. `tls13_epsks` flag — validation metadata, not a connection selector
8. External refs from binaries — clear error now; needs plugin/resolver infrastructure

---

*Individual reviews: [review-opus.md](review-opus.md) | [review-gpt.md](review-gpt.md)*
