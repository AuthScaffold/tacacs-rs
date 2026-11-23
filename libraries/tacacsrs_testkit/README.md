# tacacsrs-testkit

Shared test fixtures for cross-crate integration, TLS/PSK, revocation, and wire fault-injection tests.

This crate is excluded from workspace `default-members` and forbidden from the `supported-core` production dependency closure in `.github/steps/check-architecture/rules.json`.

## Contents

- `pki`: Fast ECDSA P-256 certificate authority, server and client leaf identities, X.509 v2 CRL signing, and OpenSSL TLS 1.3 server contexts.
- `psk_peer`: OpenSSL TLS 1.3 external pre-shared key (`psk_ke` and `psk_dhe_ke`) server callback fixture, including SHA-256 and SHA-384 cipher binding.
- `upstream`: Scripted plain-TCP and TLS 1.3 TACACS+ upstream server with per-request fault injection and handshake stall helpers.
