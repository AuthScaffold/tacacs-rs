# Independent TACACS+ Server Tests

## Native Build

The [Compose fixture](../lde/containers/compose.yml) uses Marc Huber's `tac_plus-ng` through an upstream image recipe.
You can build that server inside the development container without Docker, privileged ports, or a system installation.
The native test runner uses temporary copies of the [same configuration](../lde/containers/config/tac_plus.cfg).
Only use its public test credentials on isolated test listeners.

The verified server revision is `70bf938b542d63bca00d50be0874a38a290319e0` from `MarcJHuber/event-driven-servers`.
Its version output reports `278d8c738cfb2ed8ba505fd1b60575fcc3fadca5` from the upstream version marker.
The newer `be56730a003d3d2aed372f49ef0c0a8f478e1520` did not compile with OpenSSL 3.0 because of an upstream certificate-parser typo.
The evidence uses the unmodified pinned revision, not a patched server.

Prerequisites are Git, GCC/Make, Perl, pkg-config, OpenSSL 3.0 development headers, PCRE2, libcrypt, and zlib.
Debian package names are `build-essential`, `perl`, `pkg-config`, `libssl-dev`, `libpcre2-dev`, `libcrypt-dev`, and `zlib1g-dev`.
The current development container already provides the required build dependencies.

From the repository root, run:

```bash
workspace="$PWD"
build_root=$(mktemp -d /tmp/tacacs-rs-interop.XXXXXX)
git clone --depth 1 https://github.com/MarcJHuber/event-driven-servers.git "$build_root/server"
git -C "$build_root/server" fetch --depth 1 origin 70bf938b542d63bca00d50be0874a38a290319e0
git -C "$build_root/server" switch --detach FETCH_HEAD
pushd "$build_root/server"
./configure --prefix="$build_root/install" --with-cc=cc --with-ssl --with-pcre2 \
  --without-curl --without-ares --without-pam --without-ldap \
  --without-freeradius --without-radcli --without-doc tac_plus-ng
make -j2
popd
server_binary=$(find "$build_root/server/build" -type f -path '*/tac_plus-ng/tac_plus-ng' -print -quit)
library_dir="$(dirname "$(dirname "$server_binary")")/mavis"
python3 "$workspace/lde/run-tacplus-interop.py" \
  --server-binary "$server_binary" --library-dir "$library_dir"
```

The upstream build installs supporting files into its temporary build tree. Do not run a privileged `make install`.
The runner prints the server version and keeps generated configurations and logs in a new temporary directory.
It allocates loopback ports, validates each server configuration, and runs the server with `-f -1` and a private PID file.
It terminates and reaps that process after each scenario, including failed tests.
Port allocation has a small release-to-bind race. A bind failure stops the run; the runner does not replace an existing listener.

To run one scenario, add `--mode baseline`, `--mode mutual-tls`, `--mode psk-only`, `--mode sha384`, or `--mode plain-tcp`.
The tests are ignored in ordinary workspace runs because they require this external server.

## Verified Matrix

Validation ran on Linux with OpenSSL 3.0.20 and PCRE2 10.42.
Each successful transport performs PAP authentication, shell-command authorization, and three accounting exchanges through one prepared client.
The client requests single-connection mode. The fixture allows it; these tests do not count server-side TCP connections.

| Scenario | Server policy | Result |
| --- | --- | --- |
| TCP with obfuscation | Fixture shared secret | All operations pass |
| TCP without obfuscation | Explicit `bug compatibility = 64` test variant | All operations pass |
| Certificate TLS | Fixture CA trusted by the client | All operations pass |
| Client certificate TLS | Fixture client certificate and key | All operations pass |
| Required mutual TLS | `tls.peer.cert.validation = cert` | Valid client passes; missing certificate fails |
| SHA-256 PSK-DHE | Fixture key and X25519/P-256 groups | All operations pass |
| SHA-256 PSK-only | Server `auto` mode with disjoint P-224 group list | All operations pass without DHE |
| SHA-384 PSK-DHE | Server cipher list restricted to `TLS_AES_256_GCM_SHA384` | All operations pass |

Certificate verification stays enabled on the client, including the configured IP identity check.
The configuration crate's native identity matrix separately covers mismatched SANs, SNI selection, CN-only rejection, and wildcard rules.
The fixture permits the test user's password and command. It is not a production identity-policy test.
The plain-TCP variant needs `AllowPlainTcpWithoutSharedSecret` on the client and the server's explicit un-obfuscated compatibility bit.
It does not change the default fixture's security policy.

The server's `no-dhe` setting requires a preference option absent from OpenSSL 3.0.
The test instead uses `auto` with a disjoint group list, which permits a real no-DHE exchange.
The client independently enforces the selected PSK mode before sending TACACS+ data.
The SHA-384 variant selects only its matching cipher because this server associates the PSK session with its configured cipher choice.

The original fixture enabled PSK on the listener but omitted realm-level `tls psk = yes`.
That omission caused certificate fallback, which the client rejected. The checked-in fixture now enables PSK at both levels.

## Existing Server or Compose

For a running peer with the corrected default fixture, run:

```bash
TACPLUS_TCP_ADDR=127.0.0.1:4949 \
TACPLUS_TLS_ADDR=127.0.0.1:4449 \
TACPLUS_PSK_ADDR=127.0.0.1:4450 \
cargo test -p tacacsrs-agentd --test tacplus_interop --locked -- \
  --ignored --skip psk_only_operations --skip psk_sha384_operations \
  --skip missing_client_certificate_is_rejected --skip plain_tcp_operations --test-threads=1
```

All addresses must be socket addresses. Use an address reachable from the development container, not the container's loopback for a host-side server.
The current Compose build tracks moving upstream branches. A future upstream failure can break it independently of this repository.
The pinned native build above provides the recorded reproducible alternative.

## Docker Access Options

Native execution is sufficient for these checks. Docker-in-Docker is not required.
If container-engine access is needed for other workflows, use Docker-outside-of-Docker: install the CLI and connect it to the host engine.
The standard Dev Containers feature is `ghcr.io/devcontainers/features/docker-outside-of-docker:1`.
On Docker hosts, it can provide the CLI, socket mount, and non-root socket permissions after a container rebuild.
Verify the host engine and feature requirements before changing the launch configuration.

Host-engine socket access is effectively host-administrator access. Enable it only for trusted workspaces.
Do not solve socket permissions with a world-writable Docker socket or expose an unauthenticated TCP daemon.
Podman requires its own compatible socket configuration; do not assume a Docker socket path exists.

This workspace uses a named source volume, not a host bind mount.
Compose bind paths are interpreted by the engine host, so `./config` inside the development container is not automatically a valid host path.
Either run Compose from an updated host checkout or mount the existing source volume into the peer and adjust its configuration paths.
Do not assume the read-only seed checkout contains current native-volume edits.
No Docker socket, feature, or container privilege was added during this validation.