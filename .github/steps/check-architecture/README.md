# Check Architecture

This step enforces the tacacs-rs production dependency architecture. It reads
resolved, platform-filtered Cargo metadata and checks it against
[`rules.json`](rules.json). Cargo is the authority. Directory names and regular
expressions do not decide workspace membership or dependency identity.

## What it checks

1. **Workspace edge allowlist.** Every production (normal) edge from one
   workspace package to another must be in the allowlist. The validator rejects
   an unknown workspace package and any edge that is not listed.
2. **External and transitive guards.** The validator preserves the eight guards
   that used to run inline in `.github/steps/run-tests/action.yml`. For example,
   the protocol package must not reach Tokio or OpenSSL, and the agent must not
   reach the IPC crate.
3. **Supported-core exclusion.** The production closure of the workspace default
   members must not reach the experimental crates, Rego, or libseccomp.

The validator uses `resolve.nodes[].deps[].dep_kinds` and the platform-filtered
resolve graph, not the declared manifest dependency list. Only normal edges
count for the production rules. Development-only and build-only edges are
ignored. Dependency identity resolves through the package id, so an aliased or
renamed dependency still maps to its real crate.

## Rule model

`rules.json` has two sections.

`allowed_workspace_edges` maps each of the 17 workspace packages to the set of
other workspace packages it may depend on through production edges. The set is a
superset across supported platforms. A platform-specific edge, such as
`tacon -> tacacsrs-ipc` on Linux, is listed once. Platform filtering removes it
on other platforms, and an absent edge is never required.

`forbidden_dependency_guards` lists the eight external and transitive guards.
Each guard names its roots and the forbidden tokens. A token matches a package
with that exact name or any crate under the `token-` prefix, which mirrors the
`^token[ -]` word boundary from the old awk guards. The `supported-core` guard
uses the special `roots` value `default-members`, which resolves to
`workspace_default_members` from the metadata.

### Preserved guards

| Guard | Roots | Forbidden tokens |
| --- | --- | --- |
| `pure-protocol` | `tacacsrs-protocol` | tokio, openssl, tonic, prost, redis, tacacsrs-config, tacacsrs-networking, tacacsrs-agent |
| `provider-neutral-credentials` | `tacacsrs-credential-resolution` | tokio, openssl, tonic, prost, redis, tacacsrs-config, tacacsrs-networking, tacacsrs-agent, tacacsrs-sonic |
| `schema-free-networking` | `tacacsrs-networking` | tonic, prost, redis, tacacsrs-config, tacacsrs-credential-resolution, tacacsrs-agent, tacacsrs-sonic |
| `configuration-adapter` | `tacacsrs-config` | clap, tonic, prost, redis, tacacsrs-agent, tacacsrs-sonic |
| `ipc-independent-agent` | `tacacsrs-agent` | tonic, prost, tacacsrs-ipc |
| `runtime-independent-ipc` | `tacacsrs-ipc` | redis, tacacsrs-config, tacacsrs-networking, tacacsrs-credential-resolution, tacacsrs-agent, tacacsrs-sonic |
| `unix-socket-leaf` | `tacacsrs-unix-socket` | tonic, prost, redis, openssl, tacacsrs-protocol, tacacsrs-config, tacacsrs-networking, tacacsrs-agent, tacacsrs-ipc |
| `supported-core` | default members | session-wrapper, tacacsrs-agent-ipc-emulator, tacacsrs-agent-ipc-emulatord, regorus, libseccomp |

## Cargo metadata helper

The command-line entry point loads metadata through the sibling step
`.github/steps/cargo-metadata/workspace.py`. It adds that directory to
`sys.path` at entry and calls
`load_metadata(workspace, target=..., all_features=..., locked=True)`.

The pure validation functions take standard `cargo metadata` JSON as a plain
dict. They do not import the helper, so the tests inject synthetic metadata
directly. For a self-contained run, pass `--metadata-file` with a pre-resolved
metadata JSON instead of using the helper.

## Command-line usage

```bash
# Resolve and validate for a specific target.
python check_architecture.py --workspace . --target x86_64-unknown-linux-gnu --all-features

# Validate a pre-resolved metadata file and write a plain-JSON report.
python check_architecture.py --metadata-file metadata.json --metadata-report report.json
```

The validator exits non-zero and prints each error when it finds a violation.

## Action usage

Run the check for each supported target. Linux and Windows resolve different
platform graphs.

```yaml
- name: Check architecture (Linux)
  uses: ./.github/steps/check-architecture
  with:
    target: x86_64-unknown-linux-gnu
    all-features: 'true'

- name: Check architecture (Windows)
  uses: ./.github/steps/check-architecture
  with:
    target: x86_64-pc-windows-msvc
    all-features: 'true'
```

Wiring this step into the CI workflow and removing the inline guards from
`run-tests` is a separate integration task.

## Tests

```bash
python3 -m pytest .github/steps/check-architecture
```

The tests are hermetic. They build synthetic metadata from the shipped
`rules.json`, then inject each failure category: every forbidden guard, an
unknown member, an unlisted production edge, allowed development and build
edges, a platform-filtered edge, renamed dependencies, and product matrix
mismatches.

## Maintenance

When you add a workspace crate or a production edge, update
`allowed_workspace_edges`. When you add an external boundary, update
`forbidden_dependency_guards`. The `test_rules_cover_seventeen_packages` test
and the golden metadata test keep the rules in step with the workspace.
