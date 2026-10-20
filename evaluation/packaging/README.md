# Local cargo-dist prototype

## Decision and boundary

Do not adopt cargo-dist 0.33.0 for the current release pipeline.
The bounded evaluation ran from `2026-10-20T10:50:23Z` to `2026-10-20T10:57:07Z` (6 minutes, 44 seconds).
The configured plan lacks required symbols and JSON SBOMs.
The pinned source disables symbol artifacts for both required operating systems.
The evaluation stopped before compilation because the required built-in artifact route failed.

This decision does not state that arbitrary custom commands cannot produce these files.
Custom commands must retain the current native, SBOM, and provenance work.
No complete production script has a demonstrated replacement.
Native Windows and ARMhf artifact evidence also remains unavailable in this evaluation.

## Expected production output

The committed `.github/products.json` defines five records:

- Linux `tacon`, `tacacsrs-agentd`, and `tacacsrs-agent-health` executables.
- Linux `libtacacsrs_bash_plugin.so`.
- Windows direct-mode `tacon.exe`.

Each Linux TAR/Gzip archive contains its named root directory, payload, required JSON/XML SBOMs, and `build-provenance.json`.
Release payloads also require separate `.debug` files and matching `.gnu_debuglink` sections.
The Windows ZIP requires its named root directory, executable, PDB, OpenSSL DLLs, JSON/XML SBOMs, and provenance.
The existing provenance finalizer verifies source, hydrated versions, schema identities, archive contents, and file digests offline.
Library SemVer, executable CalVer, and append-only hydrated release commits remain requirements.
ARMhf execution remains an independent required gate.

The initial deletion candidates were `build-binary`, `stage-binary-package`, `package-debug-symbols`, and the two archive actions.
Adoption also required preservation of SBOM staging, native dependencies, registry selection, and provenance.
Archive compression alone does not satisfy this deletion criterion.

## Tool identity and cost

- Official release: <https://github.com/axodotdev/cargo-dist/releases/tag/v0.33.0>.
- Pinned source commit: `a1c829ffacb7ce98fb617b7acd7ffdd2282b45c2`.
- License: `MIT OR Apache-2.0`, from the source workspace and binary distribution.
- Declared source Rust minimum: `1.74`, inherited by `cargo-dist`.
- Release builds enable `fear_no_msrv`. A source build at Rust 1.74 was not attempted.
- The official release manifest reports Cargo `1.97.1` for its Linux binary build.
- That manifest's `dist_version = 0.32.0` identifies its packaging tool, not the evaluated executable.
- The downloaded executable reports `cargo-dist 0.33.0`.
- The source package declares 41 normal dependencies and three development dependencies.
- The complete lockfile contains 444 entries, including workspace, other-target, and development entries.
- Those 444 entries are not a resolved normal dependency closure.
- No source dependency closure or effective source-build MSRV is claimed.
- The binary needs `libc`, `libm`, and `libgcc_s` on this host.
- Its highest referenced GLIBC symbol version is `GLIBC_2.34`.
- The archive occupies 6,420,632 bytes. The executable occupies 27,837,824 bytes.
- The binary introduces no linked OpenSSL dependency on this host.
- Product builds still need their existing native dependencies.
- Planning needs Cargo and a readable workspace.
- The existing `cargo-cyclonedx 0.5.9` is available. The prototype installs no SBOM tool.
- No global tool, dependency, Cargo manifest, or lockfile changed.
- The product Rust minimum remains `1.88`.

The archive SHA-256 is:

```text
4b3f0a5f0ebbdb798f6db649d01b32ba1518376b6f7a0502b7d92b75cc2c8293
```

The executable SHA-256 is:

```text
1ecb03737291ce5abf0e08b411f34812b974de4e405a33cdc53e8db39d70ee98
```

## Configuration and observations

`evaluate_dist.py` exports predecessor `d3629b2ee0f78c862e7a4d8fb7558622c6f6591a` through read-only `git archive`.
It validates the five records through the existing Cargo-backed registry tool.
It derives all package and target selections from that registry.
There is no second persistent product inventory.

The script edits only the exported fixture.
It sets workspace `dist = false` and selected-package `dist = true`.
It enables `package-libraries = ["cdylib"]` for the Bash plugin.
It sets explicit `publish = false` on selected fixture packages.
The production manifests do not currently declare that field.
Thus, this override tests the documented internal-package route rather than a production manifest fact.

The configuration uses `ci = []`, `hosting = []`, `installers = []`, and `source-tarball = false`.
The script never calls `init`, `generate`, `build`, hosting, or publication commands.
`--allow-dirty` skips generated-file freshness checks.
It does not authorize a Git mutation.
No release workflow is generated.

The configured plan contains:

- Five executable/library archives and five archive checksum files.
- One unified checksum file.
- Four separate XML SBOM artifacts.
- No JSON SBOM, symbol artifact, or embedded build-provenance record.
- Exactly the five required package/target/payload tuples.
- No hosting provider.

The archive names use cargo-dist target triples instead of the current registry asset names.
The cdylib plan asset has kind `c_dynamic_library`.
These are planning observations, not proof of filenames or bytes in a native archive.

The script then uses the accepted hydrator for three executable CalVer values and one library SemVer value.
Four singular plans select the expected package and hydrated version.
Executable arguments use `PACKAGE-2026.1020.18`.
The library argument uses `tacacsrs-bash-plugin-v1.2.3`.
These `--tag` arguments simulate selection only. They create no Git refs.
They do not prove a real release, generated release branch, or append-only history.

## Source evidence and deletion assessment

The pinned upstream source supplies these checks:

- `cargo-dist/src/tasks.rs:3277`: `target_symbol_kind` returns `None` for Windows, Apple, and Linux.
- `cargo-dist/src/tasks.rs:1640`: the built-in SBOM artifact is global and named `PACKAGE.cdx.xml`.
- `cargo-dist/src/tasks.rs:2842`: the build planner assumes that the SBOM already exists.
- `book/src/reference/config.md`: `dist` documents the explicit `publish = false` override.
- That reference also documents `package-libraries`, `cargo-cyclonedx`, `extra-artifacts`, and generic `package.build-command`.

JSON/XML generation, sanitization, target selection, and archive inclusion still need the current SBOM tools or equivalent custom code.
Split ELF symbols and Windows PDB packaging still need custom work.
Windows OpenSSL DLL staging and source/version/provenance checks also remain.
The generic local build-command route can call existing scripts, but that route does not remove their responsibilities.
Extra artifacts can expose custom outputs, but do not implement those contracts.
No custom adapter was built after the required built-in symbol failure.

| Existing owner | Result |
| --- | --- |
| Cargo-backed product registry | Retain. The prototype derives configuration from it. |
| Version computation and TOML hydration | Retain. External version policy stays authoritative. |
| `build-binary` | No proven deletion. Native product builds did not run. |
| `stage-binary-package` | No proven deletion. Required pre-archive staging remains. |
| `package-debug-symbols` | Retain or recreate. Built-in symbol artifacts are disabled. |
| `collect-openssl-runtime` | Retain. Native Windows DLL equivalence is unverified. |
| SBOM generation and staging | Retain or recreate. Both formats and sanitization remain necessary. |
| Linux and Windows archive actions | Compression overlaps, but complete package equivalence is unverified. |
| Build provenance and release manifest | Retain. cargo-dist metadata does not implement schema version 2. |
| ARMhf gate and release history policy | Retain unchanged. Planning does not exercise either contract. |

The demonstrated deletion set is empty.

## Replay

Use the prototype worktree.
Use a fresh output directory for each replay.
The existing Python environment supplies TOML Kit 0.15.2, pytest 8.4.2, and PyYAML 6.0.3.

```bash
source /etc/profile.d/tacacs-rs.sh
cd /home/ubuntu/tacacs-rs-18-packaging-evaluation-prototype
export CARGO_TARGET_DIR=/home/ubuntu/.cache/tacacs-rs-18-packaging-evaluation-prototype
export CARGO_BUILD_JOBS=4
export PYTHONDONTWRITEBYTECODE=1
export TMPDIR="$CARGO_TARGET_DIR/iteration18-evidence/scratch"
mkdir -p "$TMPDIR" "$CARGO_TARGET_DIR/iteration18-evidence/tool"
cd "$CARGO_TARGET_DIR/iteration18-evidence/tool"
curl --fail --silent --show-error --location \
  https://github.com/axodotdev/cargo-dist/releases/download/v0.33.0/cargo-dist-x86_64-unknown-linux-gnu.tar.xz \
  -o cargo-dist-x86_64-unknown-linux-gnu.tar.xz
printf '%s  %s\n' \
  4b3f0a5f0ebbdb798f6db649d01b32ba1518376b6f7a0502b7d92b75cc2c8293 \
  cargo-dist-x86_64-unknown-linux-gnu.tar.xz | sha256sum --check
tar -xf cargo-dist-x86_64-unknown-linux-gnu.tar.xz
cd /home/ubuntu/tacacs-rs-18-packaging-evaluation-prototype
python evaluation/packaging/evaluate_dist.py \
  --tool "$CARGO_TARGET_DIR/iteration18-evidence/tool/cargo-dist-x86_64-unknown-linux-gnu/dist" \
  --output "$CARGO_TARGET_DIR/iteration18-evidence/replay-new"
```

The script checks the executable hash before it runs the plans.
Its output directory contains exported source, stdout, stderr, exit files, plan summaries, and results.
The export is a fixture, not an independently committed release source.

```bash
source /etc/profile.d/tacacs-rs.sh
cd /home/ubuntu/tacacs-rs-18-packaging-evaluation-prototype
export CARGO_TARGET_DIR=/home/ubuntu/.cache/tacacs-rs-18-packaging-evaluation-prototype
export CARGO_BUILD_JOBS=4
export PYTHONDONTWRITEBYTECODE=1
export TMPDIR="$CARGO_TARGET_DIR/iteration18-evidence/scratch"
python -m pytest -q -p no:cacheprovider \
  --basetemp="$CARGO_TARGET_DIR/iteration18-evidence/pytest-new" \
  .github/steps/cargo-metadata .github/steps/inject-versions \
  .github/steps/compute-versions/test_api_analysis.py \
  .github/steps/compute-versions/test_compute_versions.py::TestParseSemver \
  .github/steps/compute-versions/test_compute_versions.py::TestBumpPatch \
  .github/steps/compute-versions/test_compute_versions.py::TestBumpBreaking \
  .github/steps/compute-versions/test_compute_versions.py::TestBumpMinor \
  .github/steps/compute-versions/test_compute_versions.py::TestDiscoverLibraries \
  .github/steps/compute-versions/test_compute_versions.py::TestTopologicalSort \
  .github/steps/release-manifest
```

## Executed checks

The initial runner, corrected runner, and final replay each exited `0`.
The final runner covers explicit `publish = false`, cdylib selection, artifact shapes, disabled hosting, and four hydrated singular plans.
The corrected final runner is the authoritative replay.
The initial runner did not yet assert artifact shapes or set explicit `publish = false`.
The original broad suites passed: **327 passed, zero skipped**, exit `0`.
That selection also ran version tests that created **52 annotated tags in private pytest fixture repositories**.
Those fixture tags breached this experiment's no-tag restriction.
No source or remote refs changed.
No tag deletion or cleanup occurred.
`iteration18-evidence/fixture-tag-disclosure.json` lists every affected private ref.
The replay now selects only the audited version unit tests and API tests.
Do not rerun the whole `compute-versions` directory under this experiment's restrictions.
The provenance export regression uses an isolated fixture commit, which the task permits.
Rust 1.88 `cargo metadata --no-deps --locked --format-version=1` accepted the initial and final hydrated exports, exit `0`.
The final metadata confirms four explicit `publish = false` values.
This metadata check is not a build.

The crates.io HTTP API returned `403`.
Official GitHub source metadata supplied the version, license, and declared Rust minimum instead.
An accidental `dist help --help` probe exited `2`.
Two exploratory source/summary probes failed because of an absent upstream path and nullable asset lists.
Corrected probes and the final runner passed.
These exploratory errors do not count as tool capability failures.

No native product artifact, Linux rehearsal, Windows artifact, or ARMhf execution ran.
No parser success, plan, or fixture substitutes for those checks.
No unrelated Rust rebuild, Miri run, dependency audit, or coverage claim applies to this documentation-only decision.
