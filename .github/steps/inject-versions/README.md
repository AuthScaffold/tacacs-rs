# Version hydration

`hydrate_versions.py` applies the computed version map to workspace manifests and `Cargo.lock`.
Cargo metadata remains the authority for workspace membership.
The tool does not discover packages through directory scans.

## Requirements

The release tooling requires Python 3.11 or later and Cargo.
Install the pinned TOML dependency before local hydration or a local release rehearsal:

```bash
python -m pip install -r .github/steps/inject-versions/requirements.txt
python .github/steps/inject-versions/hydrate_versions.py \
  --workspace . --versions '{"tacon":"2026.1020.1"}'
```

The composite action installs this same requirements file before hydration.
The delivery tests install it before they import the hydrator.
The development image carries the same version.
A contract test compares these environments against the canonical pin.
Local rehearsal does not install tools or contact package indexes.

## Editing contract

The tool edits only each selected member's direct `package.version`.
Inherited workspace versions remain unsupported.
The tool retains comments, unknown fields, unrelated dependency tables, and line endings.
An edited string can change its quote style.
Unchanged values and their surrounding content remain intact.
Repeated hydration produces the same content.

The tool selects lock entries by package name and the absence of a `source` field.
It rejects duplicate source-free entries for a selected name.
Same-name registry and Git packages retain their versions.
Version-qualified references to a changed source-free package receive its new version.
Unqualified references and source-qualified external references remain unchanged.
Package aliases in manifests remain unchanged.

The release product registry, version policy, and generated release branch remain unchanged.
Artifact, provenance, SBOM, and no-publish rehearsal behavior also remain unchanged.

## TOML Kit evaluation

The bounded prototype accepted TOML Kit 0.15.2 on October 20, 2026.
The prototype used a separate virtual environment and a 45-minute limit.
The bounded phase ran from `06:17:02` to `06:26:05` UTC (9 minutes, 3 seconds).
The evaluation stopped after the required comparisons and concrete deletion checks passed.
It did not add a Rust executable.

Authoritative package evidence:

- [PyPI version metadata](https://pypi.org/pypi/tomlkit/0.15.2/json) reports version `0.15.2`, license expression `MIT`, and Python `>=3.9`.
- The installed wheel's `METADATA` reports the same values and no `Requires-Dist` entries.
- The wheel includes the MIT license at `tomlkit-0.15.2.dist-info/licenses/LICENSE`.
- The [upstream repository](https://github.com/python-poetry/tomlkit) owns the package source.
- The evaluated wheel's SHA-256 is `05562412163a3037b94497385fb7f9204c637bc605af7a48199e41cf2272f437`.

Adoption adds one Python runtime dependency and no transitive Python runtime dependencies.
The existing release tooling minimum remains Python 3.11.
The Rust product MSRV remains 1.88.
No Rust manifest or lockfile changes result from this adoption.

The existing Rust tool is the isolated API classifier.
Its owner is public-API analysis, not release hydration.
Adding hydration there mixes unrelated ownership and requires its Rust 1.91 toolchain.
Therefore, this evaluation did not prototype `toml_edit` or select a version for it.

### Production deletion map

| Existing implementation | Replacement |
| --- | --- |
| `PACKAGE_SECTION_RE` | TOML Kit package table access |
| `VERSION_LINE_RE` | TOML Kit string assignment |
| `LOCK_PACKAGE_RE` | TOML Kit package array access |
| `lock_package_name` | Structured package name access |
| Section offsets, body slices, block reconstruction, and cursor assembly | TOML Kit serialization |

The version input guard and Cargo metadata inventory remain.
The new lock-reference update associates exact source-free identities.
It does not introduce another parser or dependency-discovery system.
The predecessor did not update version-qualified lock references.
The regression tests cover this required correction.

### Comparison evidence

The prototype compared unchanged predecessor functions against independent golden content.
Both semantic comparisons and unaffected-content comparisons passed.
The comparison also covered all 17 actual workspace manifests and the actual lockfile.
The accepted tests preserve these goldens without copying the predecessor implementation.
The final focused prototype run passed 138 tests.
The separate fixture-based rehearsal passed one test.

The cases cover:

- Canonical manifests and lockfiles.
- Comments on keys, table headers, and array elements.
- Quoted keys, quoted table headers, dotted keys, inline tables, and multiline strings.
- LF and CRLF line endings.
- Unknown fields and nested metadata.
- Idempotence and source-free selection.
- Same-name registry and Git packages, including an external package at the old workspace version.
- Correct association of version-qualified references.
- Duplicate source-free entries and malformed TOML.
- Real Cargo metadata selection, exclusions, and alternate valid manifest layouts.

The initial prototype asserted identical quotes for edited strings.
That assertion was too strict.
The final goldens permit quote changes only for edited literals.
The malformed-input tests also identified a separate TOML Kit duplicate-key exception.
The accepted implementation translates all `TOMLKitError` exceptions to `HydrationError`.

## Validation

Use an isolated test directory outside the source checkout.
This prevents Cargo from discovering test fixtures as implicit workspace members.

```bash
PYTHONDONTWRITEBYTECODE=1 python -m pytest -p no:cacheprovider \
  --basetemp="$CARGO_TARGET_DIR/hydration-tests" \
  .github/steps/inject-versions .github/steps/compute-versions
```

The relevant delivery suites also cover Cargo metadata, architecture, and release manifests.
The fixture rehearsal runs the real hydration and packaging CLIs without product compilation or publication.
Fixture binaries and SBOM generation do not prove native product builds.
This tool-only change does not require unrelated Rust rebuilds.
