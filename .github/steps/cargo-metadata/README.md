# Cargo metadata inventory

`workspace.py` supplies Cargo-authoritative workspace facts to the release
steps. Version discovery, manifest hydration, and CI reporting read the same
inventory. Directory names and regular expressions decide nothing.

## Release product registry

[`.github/products.json`](../../products.json) is the only production inventory
of release products. Cargo workspace membership does not enroll a release
product. Version discovery still covers workspace crates under the existing
SemVer and CalVer policy.

`products.py` validates the registry through `load_metadata` and `inventory`.
It checks workspace membership, package paths, exact target names, target kinds,
crate types, declared features, and target-required features. It rejects empty
registries, duplicate products, unknown fields, and incomplete policies.

Each record declares its runner, target triple, asset name, package, artifact,
features, packaging, and SBOM policy. Default features remain enabled. Linux
packages use TAR/Gzip archives, split release debug symbols, and system OpenSSL.
Windows packages use ZIP archives, PDB files, and bundled OpenSSL DLLs. Both
platforms retain dynamic linkage and require JSON and XML SBOMs. Debug rehearsal
builds retain their existing behavior without separate debug files.

The validator accepts only policies that the current packaging scripts support.
Policy fields document and validate those scripts. They do not replace the
scripts. A product or platform policy change requires separate authorization.

The reusable workflow derives its matrix in the required `product-registry`
job. Both workflow callers use this job without product overrides or defaults.
The job emits one `products` output containing a JSON array. Each record keeps
the existing nine matrix fields. The build and architecture checks consume this
output.

The Linux rehearsal invokes the same tool from the exported source revision.
It validates the complete registry before it selects Linux records for the
requested target. An empty selection fails before hydration or builds.

```bash
python3 .github/steps/cargo-metadata/products.py --workspace .
python3 .github/steps/cargo-metadata/products.py \
  --workspace . --linux --target x86_64-unknown-linux-gnu
```

`--github-output PATH` also appends the compact JSON array as `products=<JSON>`.
A validation error emits no matrix and exits nonzero.

When an authorized product change occurs, update the registry and the
independent expectations in `test_products.py`. Do not derive expected policy
from the registry. The tests preserve the four Linux records and the single
Windows direct-mode `tacon` record. Experimental products remain excluded.

## Public API

### `load_metadata(workspace, *, target=None, all_features=False, locked=True, no_deps=False) -> dict`

Run `cargo metadata --format-version 1` and return the parsed JSON object.

- `target`: filter the resolved graph to one target triple
  (`--filter-platform`).
- `all_features`: enable every feature (`--all-features`).
- `locked`: require an up-to-date `Cargo.lock` (`--locked`).
- `no_deps`: read only the workspace manifests (`--no-deps`). Version discovery
  and hydration use this mode. It does not need a native build or network
  access.

Raises `MetadataError` when Cargo fails or returns output that is not a JSON
object.

### `inventory(metadata) -> dict`

Turn a `cargo metadata` object into a deterministic inventory. The result
contains only workspace members, even when the input lists resolved dependency
packages. Packages sort by name then package id. Each package's dependencies
sort by identity.

```json
{
  "workspace_root": "/abs/workspace",
  "packages": [
    {
      "id": "path+file:///abs/workspace/libraries/foo#foo@0.0.0-dev",
      "name": "foo",
      "version": "0.0.0-dev",
      "manifest_path": "libraries/foo/Cargo.toml",
      "directory": "libraries/foo",
      "default_member": true,
      "target_kinds": ["lib"],
      "dependencies": [
        {
          "name": "bar",
          "source": null,
          "rename": null,
          "kind": null,
          "target": null,
          "optional": false,
          "workspace_member": "bar"
        }
      ]
    }
  ]
}
```

Field notes:

- `manifest_path` and `directory` are relative to `workspace_root`.
- `target_kinds` is the sorted union of every target kind, so a dual
  `crate-type = ["cdylib", "rlib"]` library reports `["cdylib", "rlib"]`.
- A dependency `kind` is `null` for a normal edge, `"build"` for a build edge,
  or `"dev"` for a development edge.
- `rename` is the local alias of a renamed dependency. `name` is always the real
  package identity.
- `workspace_member` is the real member name when a path edge resolves to a
  workspace member, or `null` otherwise. The resolution uses the dependency's
  canonical manifest path, not its directory name, so renamed and inherited
  (`workspace = true`) edges still resolve.

## Command line

```bash
python workspace.py --workspace . > inventory.json
python workspace.py --resolved --target x86_64-unknown-linux-gnu
```

`--resolved` resolves the full dependency graph. `--no-locked` drops the
`--locked` requirement.

## Tests

```bash
python3 -m pytest .github/steps/cargo-metadata
```

The `inventory` tests build synthetic metadata and do not need Cargo. The
`load_metadata` tests build a real minimal workspace and run Cargo.
`test_products.py` holds the independent release policy goldens. Its workflow
and action checks need PyYAML. Its composite action test runs Cargo.
