# Cargo metadata inventory

`workspace.py` supplies Cargo-authoritative workspace facts to the release
steps. Version discovery, manifest hydration, and CI reporting read the same
inventory. Directory names and regular expressions decide nothing.

## Source release inventory

Source releases use Cargo workspace membership, not a product registry.
Version discovery retains the library SemVer and executable CalVer policy.
The source-release helper uses this inventory to detect managed crates and list every crate version in release notes.
The platform validation matrix declares Linux and Windows package selections.
Each platform job uploads its hydrated Cargo inventory.
Architecture validation retains the resolved dependency rules and supported-core guards.

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
Source publication and workflow contract tests live in `../source-release`.
