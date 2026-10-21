# Local cargo-dist Packaging Evaluation

This document records the historical binary-packaging evaluation.
The [source-only release process](release-rehearsal.md) supersedes its decision to retain distribution packaging.
The evaluation evidence remains unchanged.

## Decision

Do not adopt cargo-dist 0.33.0 for the current release pipeline.
Keep the product registry, accepted TOML hydration, packaging scripts, and release policy.
The configured built-in artifact route fails required symbol and JSON SBOM contracts.
No complete production script has a demonstrated replacement.

The bounded evaluation ran on October 20, 2026, from `10:50:23` to `10:57:07` UTC (6 minutes, 44 seconds).
Final replay and initial source checks finished by `10:59:42` UTC (9 minutes, 19 seconds from the start).
The corrected safety disclosure and final prototype source checks finished by `11:03:15` UTC (12 minutes, 52 seconds from the start).
The limit was 45 minutes.
The evaluation stopped before native builds after the required built-in symbol failure.

This decision does not mean that cargo-dist cannot run custom artifact commands.
Such commands must retain or recreate the current symbol, SBOM, native-library, and provenance work.
The documented custom routes do not establish a complete script deletion.
Native Windows and ARMhf artifact equivalence also remains unverified.
Plans and fixtures do not replace native evidence.

## Tool Facts

The [official release](https://github.com/axodotdev/cargo-dist/releases/tag/v0.33.0) supplies the evaluated Linux GNU executable.
The pinned [workspace manifest](https://github.com/axodotdev/cargo-dist/blob/a1c829ffacb7ce98fb617b7acd7ffdd2282b45c2/Cargo.toml) and [package manifest](https://github.com/axodotdev/cargo-dist/blob/a1c829ffacb7ce98fb617b7acd7ffdd2282b45c2/cargo-dist/Cargo.toml) supply its declared package requirements.

| Item | Verified fact |
| --- | --- |
| Version | The executable reports `cargo-dist 0.33.0`. |
| Source commit | `a1c829ffacb7ce98fb617b7acd7ffdd2282b45c2` |
| License | `MIT OR Apache-2.0`. The archive contains both license files. |
| Declared source Rust minimum | `1.74`, inherited by the `cargo-dist` package. |
| Source-build limitation | Release builds enable `fear_no_msrv`. The effective source-build minimum was not tested. |
| Official build toolchain | The release manifest records Cargo `1.97.1` for the Linux build. |
| Dependency declarations | 41 normal and three development dependencies in the source package. |
| Complete source lockfile | 444 entries, including workspace, other-target, and development entries. This is not the normal dependency closure. |
| Binary dependencies | Host `ldd` resolves `libc`, `libm`, and `libgcc_s`, plus the ELF loader. |
| Binary ABI observation | The highest referenced GLIBC symbol version is `GLIBC_2.34`. This is not a complete portability test. |
| Download size | 6,420,632 bytes for the compressed Linux GNU archive. |
| Executable size | 27,837,824 bytes. |
| Product build requirements | Existing OpenSSL, libseccomp, platform tools, and Cargo requirements remain. |
| SBOM helper | The project pins `cargo-cyclonedx 0.5.9`. Host installation is unverified. No helper installation or execution occurred. |
| Integration dependency cost | Zero. No executable, dependency, manifest, lockfile, or production configuration enters integration. |

The official manifest's `dist_version = 0.32.0` identifies its packaging tool.
It does not change the evaluated executable's `0.33.0` version.
The source-build Rust minimum and binary runtime requirements are separate facts.
The product Rust minimum remains `1.88`.
No source build of cargo-dist or complete dependency-MSRV check is claimed.

The archive SHA-256 is `4b3f0a5f0ebbdb798f6db649d01b32ba1518376b6f7a0502b7d92b75cc2c8293`.
The executable SHA-256 is `1ecb03737291ce5abf0e08b411f34812b974de4e405a33cdc53e8db39d70ee98`.
The pinned source archive SHA-256 is `37b74af190201c8a9338d3311e02b5d6b174dd187ca913bf3f6077c2fce1ad1d`.
The official checksum file and the downloaded archive agree.
The executable stayed in the prototype cache. No global tool changed.

## Required Output and Configuration

The [product registry](https://github.com/AuthScaffold/tacacs-rs/blob/8ff903ad5085e08705b4e041da3719ed4ff038a0/.github/products.json) remains the only production authority for product selection.
Its [Cargo-backed validator](https://github.com/AuthScaffold/tacacs-rs/blob/8ff903ad5085e08705b4e041da3719ed4ff038a0/.github/steps/cargo-metadata/README.md#release-product-registry) preserves five records.
Those records cover four Linux products and Windows direct-mode `tacon`.
Workspace enrollment does not select a product.

Linux TAR/Gzip packages require a named root, native payload, split release symbols, JSON/XML SBOMs, and `build-provenance.json`.
Windows ZIP packages require a named root, `tacon.exe`, a PDB, OpenSSL DLLs, JSON/XML SBOMs, and provenance.
The [existing finalizer](https://github.com/AuthScaffold/tacacs-rs/blob/8ff903ad5085e08705b4e041da3719ed4ff038a0/.github/steps/release-manifest/README.md) verifies source, hydrated versions, archive contents, and digests offline.
It also records the YANG and protobuf schema identities.
The [rehearsal guide](https://github.com/AuthScaffold/tacacs-rs/blob/8ff903ad5085e08705b4e041da3719ed4ff038a0/docs/release-rehearsal.md) defines these unchanged contracts.

The prototype exports committed predecessor `d3629b2ee0f78c862e7a4d8fb7558622c6f6591a` through read-only `git archive`.
It derives disposable cargo-dist configuration from the validated registry.
It sets workspace `dist = false` and selected-package `dist = true`.
It enables `package-libraries = ["cdylib"]` for the Bash plugin.
These are [documented configuration controls](https://github.com/axodotdev/cargo-dist/blob/a1c829ffacb7ce98fb617b7acd7ffdd2282b45c2/book/src/reference/config.md).
The pinned reference marks `package-libraries` as an experimental feature.

The fixture explicitly sets `publish = false` on the four selected packages.
Their production manifests do not currently declare that field.
This fixture override proves the documented internal-package selection route.
The evaluation does not mistake the default exclusion of internal packages or libraries for a capability failure.

The configuration sets `ci = []`, `hosting = []`, `installers = []`, and `source-tarball = false`.
Only local `plan` commands run.
`--allow-dirty` skips generated-file freshness checks.
No `init`, `generate`, hosting, announcement, upload, or publication command runs.
The evaluator creates no release workflow, Git tag, fixture commit, source ref, index change, or release branch.
The original broad regression selection did create tags in isolated test repositories, as the safety disclosure explains.

## Results and Limits

The configured plan contains five archives, five archive checksum files, one unified checksum, and four global XML SBOM artifacts.
Its five package/target/payload tuples match the registry.
The Bash plugin asset has kind `c_dynamic_library`.
Archive names use target triples instead of the existing registry asset names.
There are no planned symbol artifacts, JSON SBOMs, or embedded provenance records.
These observations describe plans, not native archive contents.

The pinned [symbol selector](https://github.com/axodotdev/cargo-dist/blob/a1c829ffacb7ce98fb617b7acd7ffdd2282b45c2/cargo-dist/src/tasks.rs#L3277) returns `None` for Windows, Apple, and Linux.
No documented symbol configuration changes that selector in this version.
Its disabled Linux branch names DWP files, not the current `.debug` files and `.gnu_debuglink` sections.
The [SBOM artifact path](https://github.com/axodotdev/cargo-dist/blob/a1c829ffacb7ce98fb617b7acd7ffdd2282b45c2/cargo-dist/src/tasks.rs#L1640) creates global `PACKAGE.cdx.xml` entries.
The local planner does not supply the required JSON/XML pair inside each archive.
Custom generation and staging remain necessary.

| Required contract | Status | Evidence or limit |
| --- | --- | --- |
| Exact product and target selection | PASSED for planning | Five registry-derived archive payload tuples. No unsupported variants appear. |
| Explicit internal-package and cdylib selection | PASSED for planning | Corrected fixture uses `publish = false`, `dist = true`, and `package-libraries`. |
| BIN and CDYLIB native output | UNVERIFIED | No native product build ran after the stop condition. |
| Split Linux symbols and debug links | FAILED for built-in route | No symbol artifact. Pinned source disables symbol selection. |
| Windows PDB packaging | FAILED for built-in route | The same selector disables PDB artifacts. Native contents remain unverified. |
| Required JSON and XML SBOMs per package | FAILED for built-in route | Four global XML entries, no JSON entries, and neither format inside planned archives. |
| Dynamic Linux OpenSSL behavior | UNVERIFIED | No native payload or dependency inspection ran. Existing behavior remains unchanged. |
| Windows OpenSSL DLL contents | UNVERIFIED | No native Windows package exists from this evaluation. |
| Hydrated versions and singular selection arguments | PASSED for planning | Four singular plans accept the hydrated versions. Only the `tacon` and Bash plugin arguments match existing tag names. |
| Offline source/version/provenance verification | UNVERIFIED for replacement | No compatible archive or schema-version-2 provenance replacement was produced. Existing regression tests pass. |
| ARMhf execution | UNVERIFIED for replacement | No ARMhf execution ran. The existing independent gate remains required. |
| SemVer, CalVer, and append-only hydrated history | UNVERIFIED for replacement | Planning does not exercise release history. Existing policy remains unchanged. |
| Complete production script deletion | FAILED | The demonstrated deletion set is empty. |

The hydrator injects `2026.1020.18` for three executables and `1.2.3` for the Bash library.
Singular plans use `PACKAGE-2026.1020.18` and `tacacsrs-bash-plugin-v1.2.3`.
These `--tag` arguments simulate selection only. They create no Git refs.

The current pipeline creates one executable tag, `tacon-YYYY.MMDD.BUILD`, and `<crate>-vX.Y.Z` library tags.
`tacacsrs-agentd` and `tacacsrs-agent-health` receive the `tacon` CalVer value without their own tags.
Thus, their two singular arguments are synthetic.
The existing `tacon-2026.1020.18` spelling selects only `tacon`.
No tested route selects all three executables from an existing tag.

Rust 1.88 accepts the hydrated fixture through locked Cargo metadata.
Neither metadata nor simulated tag arguments prove a native build or real release.

The host is Linux x86_64.
The Rust 1.88.0 override for these worktrees has only the `x86_64-unknown-linux-gnu` target.
The default stable toolchain also has `x86_64-pc-windows-gnu`, which is not a product target.
No installed toolchain has the `x86_64-pc-windows-msvc` target or an ARMhf target.

The probes find no `cl.exe`, ARMhf compiler, QEMU ARM executable, or Wine.
Docker and Windows command shells are visible.
Their presence does not establish native package or ARMhf evidence.
The evaluation does not attempt another platform after the required built-in artifact failure.

## Concrete Deletion Assessment

| Existing owner | Assessment |
| --- | --- |
| Registry and Cargo metadata | Retain as the canonical product and target authority. |
| Version computation and TOML hydration | Retain. Do not replace SemVer, CalVer, or hydrated release history. |
| `build-binary` | No proven deletion without native product build evidence. |
| `stage-binary-package` | Required pre-archive payload and evidence work remains. |
| `package-debug-symbols` | Retain or recreate the split-symbol contract. |
| `collect-openssl-runtime` | Retain. Windows DLL equivalence is unverified. |
| `generate-sbom`, `package-sboms`, `stage-sbom-files` | Retain or recreate both formats, target policy, and sanitization. |
| `create-linux-archive`, `create-windows-archive` | Compression overlaps, but complete archive equivalence is unverified. |
| Build provenance, release manifest, and final checksums | Retain their source/version/payload verification, schema records, and digest ordering. |
| ARMhf gate | Retain the existing execution requirement. |

The documented `extra-artifacts` and generic `package.build-command` routes can invoke custom local commands.
Those commands can wrap the current pipeline, but do not remove its responsibilities.
The pinned reference marks `package.build-command` as an experimental, package-only setting.
A generated generic manifest also needs a maintained adapter to the registry and Cargo metadata.
No such adapter was built after the required symbol failure.
This rejection concerns this version and these release contracts, not all possible cargo-dist uses.

## Replay and Checks

The prototype source remains in `$HOME/tacacs-rs-18-packaging-evaluation-prototype`.
Its branch is `refactor/general-prototypes/18-packaging-evaluation`.
The frozen remote commit is [`fc2226a7253b18ffa9c7aba7322d5762b60ef88a`](https://github.com/AuthScaffold/tacacs-rs/commit/fc2226a7253b18ffa9c7aba7322d5762b60ef88a).
The remote branch `origin/refactor/general-prototypes/18-packaging-evaluation` preserves this commit separately from integration.
The prototype is not merged into integration and never becomes an integration predecessor.

The only new source paths are `evaluation/packaging/evaluate_dist.py` and `evaluation/packaging/README.md`.
The script SHA-256 is `980e8b79fac8658f7c2934287e0da4107d0b5b3c67229dbd789b65a3f4bfbd58`.
The two-file canonical source manifest SHA-256 is `cdace5a3c90d255344ee65430acb067342d25773f41635bbc8a784f1b94167e0`.
The complete full-index patch SHA-256 is `5819a873c52b65db022f8dfb05b6220b3251cd2d07588034712ddb8819971f31`.

### Recover the Prototype

The commands assume Linux GNU and an existing repository at `$HOME/tacacs-rs`.
Recovery requires repository-owner authorization because it changes local Git metadata.
Recovery is not part of the read-only evaluation or its safety claim.
No recovery command ran during either direct review.

If the prototype directory is absent, restore the exact preserved commit:

```bash
set -euo pipefail
prototype="$HOME/tacacs-rs-18-packaging-evaluation-prototype"
prototype_commit=fc2226a7253b18ffa9c7aba7322d5762b60ef88a
if [ ! -e "$prototype" ]; then
  git -C "$HOME/tacacs-rs" fetch origin \
    refs/heads/refactor/general-prototypes/18-packaging-evaluation
  git -C "$HOME/tacacs-rs" worktree add --detach \
    "$prototype" "$prototype_commit"
fi
test "$(git -C "$prototype" rev-parse HEAD)" = "$prototype_commit"
GIT_OPTIONAL_LOCKS=0 git -C "$prototype" diff --exit-code "$prototype_commit" --
```

### Replay the Plans

Run the remaining blocks in order in one noninteractive Bash process, for example one script file.
`set -euo pipefail` stops that process at the first failed command.
Use a fresh output path for each replay.

The evaluated Python environment supplies TOML Kit 0.15.2, pytest 8.4.2, and PyYAML 6.0.3.
Planning requires Cargo and the existing workspace dependencies, not a native product build.
The optional profile script configures this host. It is not preserved prototype source.
The following block uses the retained binary or downloads the pinned official archive into the new cache directory.

```bash
set -euo pipefail
if [ -f /etc/profile.d/tacacs-rs.sh ]; then
  source /etc/profile.d/tacacs-rs.sh
fi
prototype="$HOME/tacacs-rs-18-packaging-evaluation-prototype"
test "$(git -C "$prototype" rev-parse HEAD)" = \
  fc2226a7253b18ffa9c7aba7322d5762b60ef88a
export GIT_OPTIONAL_LOCKS=0
test -z "$(git -C "$prototype" status --porcelain)"
export CARGO_TARGET_DIR="$HOME/.cache/tacacs-rs-18-packaging-evaluation"
export CARGO_BUILD_JOBS=4
export PYTHONDONTWRITEBYTECODE=1
replay="$CARGO_TARGET_DIR/iteration18-evidence/review-new"
test ! -e "$replay"
mkdir -p "$replay"
export TMPDIR="$replay/scratch"
mkdir "$TMPDIR"
tool="$HOME/.cache/tacacs-rs-18-packaging-evaluation-prototype/iteration18-evidence/tool/cargo-dist-x86_64-unknown-linux-gnu/dist"
if [ ! -f "$tool" ]; then
  mkdir "$replay/tool"
  (
    cd "$replay/tool"
    curl --fail --silent --show-error --location \
      https://github.com/axodotdev/cargo-dist/releases/download/v0.33.0/cargo-dist-x86_64-unknown-linux-gnu.tar.xz \
      -o cargo-dist-x86_64-unknown-linux-gnu.tar.xz
    printf '%s  %s\n' \
      4b3f0a5f0ebbdb798f6db649d01b32ba1518376b6f7a0502b7d92b75cc2c8293 \
      cargo-dist-x86_64-unknown-linux-gnu.tar.xz | sha256sum --check
    tar -xf cargo-dist-x86_64-unknown-linux-gnu.tar.xz
  )
  tool="$replay/tool/cargo-dist-x86_64-unknown-linux-gnu/dist"
fi
printf '%s  %s\n' \
  1ecb03737291ce5abf0e08b411f34812b974de4e405a33cdc53e8db39d70ee98 \
  "$tool" | sha256sum --check
cd "$prototype"
source_refs=$(git for-each-ref --format='%(refname) %(objectname)')
source_index=$(sha256sum "$(git rev-parse --git-path index)")
python evaluation/packaging/evaluate_dist.py \
  --tool "$tool" --output "$replay/plan"
test "$(git for-each-ref --format='%(refname) %(objectname)')" = "$source_refs"
test "$(sha256sum "$(git rev-parse --git-path index)")" = "$source_index"
test -z "$(git status --porcelain)"
```

The shell verifies the executable hash before any execution.
The script runs `--version`, then verifies the hash again before planning.
The ref comparison includes every worktree that shares the repository.
A concurrent ref update in another worktree also stops the replay.

New replay evidence remains under `$replay`. It does not change the frozen prototype.
The original prototype cache's `iteration18-evidence/final-replay` retains the original fixture, command stdout/stderr, exit files, plans, and results.
Cache evidence is local and is not committed source. Post-merge cleanup can remove it.

The separate source manifest and full-index patch include every new prototype source file.
Generated exports, logs, upstream source, and binaries stay outside both source patches.

| Executed check | Result |
| --- | --- |
| Initial runner | Exit `0`. This runner preceded explicit `publish = false` and artifact-shape assertions. |
| Corrected runner and final replay | Both exit `0`. Each runs one full configured plan and four hydrated singular plans. |
| Original broad registry, hydration, version, and release suites | 327 passed, zero skipped, exit `0`. This selection breached the no-tag restriction in private fixtures. |
| Tag-free integration selection and documented replay | Each passed 276 tests, zero skipped, exit `0`. Both direct reviews recreated the Git guard from this document. |
| Rust 1.88 locked metadata | Initial, final, and both direct-review hydrated exports exit `0`. The final and both direct-review runs confirm four `publish = false` packages. |
| Prototype source syntax | Python AST passes. Both prototype README Bash blocks pass `bash -n`. |
| Complete prototype patch | `git apply --check` passes against an exported fixture without source writes. |
| Source integrity | All 937 tracked baseline files and the index remain unchanged. |

### Replay the Guarded Tests

The frozen two-file prototype does not contain the private Git guard.
Its README test command selects the safe cases but does not install that guard.
Use the complete setup here instead.
It recreates the provided guard without an existing cache helper.

The guard rejects any argument that equals a blocked command or option, for example `tag`.
It permits `init`, `add`, `commit`, and `config` only when the working directory or `-C` path is at or below the fresh pytest root.
It does not inspect positional `init` paths, `--git-dir`, `--work-tree`, or `GIT_DIR`.

This wrapper controls CLI accidents. It is not a universal process sandbox.
It does not intercept Cargo's internal Git library, alternate Git executables, aliases, or arbitrary filesystem writes.
The scope depends on the inspected commands and exact selectors at predecessor `d3629b2ee0f78c862e7a4d8fb7558622c6f6591a`.

The hydration fixtures use only local `file://` Git dependencies and a private Cargo home.
Their fixture commits and the rehearsal source-export fixture commit are permitted. Tags are not permitted.
The final inspection reads loose and packed tag refs. It fails if a fixture uses a reftable store.

Do not expand this selection or run the complete `compute-versions` directory.
Run the following block after the plan replay:

```bash
mkdir "$replay/git-guard"
cat > "$replay/git-guard/git" <<'PY'
#!/usr/bin/python3
import os
import pathlib
import sys
args = sys.argv[1:]
blocked = {"tag", "push", "fetch", "pull", "clone", "checkout", "switch", "reset", "update-ref", "symbolic-ref", "worktree", "branch", "merge", "rebase", "--global", "--system"}
if blocked.intersection(args):
    print("Git safety guard rejected: " + repr(args), file=sys.stderr)
    raise SystemExit(96)
if {"init", "add", "commit", "config"}.intersection(args):
    here = pathlib.Path.cwd()
    for i, arg in enumerate(args[:-1]):
        if arg == "-C":
            here = (here / args[i + 1]).resolve()
    allowed = pathlib.Path(os.environ["ITERATION18_TEST_ROOT"])
    if here != allowed and allowed not in here.parents:
        print("Git safety guard rejected fixture mutation outside the test root", file=sys.stderr)
        raise SystemExit(97)
os.execv("/usr/bin/git", ["git", *args])
PY
chmod +x "$replay/git-guard/git"
(
export ITERATION18_TEST_ROOT="$replay/pytest"
test ! -e "$ITERATION18_TEST_ROOT"
export PATH="$replay/git-guard:$PATH"
test "$(command -v git)" = "$replay/git-guard/git"
python -m pytest -q -p no:cacheprovider \
  --basetemp="$ITERATION18_TEST_ROOT" \
  .github/steps/cargo-metadata .github/steps/inject-versions \
  .github/steps/compute-versions/test_api_analysis.py \
  .github/steps/compute-versions/test_compute_versions.py::TestParseSemver \
  .github/steps/compute-versions/test_compute_versions.py::TestBumpPatch \
  .github/steps/compute-versions/test_compute_versions.py::TestBumpBreaking \
  .github/steps/compute-versions/test_compute_versions.py::TestBumpMinor \
  .github/steps/compute-versions/test_compute_versions.py::TestDiscoverLibraries \
  .github/steps/compute-versions/test_compute_versions.py::TestTopologicalSort \
  .github/steps/release-manifest
python - <<'PY'
import os
from pathlib import Path
root = Path(os.environ["ITERATION18_TEST_ROOT"]).resolve(strict=True)
loose = [
    path for tags in root.rglob("refs/tags")
    for path in tags.rglob("*") if path.is_file() or path.is_symlink()
]
packed = [
    path for path in root.rglob("packed-refs")
    if any(" refs/tags/" in line for line in path.read_text().splitlines())
]
reftable = [path for path in root.rglob("reftable") if path.is_dir()]
assert not loose and not packed and not reftable, (loose, packed, reftable)
print("No loose or packed fixture tag refs and no reftable stores.")
PY
)
test "$(git for-each-ref --format='%(refname) %(objectname)')" = "$source_refs"
test "$(sha256sum "$(git rev-parse --git-path index)")" = "$source_index"
test -z "$(git status --porcelain)"
```

### Safety Disclosure

The original `pytest .github/steps/compute-versions` selection ran tests that create annotated tags.
It created **52 annotated tag refs in 37 private pytest fixture repositories**.
This breached the experiment's no-tag restriction.
No source repository or remote ref changed.
No tag deletion or cache cleanup occurred.

The prototype cache's `iteration18-evidence/fixture-tag-disclosure.json` lists all affected private refs.
The coordinator keeps a copy of this inventory outside disposable caches.

Independent inspection resolved all 52 ref paths, their contents and object IDs, and all 37 Git common directories.
Every path stays inside the owned `iteration18-evidence/pytest-01` cache.
These standalone repositories do not use source-project Git storage.
Each direct review found all 52 refs unchanged. They remain available for coordinator inspection and cleanup.

Do not repeat that broad selection under this experiment's restrictions.
The safe selection uses only the permitted isolated fixture commits described earlier.

The crates.io HTTP API returned `403`. Official GitHub source supplied the package metadata.
An accidental `dist help --help` probe exited `2`.
Exploratory source/summary probes also failed on an absent path and nullable asset lists.
Corrected probes passed. These errors are not capability-failure evidence.

No private Linux rehearsal, native product build, Windows package, or ARMhf execution ran.
No Rust rebuild, coverage, Miri, dependency audit, or freshness result is claimed for this documentation-only integration.
No host service, operator configuration, unrelated worktree, global tool, source Git history, or publication state changed.
