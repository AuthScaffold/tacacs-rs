#!/usr/bin/env python3
"""Rehearse the Linux release packaging path offline from a committed source.

This tool is the local, bounded Stage 6 rehearsal. It proves that a committed
source revision still produces runnable, well-formed Linux release artifacts
without publishing anything. It never pushes a tag, never writes the generated
release branch, and never touches the working tree of the source repository.

What it exercises
-----------------

The rehearsal reuses the **same** committed automation that the CI release path
runs, rather than reimplementing it:

* It exports the committed source with ``git archive`` into an owned temporary
  tree, so only tracked files at the revision take part. Uncommitted or
  untracked files in the working tree are never built or packaged.
* It selects the Linux products with the committed product registry validator
  from the export. A missing or invalid registry fails before hydration.
* It hydrates the computed versions into the exported tree with the committed
  ``inject-versions`` tool, after ``cargo metadata`` is available there.
* It builds the four supported Linux products with ``--locked`` and ``--target``.
* It stages, extracts debug symbols, and archives each product by invoking the
  committed ``stage-binary-package``, ``package-debug-symbols``, and
  ``create-linux-archive`` scripts. The rehearsal and CI share one copy of each
  script, so a packaging bug fails in both places.
* It generates CycloneDX SBOMs with the installed ``cargo-cyclonedx`` and checks
  that each SBOM root component version matches the computed version map.
* It validates every artifact: executables report the expected ``--version``,
  the Bash plugin exports the expected dynamic symbols, and every native ELF
  resolves its shared libraries.
* It writes and offline-verifies the release manifest and the checksums file,
  then rehearses a rollback by redeploying one archive into a scratch directory.

Boundaries
----------

* The tool requires a Python standard library only. It invokes external build
  and inspection tools as subprocesses.
* It never installs tools. A missing tool is a clear preflight failure.
* It is Linux-only. It makes no Windows or container claim.
* It never writes a product ``Cargo.lock`` in the source workspace. Hydration
  and the ``--locked`` build happen in the temporary export tree.
* The rollback rehearsal only verifies artifacts and redeploys one archive into
  a temporary directory. It never contacts a live host and never downgrades a
  credential.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable, Sequence

# The default Linux GNU target. The rehearsal is Linux-only.
DEFAULT_TARGET = "x86_64-unknown-linux-gnu"

# The Bash plugin shared object must export these ABI entry points. A stripped
# cdylib keeps its dynamic symbol table, so ``nm -D`` still lists them.
BASH_PLUGIN_EXPORTS: tuple[str, ...] = (
    "plugin_init",
    "plugin_uninit",
    "on_shell_execve",
)

# External tools the rehearsal needs. The tool never installs any of them.
REQUIRED_TOOLS: tuple[str, ...] = (
    "git",
    "cargo",
    "rustc",
    "cargo-cyclonedx",
    "objcopy",
    "strip",
    "tar",
    "ldd",
    "nm",
)

# Committed automation the rehearsal drives from the exported tree.
STAGE_SCRIPT_RELPATH = ".github/steps/stage-binary-package/run.sh"
SYMBOLS_SCRIPT_RELPATH = ".github/steps/package-debug-symbols/run.sh"
ARCHIVE_SCRIPT_RELPATH = ".github/steps/create-linux-archive/run.sh"
HYDRATE_TOOL_RELPATH = ".github/steps/inject-versions/hydrate_versions.py"
MANIFEST_TOOL_RELPATH = ".github/steps/release-manifest/release_manifest.py"
PROVENANCE_TOOL_RELPATH = ".github/steps/release-manifest/build_provenance.py"
SBOM_STAGE_TOOL_RELPATH = ".github/steps/stage-sbom-files/stage_sbom.py"
PRODUCT_TOOL_RELPATH = ".github/steps/cargo-metadata/products.py"

# One mebibyte read window keeps hashing memory bounded for large archives.
_HASH_CHUNK_BYTES = 1024 * 1024


class RehearsalError(RuntimeError):
    """The rehearsal cannot continue from the given inputs or environment."""


# ---------------------------------------------------------------------------
# Pure helpers. These take plain data and never reach the network, so the tests
# cover them without a toolchain.
# ---------------------------------------------------------------------------


def linux_artifact_names(artifact_name: str, artifact_kind: str) -> tuple[str, str]:
    """Return the Linux ``(filename, basename)`` for a product artifact.

    A ``bin`` artifact keeps its name. A ``cdylib`` artifact gains the ``lib``
    prefix and the ``.so`` suffix, which is how Cargo names a Linux shared
    object.
    """
    if artifact_kind == "bin":
        return artifact_name, artifact_name
    if artifact_kind == "cdylib":
        return f"lib{artifact_name}.so", f"lib{artifact_name}"
    raise RehearsalError(f"unsupported artifact kind: {artifact_kind!r}")


def asset_suffix(asset_name: str, package_name: str) -> str:
    """Return the platform suffix of an asset name, matching compute-package-names."""
    if asset_name == package_name:
        raise RehearsalError(
            f"asset name must be platform-specific, got {asset_name!r}"
        )
    prefix = f"{package_name}-"
    if asset_name.startswith(prefix):
        return asset_name[len(prefix):]
    return asset_name


def read_versions_file(path: Path) -> dict[str, str]:
    """Return the computed versions map from a JSON object file.

    An empty object is valid and records that hydration injects no versions.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise RehearsalError(f"cannot read versions file {path}: {error}") from error
    if not isinstance(data, dict):
        raise RehearsalError("versions file must contain a JSON object")
    for name, version in data.items():
        if not isinstance(name, str) or not isinstance(version, str):
            raise RehearsalError("the versions map must have string keys and values")
    return data


def preflight_tools(
    tools: Iterable[str], *, which: Callable[[str], str | None] = shutil.which
) -> list[str]:
    """Return the tools that are not on ``PATH``, in input order."""
    return [tool for tool in tools if which(tool) is None]


def build_product_command(
    product: dict[str, str], target: str, profile_flag: Sequence[str]
) -> list[str]:
    """Return the ``cargo build`` command for one product."""
    kind = product["artifact_kind"]
    command = [
        "cargo",
        "build",
        *profile_flag,
        "--locked",
        "--target",
        target,
        "--package",
        product["package_name"],
    ]
    if kind == "bin":
        command.append("--bins")
    elif kind == "cdylib":
        command.append("--lib")
    else:
        raise RehearsalError(f"unsupported artifact kind: {kind!r}")
    features = product.get("features", "").strip()
    if features:
        command += ["--features", features]
    return command


def sbom_command(
    manifest_path: Path, describe: str, target: str, output_format: str,
    features: str = "",
) -> list[str]:
    """Return the ``cargo cyclonedx`` command, matching the generate-sbom action.

    The release path generates SBOMs with ``--target-in-filename``, so the
    rehearsal passes it next to ``--target``. ``features`` is reserved for future
    configured features; every supported product currently requests none.
    """
    command = ["cargo", "cyclonedx", "--format", output_format]
    if manifest_path:
        command += ["--manifest-path", str(manifest_path)]
    if describe:
        command += ["--describe", describe]
    if target:
        command += ["--target", target]
        command.append("--target-in-filename")
    if features.strip():
        command += ["--features", features]
    return command


def parse_dynamic_exports(nm_output: str) -> set[str]:
    """Return the defined dynamic symbol names from ``nm -D`` output.

    A defined symbol has an address and a type that is not ``U`` (undefined) or
    a lowercase weak-undefined marker. Undefined references are excluded.
    """
    exports: set[str] = set()
    for line in nm_output.splitlines():
        parts = line.split()
        if len(parts) == 3:
            _address, symbol_type, name = parts
            if symbol_type not in ("U", "w", "v"):
                exports.add(name)
        elif len(parts) == 2:
            symbol_type, name = parts
            if symbol_type not in ("U", "w", "v"):
                exports.add(name)
    return exports


def missing_dynamic_exports(nm_output: str, expected: Iterable[str]) -> list[str]:
    """Return the expected exports that are absent from ``nm -D`` output."""
    exports = parse_dynamic_exports(nm_output)
    return [name for name in expected if name not in exports]


def ldd_missing_libraries(ldd_output: str) -> list[str]:
    """Return the ``ldd`` lines that report an unresolved shared library."""
    return [line.strip() for line in ldd_output.splitlines() if "not found" in line]


def version_output_matches(output: str, expected_version: str) -> bool:
    """Return whether a ``--version`` output contains the expected version token."""
    return expected_version in output.split()


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 digest of a file, read in bounded chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_recorded_digests(manifest_path: Path, artifacts_dir: Path) -> list[str]:
    """Recompute the manifest digests offline and return mismatch errors.

    This repeats the manifest's own check through an independent code path, so
    the rehearsal does not import the manifest module. It detects a corrupt or
    missing artifact, which is what a rollback relies on.
    """
    try:
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise RehearsalError(
            f"cannot read manifest {manifest_path}: {error}"
        ) from error
    errors: list[str] = []
    root = Path(artifacts_dir)
    for name, expected in sorted(manifest.get("artifacts", {}).items()):
        path = root / name
        if not path.is_file():
            errors.append(f"recorded artifact '{name}' is missing")
            continue
        actual = sha256_file(path)
        if actual != expected:
            errors.append(
                f"artifact '{name}' digest mismatch: "
                f"expected {expected}, found {actual}"
            )
    return errors


def write_checksums(release_dir: Path, *, filename: str = "checksums-sha256.txt") -> Path:
    """Write a sorted SHA-256 checksums file for every other file in a directory.

    The format matches ``sha256sum``: ``<hex-digest>  <basename>``. The checksums
    file never covers itself.
    """
    release_dir = Path(release_dir)
    checksums_path = release_dir / filename
    lines = [
        f"{sha256_file(entry)}  {entry.name}"
        for entry in sorted(release_dir.iterdir())
        if entry.is_file() and entry.name != filename
    ]
    lines.sort()
    checksums_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return checksums_path


# ---------------------------------------------------------------------------
# Subprocess helpers.
# ---------------------------------------------------------------------------


def _format_command(command: Sequence[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in command)


def _run(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture: bool = False,
    stdin_bytes: bytes | None = None,
) -> subprocess.CompletedProcess:
    """Run a command and raise ``RehearsalError`` on a non-zero exit."""
    print(f"+ {_format_command(command)}", flush=True)
    result = subprocess.run(
        list(command),
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        text=stdin_bytes is None,
        capture_output=capture,
        input=stdin_bytes,
    )
    if result.returncode != 0:
        if capture:
            sys.stderr.write(result.stdout or "")
            sys.stderr.write(result.stderr or "")
        raise RehearsalError(
            f"command failed with exit {result.returncode}: {_format_command(command)}"
        )
    return result


def _capture_lenient(
    command: Sequence[str], *, cwd: Path | None = None, env: dict[str, str] | None = None
) -> tuple[int, str]:
    """Run a command, returning its exit code and combined output without raising."""
    print(f"+ {_format_command(command)}", flush=True)
    result = subprocess.run(
        list(command),
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        text=True,
        capture_output=True,
    )
    return result.returncode, (result.stdout or "") + (result.stderr or "")


# ---------------------------------------------------------------------------
# Orchestration. These invoke real tools and are driven end to end by main.
# ---------------------------------------------------------------------------


def resolve_commit(source: Path, revision: str) -> str:
    """Resolve a revision to a full commit SHA in the source repository."""
    result = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "--verify", f"{revision}^{{commit}}"],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RehearsalError(
            f"cannot resolve revision {revision!r} in {source}: "
            f"{result.stderr.strip()}"
        )
    return result.stdout.strip()


def export_source(source: Path, revision: str, destination: Path) -> None:
    """Export the committed tree at a revision into an owned directory.

    ``git archive`` emits only tracked files at the revision, so uncommitted or
    untracked files in the working tree never enter the rehearsal.
    """
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(
        ["git", "-C", str(source), "archive", "--format=tar", revision],
        capture_output=True,
    )
    if archive.returncode != 0:
        raise RehearsalError(
            f"git archive failed for {revision!r}: "
            f"{archive.stderr.decode('utf-8', 'replace').strip()}"
        )
    _run(["tar", "-x", "-C", str(destination)], stdin_bytes=archive.stdout)


def hydrate_versions(
    export_dir: Path,
    versions: dict[str, str],
    *,
    python: str = sys.executable,
    env: dict[str, str] | None = None,
) -> None:
    """Hydrate the computed versions into the exported tree.

    This runs the committed ``inject-versions`` tool from the export, which reads
    ``cargo metadata`` and rewrites the exported ``Cargo.toml`` files and
    ``Cargo.lock``. The source workspace is never touched.
    """
    tool = Path(export_dir) / HYDRATE_TOOL_RELPATH
    if not tool.is_file():
        raise RehearsalError(f"inject-versions tool is missing in the export: {tool}")
    _run(
        [
            python,
            str(tool),
            "--workspace",
            str(export_dir),
            "--versions",
            json.dumps(versions),
        ],
        cwd=export_dir,
        env=env,
    )


def generate_and_stage_sbom(
    product: dict[str, str],
    *,
    export_dir: Path,
    staging_dir: Path,
    suffix: str,
    target: str,
    versions: dict[str, str],
    env: dict[str, str],
    python: str = sys.executable,
) -> list[Path]:
    """Generate both required SBOM formats, then stage them with the shared helper.

    JSON and XML are both required, matching CI. The committed
    ``stage-sbom-files`` helper is the single authority: it selects the product
    SBOM by Cargo metadata, enforces the version, sanitizes paths, and writes the
    staged copies. The rehearsal only generates the two formats, so one staging
    bug fails in both CI and the rehearsal.
    """
    manifest_path = Path(export_dir) / product["package_root"] / "Cargo.toml"
    package_name = product["package_name"]
    expected_version = versions.get(package_name)
    package_dir = manifest_path.parent

    for output_format in ("json", "xml"):
        for previous in package_dir.glob(f"*.cdx.{output_format}"):
            previous.unlink()
        command = sbom_command(
            manifest_path, product["sbom_describe"], target, output_format,
            product.get("features", ""),
        )
        _run(command, cwd=export_dir, env=env)

    command = [
        python, str(Path(export_dir) / SBOM_STAGE_TOOL_RELPATH),
        "--package-root", str(package_dir),
        "--package-dir", str(staging_dir),
        "--basename", f"sbom-{suffix}",
        "--package-name", package_name,
        "--workspace", str(export_dir),
        "--repository", f"https://github.com/{env.get('GITHUB_REPOSITORY', 'AuthScaffold/tacacs-rs')}",
    ]
    if env.get("GITHUB_WORKSPACE"):
        command += ["--workspace", env["GITHUB_WORKSPACE"]]
    if expected_version is not None:
        command += ["--expected-version", expected_version]
    _run(command, cwd=export_dir, env=env)
    return [staging_dir / f"sbom-{suffix}.{fmt}" for fmt in ("json", "xml")]


def validate_artifact(
    product: dict[str, str],
    *,
    staging_dir: Path,
    artifact_filename: str,
    versions: dict[str, str],
) -> None:
    """Validate one staged artifact: shared libraries, version, and exports."""
    staged = Path(staging_dir) / artifact_filename
    if not staged.is_file():
        raise RehearsalError(f"staged artifact is missing: {staged}")

    # Record the native dependency report and fail on an unresolved library.
    code, ldd_output = _capture_lenient(["ldd", str(staged)])
    print(ldd_output.rstrip())
    if code != 0:
        raise RehearsalError(f"native dependency inspection failed for {artifact_filename}")
    missing = ldd_missing_libraries(ldd_output)
    if missing:
        raise RehearsalError(
            f"{artifact_filename} has unresolved shared libraries: {missing}"
        )

    if product["artifact_kind"] == "bin":
        result = _run([str(staged), "--version"], capture=True)
        expected = versions.get(product["package_name"])
        reported = (result.stdout or "").strip()
        print(f"  --version: {reported}")
        if expected is not None and not version_output_matches(result.stdout or "", expected):
            raise RehearsalError(
                f"{artifact_filename} --version {reported!r} does not report the "
                f"computed version {expected!r}"
            )
    elif product["artifact_kind"] == "cdylib":
        result = _run(["nm", "-D", str(staged)], capture=True)
        missing_exports = missing_dynamic_exports(result.stdout or "", BASH_PLUGIN_EXPORTS)
        if missing_exports:
            raise RehearsalError(
                f"{artifact_filename} is missing expected exports: {missing_exports}"
            )
        print(f"  exports: {', '.join(BASH_PLUGIN_EXPORTS)} present")


def _script_env(
    base_env: dict[str, str],
    *,
    target: str,
    profile: str,
    artifact_filename: str,
    artifact_basename: str,
    package_dir: Path,
    asset_name: str,
    build_dir: Path,
) -> dict[str, str]:
    env = base_env.copy()
    env.update(
        {
            "TARGET": target,
            "PROFILE": profile,
            "ARTIFACT_FILENAME": artifact_filename,
            "ARTIFACT_BASENAME": artifact_basename,
            "PACKAGE_DIR": str(package_dir),
            "ASSET_NAME": asset_name,
            "CARGO_TARGET_DIR": str(build_dir),
        }
    )
    # An unset RUNNER_OS selects the non-Windows script path.
    env.pop("RUNNER_OS", None)
    return env


def process_product(
    product: dict[str, str],
    *,
    export_dir: Path,
    output_dir: Path,
    build_dir: Path,
    release_dir: Path,
    target: str,
    profile: str,
    versions: dict[str, str],
    base_env: dict[str, str],
    commit: str,
    python: str = sys.executable,
) -> Path:
    """Build, stage, symbolize, SBOM, validate, and archive one product."""
    asset_name = product["asset_name"]
    package_name = product["package_name"]
    print(f"\n=== {asset_name} ({package_name}) ===", flush=True)

    artifact_filename, artifact_basename = linux_artifact_names(
        product["artifact_name"], product["artifact_kind"]
    )
    suffix = asset_suffix(asset_name, package_name)
    staging_dir = output_dir / "staging" / asset_name
    profile_flag = ["--release"] if profile == "release" else []

    env = _script_env(
        base_env,
        target=target,
        profile=profile,
        artifact_filename=artifact_filename,
        artifact_basename=artifact_basename,
        package_dir=staging_dir,
        asset_name=asset_name,
        build_dir=build_dir,
    )

    # 1. Build into the out-of-tree target directory.
    _run(build_product_command(product, target, profile_flag), cwd=export_dir, env=env)

    # 2. Stage without stripping, then 3. extract debug symbols and strip.
    _run(["bash", str(Path(export_dir) / STAGE_SCRIPT_RELPATH)], cwd=output_dir, env=env)
    _run(["bash", str(Path(export_dir) / SYMBOLS_SCRIPT_RELPATH)], cwd=output_dir, env=env)

    # 4. Generate and verify SBOMs into the staging directory.
    generate_and_stage_sbom(
        product,
        export_dir=export_dir,
        staging_dir=staging_dir,
        suffix=suffix,
        target=target,
        versions=versions,
        env=base_env,
        python=python,
    )

    # 5. Validate the staged artifact.
    validate_artifact(
        product,
        staging_dir=staging_dir,
        artifact_filename=artifact_filename,
        versions=versions,
    )

    _run(
        [
            python, str(Path(export_dir) / PROVENANCE_TOOL_RELPATH),
            "--workspace", str(export_dir),
            "--package-root", str(Path(export_dir) / product["package_root"]),
            "--package-dir", str(staging_dir),
            "--upload-dir", str(output_dir / "packaged"),
            "--asset-name", asset_name,
            "--package-name", package_name,
            "--artifact-filename", artifact_filename,
            "--artifact-kind", product["artifact_kind"],
            "--source", commit,
            "--target", target,
            "--profile", profile,
            "--features", product.get("features", ""),
            "--versions-json", json.dumps(versions),
        ],
        cwd=export_dir,
        env=base_env,
    )

    _run(["bash", str(Path(export_dir) / ARCHIVE_SCRIPT_RELPATH)], cwd=output_dir, env=env)
    archive = output_dir / "packaged" / f"{asset_name}.tar.gz"
    if not archive.is_file():
        raise RehearsalError(f"expected archive was not produced: {archive}")
    collected = release_dir / archive.name
    shutil.copy2(archive, collected)
    record = output_dir / "packaged" / f"build-provenance-{asset_name}.json"
    shutil.copy2(record, release_dir / record.name)
    return collected


def generate_manifest(
    export_dir: Path,
    release_dir: Path,
    versions_path: Path,
    commit: str,
    *,
    python: str = sys.executable,
) -> Path:
    """Generate the release manifest through the committed manifest CLI.

    The rehearsal invokes the manifest tool as a subprocess instead of importing
    it, so the two stay decoupled.
    """
    tool = Path(export_dir) / MANIFEST_TOOL_RELPATH
    if not tool.is_file():
        raise RehearsalError(f"release-manifest tool is missing in the export: {tool}")
    output = Path(release_dir) / "release-manifest.json"
    _run(
        [
            python,
            str(tool),
            "--artifacts",
            str(release_dir),
            "--versions",
            str(versions_path),
            "--source",
            commit,
            "--workspace",
            str(export_dir),
            "--provenance-dir",
            str(release_dir),
            "--output",
            str(output),
        ]
    )
    return output


def rehearse_rollback(
    release_dir: Path,
    product: dict[str, str],
    install_dir: Path,
    versions: dict[str, str],
) -> Path:
    """Redeploy one archive into a scratch directory and run it offline.

    This simulates restoring a known-good commit's artifact. It never contacts a
    host and never changes a credential.
    """
    asset_name = product["asset_name"]
    archive = Path(release_dir) / f"{asset_name}.tar.gz"
    if not archive.is_file():
        raise RehearsalError(f"rollback archive is missing: {archive}")
    install_dir = Path(install_dir)
    install_dir.mkdir(parents=True, exist_ok=True)
    _run(["tar", "-xzf", str(archive), "-C", str(install_dir)])

    artifact_filename, _basename = linux_artifact_names(
        product["artifact_name"], product["artifact_kind"]
    )
    binary = install_dir / asset_name / artifact_filename
    if not binary.is_file():
        raise RehearsalError(f"rollback archive did not contain {binary}")
    result = _run([str(binary), "--version"], capture=True)
    expected = versions.get(product["package_name"])
    if expected is not None and not version_output_matches(result.stdout or "", expected):
        raise RehearsalError(
            f"rollback redeploy of {asset_name} reports "
            f"{(result.stdout or '').strip()!r}, expected the computed version "
            f"{expected!r}"
        )
    return binary


def require_empty_output(output: Path) -> None:
    """Reject an existing output unless it is an empty, real directory."""
    if output.is_symlink() or (
        output.exists() and (not output.is_dir() or any(output.iterdir()))
    ):
        raise RehearsalError(f"output must be a new or empty directory: {output}")


def build_directory(source: Path, output: Path, cache: str | None) -> Path:
    """Select a Cargo cache without permitting writes into the source checkout."""
    candidate = (Path(cache) if cache else output / "build").resolve()
    protected_roots = [
        source,
        *(output / name for name in ("source", "staging", "packaged", "release", "rollback")),
    ]
    if candidate == output.resolve() or any(
        candidate.is_relative_to(root.resolve()) for root in protected_roots
    ):
        raise RehearsalError("build cache must be separate from source and release directories")
    return candidate


def rehearsal_products(
    export_dir: Path, target: str, *, python: str, env: dict[str, str]
) -> list[dict[str, str]]:
    """Read the Linux matrix through the exported revision's registry tool."""
    tool = Path(export_dir) / PRODUCT_TOOL_RELPATH
    if not tool.is_file():
        raise RehearsalError(f"product registry tool is missing in the export: {tool}")
    result = _run(
        [python, str(tool),
         "--workspace", str(export_dir), "--target", target, "--linux"],
        cwd=export_dir, env=env, capture=True,
    )
    try:
        products = json.loads(result.stdout)
    except (ValueError, TypeError) as error:
        raise RehearsalError("the product registry tool returned invalid JSON") from error
    if not isinstance(products, list) or not products or any(
        not isinstance(product, dict)
        or product.get("target") != target
        or product.get("os") != "ubuntu-latest"
        or any(not isinstance(product.get(field), str) for field in (
            "asset_name", "package_name", "package_root", "artifact_name",
            "artifact_kind", "features", "sbom_describe",
        ))
        for product in products
    ):
        raise RehearsalError("the product registry tool returned no valid Linux matrix")
    return products


def rehearse(
    *,
    source: str,
    revision: str,
    versions_path: str,
    output: str,
    target: str = DEFAULT_TARGET,
    profile: str = "release",
    build_cache: str | None = None,
    python: str = sys.executable,
) -> dict[str, object]:
    """Run the full Linux release rehearsal and return a summary."""
    source_path = Path(source).resolve()
    require_empty_output(Path(output))
    output_path = Path(output).resolve()
    if output_path.is_relative_to(source_path):
        raise RehearsalError("rehearsal output must be outside the source checkout")
    versions_file = Path(versions_path).resolve()

    missing = preflight_tools(REQUIRED_TOOLS)
    if missing:
        raise RehearsalError(
            "missing required tools: "
            + ", ".join(missing)
            + ". Install them and re-run. This rehearsal never installs tools."
        )

    if not (source_path / ".git").exists():
        raise RehearsalError(f"source is not a git repository: {source_path}")

    versions = read_versions_file(versions_file)
    commit = resolve_commit(source_path, revision)

    export_dir = output_path / "source"
    build_dir = build_directory(source_path, output_path, build_cache)
    release_dir = output_path / "release"
    install_dir = output_path / "rollback"
    for directory in (output_path, export_dir, build_dir, release_dir):
        directory.mkdir(parents=True, exist_ok=True)

    base_env = os.environ.copy()
    base_env["CARGO_TARGET_DIR"] = str(build_dir)
    base_env.pop("RUNNER_OS", None)

    print(f"Rehearsing commit {commit} for target {target} ({profile}).")
    export_source(source_path, commit, export_dir)
    products = rehearsal_products(export_dir, target, python=python, env=base_env)
    hydrate_versions(export_dir, versions, python=python, env=base_env)

    archives: list[str] = []
    for product in products:
        collected = process_product(
            product,
            export_dir=export_dir,
            output_dir=output_path,
            build_dir=build_dir,
            release_dir=release_dir,
            target=target,
            profile=profile,
            versions=versions,
            base_env=base_env,
            commit=commit,
            python=python,
        )
        archives.append(collected.name)

    manifest_path = generate_manifest(
        export_dir, release_dir, versions_file, commit, python=python
    )
    checksums_path = write_checksums(release_dir)

    errors = verify_recorded_digests(manifest_path, release_dir)
    if errors:
        raise RehearsalError("manifest verification failed: " + "; ".join(errors))

    rehearse_rollback(release_dir, products[0], install_dir, versions)

    return {
        "commit": commit,
        "target": target,
        "profile": profile,
        "versions": versions,
        "archives": archives,
        "manifest": str(manifest_path),
        "checksums": str(checksums_path),
        "release_dir": str(release_dir),
    }


def _print_summary(summary: dict[str, object]) -> None:
    print("\n=== Rehearsal summary ===")
    print(f"  source commit: {summary['commit']}")
    print(f"  target:        {summary['target']}")
    print(f"  profile:       {summary['profile']}")
    versions = summary["versions"]
    assert isinstance(versions, dict)
    if versions:
        print("  computed versions:")
        for name, version in sorted(versions.items()):
            print(f"    {name} -> {version}")
    else:
        print("  computed versions: none (manifests stay at their in-tree value)")
    print("  archives:")
    archives = summary["archives"]
    assert isinstance(archives, list)
    for name in archives:
        print(f"    {name}")
    print(f"  manifest:  {summary['manifest']}")
    print(f"  checksums: {summary['checksums']}")
    print("  release artifacts verified offline against the manifest.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Rehearse the Linux release packaging path offline."
    )
    parser.add_argument(
        "--source",
        required=True,
        help="Path to the source git repository to export from.",
    )
    parser.add_argument(
        "--revision",
        required=True,
        help="Committed revision (SHA, tag, or ref) to rehearse.",
    )
    parser.add_argument(
        "--versions",
        required=True,
        help="Path to the computed versions JSON object file.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="New or empty output directory for the exported tree and artifacts.",
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Rust target triple (default: {DEFAULT_TARGET}).",
    )
    parser.add_argument(
        "--build-cache",
        help="Optional trusted Cargo target directory outside the source checkout; release output must still be empty.",
    )
    parser.add_argument(
        "--profile",
        default="release",
        choices=["release", "debug"],
        help="Cargo profile to build (default: release).",
    )
    args = parser.parse_args(argv)

    try:
        summary = rehearse(
            source=args.source,
            revision=args.revision,
            versions_path=args.versions,
            output=args.output,
            target=args.target,
            profile=args.profile,
            build_cache=args.build_cache,
        )
    except RehearsalError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    _print_summary(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
