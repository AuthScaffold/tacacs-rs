"""Classify a library crate's public-API change through the api-classifier tool.

This module wraps the ``api-classifier`` binary built from
``.github/tools/api-classifier``. The binary combines three signals:
``cargo-semver-checks`` and ``public-api`` for breaking and additive public-API
changes, and Cargo metadata for feature-label changes. It then prints one JSON
object that states the minimum required bump.

The wrapper returns a structured result, :class:`ApiBump`. It does not infer a
bump from a process exit code. When the analysis cannot complete, it raises
:class:`ApiAnalysisError` so the caller fails closed: an analysis error is not a
compatibility result and must not become a silent major or patch bump.
"""

from __future__ import annotations

import enum
import json
import os
import shutil
import subprocess
from pathlib import Path

# The binary name as installed by ``cargo install --path``.
DEFAULT_BINARY = "api-classifier"

# The toolchain the binary uses to render rustdoc JSON for both engines. It must
# emit a rustdoc JSON format that the pinned analysis libraries understand.
DEFAULT_TOOLCHAIN = "nightly-2025-11-23"


class ApiBump(enum.Enum):
    """The minimum version bump a public-API change requires.

    This is the API-level classification, independent of the SemVer version
    arithmetic. For a crate before ``1.0`` the caller still decides how each
    classification maps onto a version number.
    """

    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"


class ApiAnalysisError(RuntimeError):
    """The public-API analysis could not complete.

    Raised on a missing binary, a non-zero tool exit, or output that cannot be
    parsed into an :class:`ApiBump`. The caller must fail closed rather than
    assume a compatibility result.
    """


def _resolve_binary(binary: str | None) -> str:
    """Return the api-classifier path from the argument, env, or ``PATH``."""
    if binary:
        return binary
    from_env = os.environ.get("API_CLASSIFIER_BIN")
    if from_env:
        return from_env
    found = shutil.which(DEFAULT_BINARY)
    if found:
        return found
    raise ApiAnalysisError(
        f"api-classifier binary not found: set API_CLASSIFIER_BIN or add "
        f"'{DEFAULT_BINARY}' to PATH"
    )


def classify_api_change(
    package: str,
    baseline_rev: str,
    *,
    workspace_root: Path,
    binary: str | None = None,
    toolchain: str = DEFAULT_TOOLCHAIN,
) -> ApiBump:
    """Return the :class:`ApiBump` for ``package`` against ``baseline_rev``.

    ``workspace_root`` is the directory that holds the workspace ``Cargo.toml``.
    ``baseline_rev`` should be the hydrated release tag so the baseline reflects
    the released public API.

    Raises :class:`ApiAnalysisError` when the analysis cannot complete.
    """
    executable = _resolve_binary(binary)
    manifest_path = Path(workspace_root) / "Cargo.toml"
    command = [
        executable,
        "--package", package,
        "--baseline-rev", baseline_rev,
        "--manifest-path", str(manifest_path),
        "--toolchain", toolchain,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=str(workspace_root),
            check=False,
        )
    except OSError as exc:
        raise ApiAnalysisError(
            f"could not run api-classifier for package '{package}': {exc}"
        ) from exc

    if result.returncode != 0:
        raise ApiAnalysisError(
            f"api-classifier exited with code {result.returncode} for package "
            f"'{package}': {result.stderr.strip()}"
        )

    return _parse_classification(result.stdout, package)


# The minor_analysis values the current adapter can emit. It fails closed
# instead of deferring, so a "deferred" result is stale and must be rejected.
_VALID_MINOR_ANALYSIS = ("public-api", "not-run")


def _parse_classification(stdout: str, package: str) -> ApiBump:
    """Parse the api-classifier JSON output into an :class:`ApiBump`.

    The adapter prints exactly one JSON object on standard output and writes
    every other engine's output to standard error. This parser therefore
    requires the whole output to be that single object: a noisy prefix, trailing
    content, or a JSON array is rejected. It also checks that the reported
    package matches the request and that ``minor_analysis`` is a value the
    current adapter emits, so a stale ``deferred`` result cannot pass as a patch.
    """
    text = stdout.strip()
    if not text:
        raise ApiAnalysisError(
            f"api-classifier produced no output for package '{package}'"
        )

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ApiAnalysisError(
            f"api-classifier output is not a single JSON object for package "
            f"'{package}': {text!r}"
        ) from exc

    if not isinstance(payload, dict):
        raise ApiAnalysisError(
            f"api-classifier output is not a JSON object for package "
            f"'{package}': {text!r}"
        )

    reported_package = payload.get("package")
    if reported_package != package:
        raise ApiAnalysisError(
            f"api-classifier reported package {reported_package!r}, but "
            f"'{package}' was requested"
        )

    bump = payload.get("bump")
    try:
        result = ApiBump(bump)
    except ValueError as exc:
        raise ApiAnalysisError(
            f"api-classifier returned an unknown bump {bump!r} for package "
            f"'{package}'"
        ) from exc

    minor_analysis = payload.get("minor_analysis")
    if minor_analysis not in _VALID_MINOR_ANALYSIS:
        raise ApiAnalysisError(
            f"api-classifier reported an unexpected minor_analysis "
            f"{minor_analysis!r} for package '{package}'"
        )

    return result
