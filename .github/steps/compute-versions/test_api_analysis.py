"""Tests for api_analysis.py.

These tests mock the api-classifier subprocess, so they are hermetic and do not
build any Rust crate. The real end-to-end classification is exercised by the
api-classifier crate's own integration tests.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from api_analysis import (
    ApiAnalysisError,
    ApiBump,
    classify_api_change,
)


def _completed(returncode: int, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    """Return a stand-in for subprocess.CompletedProcess."""
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _json_line(
    bump: str,
    package: str = "my-lib",
    minor_analysis: str = "public-api",
) -> str:
    """Render one api-classifier JSON result line."""
    return json.dumps(
        {
            "package": package,
            "bump": bump,
            "breaking_analysis": "cargo-semver-checks",
            "minor_analysis": minor_analysis,
        }
    )


# ---------------------------------------------------------------------------
# Successful classification
# ---------------------------------------------------------------------------

class TestClassifyApiChangeSuccess:
    @pytest.mark.parametrize(
        "bump_str, expected",
        [
            ("patch", ApiBump.PATCH),
            ("minor", ApiBump.MINOR),
            ("major", ApiBump.MAJOR),
        ],
    )
    def test_maps_bump_to_enum(self, bump_str: str, expected: ApiBump, tmp_path: Path) -> None:
        with patch("api_analysis.subprocess.run", return_value=_completed(0, _json_line(bump_str))):
            result = classify_api_change(
                "my-lib", "my-lib-v0.1.0",
                workspace_root=tmp_path, binary="api-classifier",
            )
        assert result is expected

    def test_builds_expected_command(self, tmp_path: Path) -> None:
        line = _json_line("patch", package="tacacsrs-protocol")
        with patch("api_analysis.subprocess.run", return_value=_completed(0, line)) as run:
            classify_api_change(
                "tacacsrs-protocol", "tacacsrs-protocol-v0.3.0",
                workspace_root=tmp_path, binary="/opt/api-classifier",
                toolchain="nightly-2025-08-02",
            )
        command = run.call_args.args[0]
        assert command[0] == "/opt/api-classifier"
        assert "--package" in command and "tacacsrs-protocol" in command
        assert "--baseline-rev" in command and "tacacsrs-protocol-v0.3.0" in command
        assert "--manifest-path" in command
        assert str(tmp_path / "Cargo.toml") in command
        assert "--toolchain" in command and "nightly-2025-08-02" in command


# ---------------------------------------------------------------------------
# Fail-closed behavior
# ---------------------------------------------------------------------------

class TestClassifyApiChangeFailsClosed:
    def test_nonzero_exit_raises(self, tmp_path: Path) -> None:
        with patch(
            "api_analysis.subprocess.run",
            return_value=_completed(1, "", "check_release returned an error"),
        ):
            with pytest.raises(ApiAnalysisError, match="exited with code 1"):
                classify_api_change(
                    "my-lib", "my-lib-v0.1.0",
                    workspace_root=tmp_path, binary="api-classifier",
                )

    def test_empty_stdout_raises(self, tmp_path: Path) -> None:
        with patch("api_analysis.subprocess.run", return_value=_completed(0, "   \n")):
            with pytest.raises(ApiAnalysisError, match="no output"):
                classify_api_change(
                    "my-lib", "my-lib-v0.1.0",
                    workspace_root=tmp_path, binary="api-classifier",
                )

    def test_invalid_json_raises(self, tmp_path: Path) -> None:
        with patch("api_analysis.subprocess.run", return_value=_completed(0, "not json")):
            with pytest.raises(ApiAnalysisError, match="not a single JSON object"):
                classify_api_change(
                    "my-lib", "my-lib-v0.1.0",
                    workspace_root=tmp_path, binary="api-classifier",
                )

    def test_noisy_prefix_raises(self, tmp_path: Path) -> None:
        """Only the single JSON object may be on stdout; a noisy prefix is rejected."""
        noisy = "Compiling foo v0.1.0\nFinished\n" + _json_line("minor")
        with patch("api_analysis.subprocess.run", return_value=_completed(0, noisy)):
            with pytest.raises(ApiAnalysisError, match="not a single JSON object"):
                classify_api_change(
                    "my-lib", "my-lib-v0.1.0",
                    workspace_root=tmp_path, binary="api-classifier",
                )

    def test_json_array_raises(self, tmp_path: Path) -> None:
        """A JSON array is not the expected single object."""
        payload = "[" + _json_line("patch") + "]"
        with patch("api_analysis.subprocess.run", return_value=_completed(0, payload)):
            with pytest.raises(ApiAnalysisError, match="not a JSON object"):
                classify_api_change(
                    "my-lib", "my-lib-v0.1.0",
                    workspace_root=tmp_path, binary="api-classifier",
                )

    def test_wrong_package_raises(self, tmp_path: Path) -> None:
        """A result for a different package is rejected."""
        line = _json_line("patch", package="other-lib")
        with patch("api_analysis.subprocess.run", return_value=_completed(0, line)):
            with pytest.raises(ApiAnalysisError, match="reported package"):
                classify_api_change(
                    "my-lib", "my-lib-v0.1.0",
                    workspace_root=tmp_path, binary="api-classifier",
                )

    def test_deferred_minor_analysis_raises(self, tmp_path: Path) -> None:
        """A stale 'deferred' minor_analysis is rejected; the tool fails closed."""
        line = _json_line("patch", minor_analysis="deferred")
        with patch("api_analysis.subprocess.run", return_value=_completed(0, line)):
            with pytest.raises(ApiAnalysisError, match="minor_analysis"):
                classify_api_change(
                    "my-lib", "my-lib-v0.1.0",
                    workspace_root=tmp_path, binary="api-classifier",
                )

    def test_unknown_bump_raises(self, tmp_path: Path) -> None:
        payload = '{"package":"my-lib","bump":"rewrite"}'
        with patch("api_analysis.subprocess.run", return_value=_completed(0, payload)):
            with pytest.raises(ApiAnalysisError, match="unknown bump"):
                classify_api_change(
                    "my-lib", "my-lib-v0.1.0",
                    workspace_root=tmp_path, binary="api-classifier",
                )

    def test_os_error_raises(self, tmp_path: Path) -> None:
        with patch("api_analysis.subprocess.run", side_effect=OSError("no such file")):
            with pytest.raises(ApiAnalysisError, match="could not run"):
                classify_api_change(
                    "my-lib", "my-lib-v0.1.0",
                    workspace_root=tmp_path, binary="api-classifier",
                )


# ---------------------------------------------------------------------------
# Binary resolution
# ---------------------------------------------------------------------------

class TestResolveBinary:
    def test_explicit_binary_wins(self, tmp_path: Path) -> None:
        with patch("api_analysis.subprocess.run", return_value=_completed(0, _json_line("patch"))) as run:
            classify_api_change(
                "my-lib", "my-lib-v0.1.0",
                workspace_root=tmp_path, binary="/explicit/api-classifier",
            )
        assert run.call_args.args[0][0] == "/explicit/api-classifier"

    def test_env_var_used_when_no_explicit(self, tmp_path: Path) -> None:
        with patch.dict(os.environ, {"API_CLASSIFIER_BIN": "/env/api-classifier"}):
            with patch("api_analysis.subprocess.run", return_value=_completed(0, _json_line("patch"))) as run:
                classify_api_change("my-lib", "my-lib-v0.1.0", workspace_root=tmp_path)
        assert run.call_args.args[0][0] == "/env/api-classifier"

    def test_missing_binary_raises(self, tmp_path: Path) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with patch("api_analysis.shutil.which", return_value=None):
                with pytest.raises(ApiAnalysisError, match="not found"):
                    classify_api_change("my-lib", "my-lib-v0.1.0", workspace_root=tmp_path)
