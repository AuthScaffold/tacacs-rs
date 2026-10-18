"""Test the command blocks in the fuzz smoke composite action."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path


ACTION_PATH = Path(__file__).with_name("action.yml")
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
HOST_OUTPUT_EXPRESSION = "${{ steps.compiler_host.outputs.host }}"
COMPILER_HOST = "x86_64-unknown-linux-gnu"
CARGO_FUZZ_DEFAULT_TARGET = "x86_64-unknown-linux-musl"
FUZZ_STEPS = {
    "Fuzz header parsing": "fuzz_header_parse",
    "Fuzz accounting request parsing": "fuzz_accounting_request_parse",
    "Fuzz accounting reply parsing": "fuzz_accounting_reply_parse",
    "Fuzz accounting request packet parsing": "fuzz_accounting_request_packet_parse",
    "Fuzz authentication message parsing": "fuzz_authentication_parse",
    "Fuzz authorization message parsing": "fuzz_authorization_parse",
    "Fuzz all protocol message families": "fuzz_protocol_parse",
}


@dataclass
class ActionStep:
    name: str
    step_id: str | None = None
    script: str | None = None


def load_action_steps() -> dict[str, ActionStep]:
    """Load names, IDs, and literal command blocks from the composite action."""
    lines = ACTION_PATH.read_text(encoding="utf-8").splitlines()
    steps: dict[str, ActionStep] = {}
    current: ActionStep | None = None
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("    - name: "):
            current = ActionStep(name=line.removeprefix("    - name: "))
            steps[current.name] = current
        elif current is not None and line.startswith("      id: "):
            current.step_id = line.removeprefix("      id: ")
        elif current is not None and line == "      run: |":
            block: list[str] = []
            index += 1
            while index < len(lines):
                block_line = lines[index]
                if block_line and not block_line.startswith("        "):
                    index -= 1
                    break
                block.append(block_line[8:] if block_line else "")
                index += 1
            current.script = "\n".join(block)
        index += 1
    return steps


class FuzzSmokeActionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(
            prefix=".fuzz-action-test-",
            dir=REPOSITORY_ROOT,
        )
        self.scratch_path = Path(self.scratch.name)
        self.bin_path = self.scratch_path / "bin"
        self.bin_path.mkdir()
        self.output_path = self.scratch_path / "github-output"
        self.call_log_path = self.scratch_path / "cargo-calls.jsonl"
        self.steps = load_action_steps()
        self._write_mock_tools()

        self.environment = os.environ.copy()
        self.environment.update(
            {
                "PATH": f"{self.bin_path}{os.pathsep}{self.environment['PATH']}",
                "GITHUB_OUTPUT": str(self.output_path),
                "MOCK_COMPILER_HOST": COMPILER_HOST,
                "MOCK_CARGO_DEFAULT_TARGET": CARGO_FUZZ_DEFAULT_TARGET,
                "MOCK_CARGO_CALL_LOG": str(self.call_log_path),
            }
        )

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def _write_executable(self, name: str, source: str) -> None:
        path = self.bin_path / name
        path.write_text(source, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def _write_mock_tools(self) -> None:
        self._write_executable(
            "rustc",
            """#!/usr/bin/env python3
import os
import sys

if sys.argv[1:] != ["+nightly", "-vV"]:
    sys.exit(97)
mode = os.environ.get("MOCK_RUSTC_MODE", "success")
if mode == "failure":
    sys.exit(42)
print("rustc 1.93.0-nightly")
if mode != "empty":
    print(f"host: {os.environ['MOCK_COMPILER_HOST']}")
""",
        )
        self._write_executable(
            "cargo",
            """#!/usr/bin/env python3
import json
import os
import sys

arguments = sys.argv[1:]
target = os.environ["MOCK_CARGO_DEFAULT_TARGET"]
for index, argument in enumerate(arguments):
    if argument == "--target" and index + 1 < len(arguments):
        target = arguments[index + 1]
    elif argument.startswith("--target="):
        target = argument.partition("=")[2]

sanitizer = "address"
for index, argument in enumerate(arguments):
    if argument in ("-s", "--sanitizer") and index + 1 < len(arguments):
        sanitizer = arguments[index + 1]
    elif argument.startswith("--sanitizer="):
        sanitizer = argument.partition("=")[2]

with open(os.environ["MOCK_CARGO_CALL_LOG"], "a", encoding="utf-8") as call_log:
    call_log.write(json.dumps({
        "args": arguments,
        "selected_target": target,
        "sanitizer": sanitizer,
    }) + "\\n")

fuzz_target = arguments[3] if arguments[:3] == ["+nightly", "fuzz", "run"] else ""
if fuzz_target == os.environ.get("MOCK_FAIL_TARGET"):
    sys.exit(73)
""",
        )

    def _run_script(
        self,
        script: str,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
            cwd=REPOSITORY_ROOT,
            env=environment or self.environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def _select_compiler_host(self) -> str:
        step = self.steps["Select nightly compiler host"]
        self.assertEqual(step.step_id, "compiler_host")
        self.assertIsNotNone(step.script)
        result = self._run_script(step.script or "")
        self.assertEqual(result.returncode, 0, result.stderr)

        outputs = dict(
            line.split("=", 1)
            for line in self.output_path.read_text(encoding="utf-8").splitlines()
            if line
        )
        self.assertEqual(outputs, {"host": COMPILER_HOST})
        return outputs["host"]

    def _render_fuzz_script(self, step_name: str, host: str) -> str:
        script = self.steps[step_name].script
        self.assertIsNotNone(script)
        self.assertEqual((script or "").count(HOST_OUTPUT_EXPRESSION), 1)
        return (script or "").replace(HOST_OUTPUT_EXPRESSION, host)

    def _read_calls(self) -> list[dict[str, object]]:
        return [
            json.loads(line)
            for line in self.call_log_path.read_text(encoding="utf-8").splitlines()
        ]

    def test_fuzz_steps_pin_the_compiler_host_and_preserve_contract(self) -> None:
        host = self._select_compiler_host()
        self.assertNotEqual(host, CARGO_FUZZ_DEFAULT_TARGET)
        actual_fuzz_steps = {
            step_name for step_name in self.steps if step_name.startswith("Fuzz ")
        }
        self.assertEqual(actual_fuzz_steps, set(FUZZ_STEPS))

        for step_name in FUZZ_STEPS:
            result = self._run_script(self._render_fuzz_script(step_name, host))
            self.assertEqual(result.returncode, 0, result.stderr)

        calls = self._read_calls()
        self.assertEqual(len(calls), len(FUZZ_STEPS))
        for call, expected_target in zip(calls, FUZZ_STEPS.values(), strict=True):
            arguments = call["args"]
            self.assertEqual(
                arguments,
                [
                    "+nightly",
                    "fuzz",
                    "run",
                    expected_target,
                    "--target",
                    host,
                    "--",
                    "-max_total_time=30",
                ],
            )
            self.assertEqual(arguments.count("--target"), 1)
            self.assertLess(arguments.index("--target"), arguments.index("--"))
            self.assertEqual(call["selected_target"], host)
            self.assertEqual(call["sanitizer"], "address")

    def test_fuzz_failure_propagates(self) -> None:
        host = self._select_compiler_host()
        environment = self.environment | {"MOCK_FAIL_TARGET": "fuzz_header_parse"}
        result = self._run_script(
            self._render_fuzz_script("Fuzz header parsing", host),
            environment,
        )
        self.assertEqual(result.returncode, 73)

    def test_host_selection_rejects_rustc_failure_and_empty_host(self) -> None:
        step = self.steps["Select nightly compiler host"]
        self.assertIsNotNone(step.script)
        for mode in ("failure", "empty"):
            with self.subTest(mode=mode):
                self.output_path.unlink(missing_ok=True)
                environment = self.environment | {"MOCK_RUSTC_MODE": mode}
                result = self._run_script(step.script or "", environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.output_path.exists())


if __name__ == "__main__":
    unittest.main()
