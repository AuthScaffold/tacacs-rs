"""Exercise the real build scripts in isolated Cargo subprocess environments."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


class ProtocSelectionTests(unittest.TestCase):
    def test_explicit_unset_invalid_and_changed_compiler(self):
        compiler = os.environ.get("PROTOC", "/usr/bin/protoc")
        with tempfile.TemporaryDirectory(prefix="protoc-selection-") as directory:
            root = Path(directory)
            log = root / "invocations"
            environment = {**os.environ, "PROTOC_TEST_LOG": str(log)}
            command = [
                "cargo", "check", "--locked",
                "-p", "tacacsrs-ipc", "-p", "tacacsrs-agent-ipc-emulator",
            ]

            def check(protoc, success):
                env = environment.copy()
                if protoc is None:
                    env.pop("PROTOC", None)
                else:
                    env["PROTOC"] = str(protoc)
                result = subprocess.run(command, env=env, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        timeout=600, check=False)
                self.assertEqual(result.returncode == 0, success, result.stdout)
                if not success:
                    self.assertIn("protoc", result.stdout.lower())

            for label in ("first", "second"):
                wrapper = root / label
                wrapper.write_text(
                    "#!/bin/sh\nset -eu\n"
                    f'printf "{label} %s\\n" "$*" >> "$PROTOC_TEST_LOG"\n'
                    f'exec {shlex.quote(compiler)} "$@"\n'
                )
                wrapper.chmod(0o755)
                check(wrapper, True)
                lines = log.read_text().splitlines()
                for schema in ("proto/tacacsrs_agent.proto",
                               "proto/tacacsrs_agent_mock_controller.proto"):
                    self.assertTrue(any(line.startswith(label + " ") and schema in line
                                        for line in lines), (label, schema, lines))

            check(root / "missing-protoc", False)
            check("", False)
            before = log.read_text()
            check(None, True)
            self.assertEqual(log.read_text(), before)
            check(compiler, True)


if __name__ == "__main__":
    unittest.main()
