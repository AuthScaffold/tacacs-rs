"""Offline checks for the native source-volume bootstrap."""

import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch


BOOTSTRAP = Path(__file__).with_name("bootstrap-source.sh")


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tacacs-container-test-")
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.seed = root / "host seed"
        self.workspace = root / "native workspace"
        self.seed.mkdir()
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.git(self.seed, "init", "--quiet", "--initial-branch=refactor/test")
        self.git(self.seed, "config", "user.name", "Container Test")
        self.git(self.seed, "config", "user.email", "container-test@example.invalid")
        (self.seed / "tracked.txt").write_text("committed data\n", encoding="utf-8")
        (self.seed / ".gitignore").write_text("target/\n", encoding="utf-8")
        self.git(self.seed, "add", ".")
        self.git(self.seed, "commit", "--quiet", "-m", "test seed")
        self.git(self.seed, "remote", "add", "origin", "https://example.invalid/tacacs-rs.git")
        self.revision = self.git(self.seed, "rev-parse", "HEAD")

    def git(self, directory, *arguments):
        result = subprocess.run(
            ["git", "-C", str(directory), *arguments],
            env=self.env, text=True, capture_output=True, check=True,
        )
        return result.stdout.strip()

    def bootstrap(self, expected_success=True):
        result = subprocess.run(
            ["bash", str(BOOTSTRAP), str(self.workspace), str(self.seed)],
            env=self.env, text=True, capture_output=True, timeout=30,
        )
        if expected_success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_imports_local_branch_without_shared_git_metadata(self):
        windows_record = self.seed / ".git" / "worktrees" / "windows-only"
        windows_record.mkdir(parents=True)
        (windows_record / "gitdir").write_text("Q:/host-worktree/.git\n", encoding="utf-8")
        self.bootstrap()
        self.assertEqual(self.git(self.workspace, "rev-parse", "HEAD"), self.revision)
        self.assertEqual(self.git(self.workspace, "branch", "--show-current"), "refactor/test")
        self.assertEqual(self.git(self.workspace, "remote", "get-url", "origin"), "https://example.invalid/tacacs-rs.git")
        self.assertEqual(self.git(self.workspace, "config", "core.fsmonitor"), "false")
        self.assertEqual(self.git(self.workspace, "config", "core.autocrlf"), "false")
        self.assertFalse((self.workspace / ".git" / "worktrees").exists())
        self.assertFalse((self.workspace / ".git" / "objects" / "info" / "alternates").exists())

    def test_rebuild_preserves_native_branch_and_uncommitted_work(self):
        self.bootstrap()
        self.git(self.workspace, "switch", "-c", "refactor/native")
        (self.workspace / "tracked.txt").write_text("native work\n", encoding="utf-8")
        (self.seed / "tracked.txt").write_text("host changed independently\n", encoding="utf-8")
        self.bootstrap()
        self.assertEqual(self.git(self.workspace, "branch", "--show-current"), "refactor/native")
        self.assertEqual((self.workspace / "tracked.txt").read_text(encoding="utf-8"), "native work\n")
        self.assertEqual(self.git(self.workspace, "rev-parse", "HEAD"), self.revision)

    def test_rebuild_does_not_need_the_seed_repository(self):
        self.bootstrap()
        self.seed.rename(self.seed.with_name("old seed"))
        self.bootstrap()
        self.assertEqual(self.git(self.workspace, "rev-parse", "HEAD"), self.revision)

    def test_rejects_uncommitted_tracked_changes(self):
        (self.seed / "tracked.txt").write_text("unsaved to Git\n", encoding="utf-8")
        result = self.bootstrap(expected_success=False)
        self.assertIn("tracked changes", result.stderr)
        self.assertFalse((self.workspace / ".git").exists())

    def test_rejects_staged_changes(self):
        (self.seed / "tracked.txt").write_text("staged work\n", encoding="utf-8")
        self.git(self.seed, "add", "tracked.txt")
        self.bootstrap(expected_success=False)
        self.assertFalse((self.workspace / ".git").exists())

    def test_rejects_a_linked_worktree_seed(self):
        linked = self.seed.with_name("linked seed")
        self.git(self.seed, "worktree", "add", "-b", "refactor/linked", str(linked))
        self.seed = linked
        result = self.bootstrap(expected_success=False)
        self.assertIn("own .git directory", result.stderr)

    def test_rejects_detached_seed(self):
        self.git(self.seed, "switch", "--detach")
        result = self.bootstrap(expected_success=False)
        self.assertIn("detached HEAD", result.stderr)

    def test_keeps_untracked_files_in_the_seed(self):
        (self.seed / "local-notes.txt").write_text("private local notes\n", encoding="utf-8")
        result = self.bootstrap()
        self.assertIn("1 untracked files remain", result.stdout)
        self.assertFalse((self.workspace / "local-notes.txt").exists())
        self.assertTrue((self.seed / "local-notes.txt").exists())

    def test_accepts_the_nested_build_volume(self):
        target = self.workspace / "target"
        target.mkdir(parents=True)
        (target / "sentinel").touch()
        self.bootstrap()
        self.assertTrue((target / "sentinel").exists())

    def test_refuses_to_overwrite_existing_nonrepository_files(self):
        self.workspace.mkdir()
        sentinel = self.workspace / "keep.txt"
        sentinel.write_text("keep\n", encoding="utf-8")
        self.bootstrap(expected_success=False)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep\n")

    def test_rejects_a_partial_import(self):
        self.workspace.mkdir()
        self.git(self.workspace, "init", "--quiet")
        result = self.bootstrap(expected_success=False)
        self.assertIn("incomplete repository", result.stderr)


class ContainerConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.directory = BOOTSTRAP.parent
        self.config = json.loads((self.directory / "devcontainer.json").read_text(encoding="utf-8"))

    def test_source_and_editor_state_use_workspace_specific_volumes(self):
        self.assertEqual(self.config["workspaceFolder"], "/workspaces/tacacs-rs")
        self.assertEqual(
            self.config["workspaceMount"],
            "source=tacacs-rs-native-source,target=/workspaces/tacacs-rs,type=volume",
        )
        self.assertFalse(self.config["updateRemoteUserUID"])
        mounts = self.config["mounts"]
        self.assertIn("source=${localWorkspaceFolder},target=/mnt/tacacs-rs-seed,type=bind,readonly", mounts)
        for suffix, target in [
            ("target", "${containerWorkspaceFolder}/target"),
            ("editor", "/home/vscode/.vscode-server"),
        ]:
            self.assertIn(f"source=tacacs-rs-${{devcontainerId}}-{suffix},target={target},type=volume", mounts)
        self.assertEqual(self.config["containerEnv"]["CARGO_TARGET_DIR"], "${containerWorkspaceFolder}/target")

    def test_bootstrap_scripts_are_in_the_image_build_context(self):
        self.assertEqual(self.config["build"]["context"], ".")
        self.assertEqual(self.config["waitFor"], "postCreateCommand")
        dockerfile = (self.directory / "Dockerfile").read_text(encoding="utf-8")
        for name in ["bootstrap-source.sh", "initialize-workspace.sh", "post-create.sh", "install-tacplus.sh"]:
            self.assertTrue((self.directory / name).is_file())
            self.assertIn(name, dockerfile)
            subprocess.run(["bash", "-n", str(self.directory / name)], check=True)
        self.assertEqual(self.config["onCreateCommand"][:3], ["sudo", "-n", "bash"])
        self.assertEqual(self.config["onCreateCommand"][-1], "/usr/local/share/tacacs-rs/initialize-workspace.sh")
        self.assertEqual(self.config["postCreateCommand"], ["bash", "/usr/local/share/tacacs-rs/post-create.sh"])
        initializer = (self.directory / "initialize-workspace.sh").read_text(encoding="utf-8")
        self.assertIn("chown -R vscode:vscode /usr/local/cargo/registry /usr/local/cargo/git", initializer)

    def test_image_provides_recent_validation_tools(self):
        dockerfile = (self.directory / "Dockerfile").read_text(encoding="utf-8")
        for toolchain in ("1.88.0", "1.91.0", "nightly-2025-11-23"):
            self.assertIn(f"rustup toolchain install {toolchain} --profile minimal", dockerfile)
        nightly = next(line for line in dockerfile.splitlines() if "install nightly --" in line)
        for component in ("rustfmt", "clippy", "miri", "rust-src"):
            self.assertIn(f"--component {component}", nightly)
        self.assertIn("rustup default 1.88.0", dockerfile)
        self.assertIn("python3 -m venv /opt/tacacs-python", dockerfile)
        for dependency in ("pyang==2.7.1", "pytest==8.4.2", "PyYAML==6.0.3"):
            self.assertIn(dependency, dockerfile)
        self.assertIn('ENV PATH="/home/vscode/.local/bin:/opt/tacacs-python/bin:/opt/tacacs-tools/bin:/opt/tacacs-test-server/sbin:${PATH}"', dockerfile)
        self.assertIn("cargo-cyclonedx --version 0.5.9 --locked", dockerfile)

    def test_image_provides_native_test_and_release_tools(self):
        dockerfile = (self.directory / "Dockerfile").read_text(encoding="utf-8")
        packages = set(dockerfile.split())
        for package in (
            "binutils", "build-essential", "libcrypt-dev", "libpcre2-dev",
            "libseccomp-dev", "libssl-dev", "openssl", "perl", "pkg-config",
            "redis-server", "redis-tools", "zlib1g-dev",
        ):
            self.assertIn(package, packages)

    def test_post_create_installs_the_repository_api_tool(self):
        script = (self.directory / "post-create.sh").read_text(encoding="utf-8")
        self.assertIn("cargo +1.91.0 install --path .github/tools/api-classifier --locked", script)
        self.assertIn('--root "$HOME/.local"', script)
        self.assertIn('--target-dir "${CARGO_TARGET_DIR:-target}/api-classifier"', script)

    def test_image_installs_a_pinned_server_without_starting_it(self):
        dockerfile = (self.directory / "Dockerfile").read_text(encoding="utf-8")
        installer = (self.directory / "install-tacplus.sh").read_text(encoding="utf-8")
        self.assertIn("RUN bash /usr/local/share/tacacs-rs/install-tacplus.sh", dockerfile)
        self.assertIn("TACPLUS_SERVER_BINARY=/opt/tacacs-test-server/sbin/tac_plus-ng", dockerfile)
        self.assertIn("TACPLUS_LIBRARY_DIR=/opt/tacacs-test-server/lib", dockerfile)
        self.assertIn("revision=70bf938b542d63bca00d50be0874a38a290319e0", installer)
        self.assertIn('rev-parse HEAD)" == "$revision"', installer)
        self.assertIn('"$prefix/sbin/tac_plus-ng" -v', installer)
        self.assertNotIn("EXPOSE", dockerfile)
        self.assertNotIn("install-tacplus.sh", (self.directory / "post-create.sh").read_text(encoding="utf-8"))

    def test_server_installer_preserves_nonempty_destination(self):
        with tempfile.TemporaryDirectory(prefix="tacacs-install-test-") as directory:
            sentinel = Path(directory) / "keep.txt"
            sentinel.write_text("existing installation\n", encoding="utf-8")
            result = subprocess.run(
                ["bash", str(self.directory / "install-tacplus.sh"), directory],
                capture_output=True, text=True, timeout=5,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("new or empty", result.stderr)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "existing installation\n")

    def test_interop_runner_uses_image_defaults_and_accepts_overrides(self):
        runner = runpy.run_path(str(self.directory.parent / "lde/run-tacplus-interop.py"))
        with patch.dict(os.environ, {
            "TACPLUS_SERVER_BINARY": "/opt/tacacs-test-server/sbin/tac_plus-ng",
            "TACPLUS_LIBRARY_DIR": "/opt/tacacs-test-server/lib",
        }, clear=True):
            args = runner["parse_args"]([])
            self.assertEqual(args.server_binary, Path(os.environ["TACPLUS_SERVER_BINARY"]))
            self.assertEqual(args.library_dir, Path(os.environ["TACPLUS_LIBRARY_DIR"]))
            self.assertEqual(args.mode, "all")
            override = runner["parse_args"]([
                "--server-binary", "/tmp/custom-server", "--library-dir", "/tmp/custom-libs", "--mode", "baseline",
            ])
            self.assertEqual(override.server_binary, Path("/tmp/custom-server"))
            self.assertEqual(override.library_dir, Path("/tmp/custom-libs"))
            self.assertEqual(override.mode, "baseline")
        with patch.dict(os.environ, {}, clear=True):
            explicit = runner["parse_args"](["--server-binary", "/tmp/custom-server"])
            self.assertEqual(explicit.server_binary, Path("/tmp/custom-server"))
            self.assertIsNone(explicit.library_dir)


if __name__ == "__main__":
    unittest.main()