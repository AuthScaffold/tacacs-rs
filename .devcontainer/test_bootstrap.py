"""Offline checks for the native source-volume bootstrap."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


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
        for name in ["bootstrap-source.sh", "initialize-workspace.sh", "post-create.sh"]:
            self.assertTrue((self.directory / name).is_file())
            self.assertIn(name, dockerfile)
            subprocess.run(["bash", "-n", str(self.directory / name)], check=True)
        self.assertEqual(self.config["onCreateCommand"][:3], ["sudo", "-n", "bash"])
        self.assertEqual(self.config["onCreateCommand"][-1], "/usr/local/share/tacacs-rs/initialize-workspace.sh")
        self.assertEqual(self.config["postCreateCommand"], ["bash", "/usr/local/share/tacacs-rs/post-create.sh"])
        initializer = (self.directory / "initialize-workspace.sh").read_text(encoding="utf-8")
        self.assertIn("chown -R vscode:vscode /usr/local/cargo/registry /usr/local/cargo/git", initializer)


if __name__ == "__main__":
    unittest.main()