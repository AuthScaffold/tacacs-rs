# Native-Volume Development Container

## Storage Model

The development container stores source and its independent `.git` directory in a Linux-native named volume.
It mounts the original host checkout read-only at `/mnt/tacacs-rs-seed`.
That checkout supplies the first import, including local commits that are not on GitHub.
It is not synchronized with later changes in the native checkout.

The active VS Code workspace remains `/workspaces/tacacs-rs`.
Editor tools, terminals, Cargo, and Git must all use that workspace.
Editing a host checkout while testing a different native checkout recreates the two-copy problem.

| Volume suffix | Contents | Rebuild behavior |
| --- | --- | --- |
| `source` | Working files, independent Git metadata, local branches, and uncommitted native work | Preserved without fetch, checkout, or reset |
| `target` | Cargo build artifacts for this container workspace | Preserved and separate from other workspaces |
| `registry` | Cargo registry cache | Preserved |
| `cargo-git` | Cargo Git dependency cache | Preserved |
| `editor` | Remote `.vscode-server` installation and state | Preserved for the same volume identity |

The source volume is named `tacacs-rs-native-source`.
This static name avoids a Dev Containers CLI interpolation error in `workspaceMount`.
The other volume names start with `tacacs-rs-${devcontainerId}-`.
The Dev Container ID remains stable across rebuilds of the same configuration identity.
A different host folder or configuration identity can select different cache and editor volumes.
All checkouts that use this profile on the same Docker host share the source volume.
Before deleting or pruning volumes, inspect their contents and back up local commits and uncommitted work.
Volumes survive container rebuilds, not deletion of the volumes or container-engine storage.

## First Migration

These steps preserve the current refactor branch without a network push.

1. Review any dirty editor buffers and compare them with disk before saving or discarding them.
2. Review and commit tracked changes in the host checkout, including this container configuration.
3. Keep `refactor/yang-first-toolkit` checked out in the host checkout.
4. Review untracked files and make a separate backup of any files that must survive.
5. From the existing host-folder connection, run **Dev Containers: Rebuild Container**.
6. If no container is attached, open the original host checkout and run **Dev Containers: Reopen in Container**.
7. After setup completes, verify the branch and commit inside `/workspaces/tacacs-rs`.

The host must run Docker or Podman with Dev Containers support.
On Windows, start its WSL2 or Hyper-V machine before rebuilding.
For Podman, configure VS Code's `dev.containers.dockerPath` as `podman`.
Do not rebuild from an unsaved or uncommitted configuration and assume that the source import includes it.

```bash
git status --short
git branch --show-current
git log -5 --oneline
findmnt -T /workspaces/tacacs-rs -o TARGET,SOURCE,FSTYPE
findmnt -T "$CARGO_TARGET_DIR" -o TARGET,SOURCE,FSTYPE
```

The source filesystem must no longer report `9p` or `drvfs`.
The bootstrap imports the seed's exact current commit into a fresh Git repository on its named branch.
It does not copy Windows Git configuration, linked-worktree records, object alternates, or hardlinks.
It preserves the `origin` URL but does not push or configure a new upstream automatically.
It imports only the current branch and its reachable history, not every local branch or tag.

The bootstrap rejects a detached seed, dirty tracked files, a linked-worktree seed, or a nonempty destination without a valid checkout.
The nested `target` mount is allowed in an otherwise empty source volume.
Untracked and ignored files remain in the host seed and are not silently copied.

If import is interrupted, inspect the partial native repository before retrying.
The helper refuses an incomplete `.git` directory rather than deleting uncertain contents automatically.
After successful import, later rebuilds preserve the native checkout even if the host branch changes.

## Rebuilds and Backups

Ordinary code changes belong only in the native workspace after migration.
The original host folder remains the launch configuration for this profile.
Changes to its `.devcontainer` definition determine the next image build.
If you change container definitions in the native clone, commit them and explicitly update the host launch copy before rebuilding.
Compare the launch copy first and preserve any independent host edits.
This bootstrap profile trades automatic host synchronization for a clear single source workspace.

To back up local committed work without pushing, create a Git bundle on the native volume:

```bash
git bundle create /workspaces/tacacs-rs/refactor-backup.bundle refactor/yang-first-toolkit
git bundle verify /workspaces/tacacs-rs/refactor-backup.bundle
```

Download the bundle to private host storage before removing any volume.
The bundle contains committed history, not uncommitted or untracked files.
Commit work or back up those files separately before deleting storage.
Do not commit the bundle into the repository.

## Installed Tools

The image retains Rust 1.88.0 as the workspace default and installs its Clippy and coverage components.
Nightly supplies rustfmt, Clippy, and Miri.
Stable builds standalone Cargo tools without changing the workspace MSRV.
The configuration disables remote-user UID updates because all writable paths use named volumes.
The initialization command assigns those volumes to the `vscode` user.
It recursively repairs ownership in the Cargo cache because Docker copies root-owned image content into a new cache volume.
This setting also prevents an unnecessary generated UID image and its `BASE_IMAGE` warning.

The image includes ripgrep, jq, ShellCheck, GitHub CLI, Python venv support, pytest, and the native OpenSSL/libseccomp build dependencies.
It also installs `cargo-audit`, `cargo-fuzz`, `cargo-llvm-cov`, `cargo-outdated`, `cargo-udeps`, and `mdbook`.
Buf comes from the versioned upstream container image.
Standalone Cargo tool versions follow their locked published releases at image-build time.
This is a development image, not a bit-for-bit reproducible release artifact.

The first image build needs network access and can take longer while it compiles the tools.
Later builds reuse container layers and named dependency caches.
Post-create setup fetches the locked workspace dependencies and runs the bootstrap contract tests.
It does not run the full Rust suite or fix existing warnings automatically.

## Validation and Limitations

Local validation without a container engine:

```bash
python3 -m unittest discover -s .devcontainer -p 'test_*.py' -v
bash -n .devcontainer/bootstrap-source.sh .devcontainer/initialize-workspace.sh .devcontainer/post-create.sh
jq empty .devcontainer/devcontainer.json
```

The bootstrap tests use temporary repositories and require no network or third-party Python packages.
They cover local-branch preservation, rebuild idempotence, refusal of unsafe inputs, and independent Git metadata.

The current container has no Docker, Podman, or Dev Container CLI.
The full image build, engine-specific mounts, and first attach need validation through the host's Dev Containers extension.
Do not interpret the offline tests as proof that the image was built or that container migration succeeded.

The source migration reduces filesystem risk but does not prove that the intermittent editor save problem is fixed.
Serialize editor edits and terminal formatting for each file, verify disk saves, and compare divergent versions before recovery.

References:

- [Dev Containers filesystem guidance](https://code.visualstudio.com/remote/advancedcontainers/improve-performance)
- [Dev Container configuration reference](https://containers.dev/implementors/json_reference/)