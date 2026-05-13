---
description: "Use when testing on Windows while changing the session-wrapper project. Prefer WSL for Linux-specific validation and map Windows paths to /mnt/<drive>/<path>."
applyTo: "executables/session_wrapper/**,docs/session-wrapper-testing.md"
---
# Session Wrapper WSL Testing

- When making or validating changes to `session-wrapper` from Windows, prefer WSL for tests that exercise Linux-only behavior such as seccomp, process supervision, signals, shell scripts, or demo execution.
- The repository is typically available in WSL under `/mnt/<drive>/<path>`. For example, `x:/code/tacacs-rs` maps to `/mnt/x/code/tacacs-rs`.
- Use the current workspace path to derive the WSL path. For this repo, `x:/tacacs-rs-2` maps to `/mnt/x/tacacs-rs-2`.
- From PowerShell, run WSL commands with an explicit working directory, for example:

```powershell
wsl --cd /mnt/x/tacacs-rs-2 -- bash -lc 'source "$HOME/.cargo/env" 2>/dev/null || true; cargo test -p session-wrapper'
```

- For shell demos, run them in WSL with bounded timeouts so a process-supervision regression cannot leave the validation stuck indefinitely.
