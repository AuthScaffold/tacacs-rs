---
description: "Use when: testing tacacs-rs binaries on SONiC VS running under QEMU, using configdb_watch, tacacsrs-sonic, SONiC ConfigDB, Redis DB 4, lde/sonic-vm helpers, SSH/SCP on port 2222, or WSL Linux builds from Windows."
applyTo: "libraries/tacacsrs_sonic/**,executables/tacacsrs_agentd/**,docs/sonic-*.md,lde/run-sonic-configdb-smoke.ps1,lde/sonic-vm/**"
---
# SONiC QEMU Testing

- The SONiC VM is managed by `lde/sonic-vm/sonic-vm.ps1`. Assume the VM is already running and SSH key authentication is configured unless the user asks for lifecycle work. Do not reset, restore, or restart the VM just to run a test.
- If lifecycle work is needed, use `.\lde\sonic-vm\sonic-vm.ps1 -Action Up`, `-Action Status`, or `-Action Stop`. The script forwards host port `2222` to guest SSH and mounts persistent guest storage at `/data`.
- For normal testing, prefer the helper scripts in `lde/sonic-vm` instead of handwritten SSH/SCP commands. They encode the standard SSH options and assume key auth:

```powershell
.\lde\sonic-vm\Invoke-SonicCommand.ps1 "hostname"
.\lde\sonic-vm\Invoke-SonicCommand.ps1 -ScriptText "set -e`nhostname"
.\lde\sonic-vm\Copy-ToSonic.ps1 -LocalPath target\debug\examples\configdb_watch -RemotePath /data/configdb_watch -Executable
.\lde\sonic-vm\Copy-FromSonic.ps1 -RemotePath /data/configdb_watch.out -LocalPath target\tmp\configdb_watch.out
```

- When a Rust binary must run inside the SONiC VS QEMU guest, build it from WSL so the artifact is a Linux ELF binary. Do not copy a Windows-built `.exe` into SONiC.
- The preferred build-and-copy path for Rust examples is:

```powershell
.\lde\sonic-vm\Publish-SonicExample.ps1 -Package tacacsrs-sonic -Example configdb_watch
```

- If doing the WSL build manually from PowerShell, build from the repository root through WSL. For this workspace, `x:/tacacs-rs-2` maps to `/mnt/x/tacacs-rs-2`:

```powershell
wsl --cd /mnt/x/tacacs-rs-2 -- bash -lc 'source "$HOME/.cargo/env" 2>/dev/null || true; cargo build -p tacacsrs-sonic --example configdb_watch'
```

- Connect to the guest interactively only when needed:

```powershell
.\lde\sonic-vm\Invoke-SonicCommand.ps1 -Interactive
```

- Copy rebuilt Linux artifacts to `/data` with the local file first and the remote destination second. Prefer `Copy-ToSonic.ps1`; if using raw `scp`, the correct order for `configdb_watch` is:

```powershell
scp -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o LogLevel=ERROR -o BatchMode=yes X:\tacacs-rs-2\target\debug\examples\configdb_watch admin@127.0.0.1:/data/configdb_watch
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o LogLevel=ERROR -o BatchMode=yes admin@127.0.0.1 "chmod +x /data/configdb_watch"
```

- SONiC `CONFIG_DB` is Redis database `4`. Before running `configdb_watch`, inspect the TACACS rows so failures are explained by guest state, not by the binary:

```powershell
.\lde\sonic-vm\Invoke-SonicCommand.ps1 "redis-cli -n 4 HGETALL 'TACPLUS|global' && redis-cli -n 4 --scan --pattern 'TACPLUS*' | sort"
```

- `configdb_watch` supports rows with no per-server or global `passkey`; those map to plain TCP without TACACS+ body obfuscation and should print `shared_secret_configured: false`. If a test specifically needs obfuscation, seed a test-only global or per-server secret:

```powershell
.\lde\sonic-vm\Invoke-SonicCommand.ps1 "redis-cli -n 4 HSET 'TACPLUS|global' passkey test-shared-secret"
```

- For watcher tests, enable Redis keyspace notifications and use bounded runs such as `--max-events 0` for initial-load validation or `--max-events 1` for a single live event. Avoid leaving unbounded watchers running in automation.

```powershell
.\lde\sonic-vm\Invoke-SonicCommand.ps1 "redis-cli -n 4 CONFIG SET notify-keyspace-events KEA >/dev/null && /data/configdb_watch --max-events 0"
```

- For the common `configdb_watch` add/delete smoke path, prefer the bounded VM scenario helper:

```powershell
.\lde\sonic-vm\Test-ConfigDbWatch.ps1 -Publish
```

- To verify a live event manually, start `/data/configdb_watch --max-events 1` in one terminal, mutate a TACACS row from another terminal, then restore the original value after the event is observed. Prefer small reversible mutations such as changing `TACPLUS_SERVER|127.0.0.1 timeout`.
- When testing add/delete behavior, include deleting the final `TACPLUS_SERVER|<addr>` row. The expected watcher output is a `removed_servers` entry for that server and `current_server_count: 0`; `configdb_watch --max-events 0` should also restart cleanly against that empty ConfigDB state.
- If a helper script fails, inspect remote state before changing code: `.\lde\sonic-vm\Invoke-SonicCommand.ps1 "redis-cli -n 4 --scan --pattern 'TACPLUS*' | sort && ls -l /data"`.
