# SONiC VM Testing Helpers

These scripts are thin wrappers for testing tacacs-rs binaries in the SONiC VS
QEMU VM managed by `sonic-vm.ps1`. They assume the VM is already running and
SSH key authentication works for `admin@127.0.0.1` on port `2222`.

Use the VM manager only for lifecycle tasks:

```powershell
.\lde\sonic-vm\sonic-vm.ps1 -Action Up
.\lde\sonic-vm\sonic-vm.ps1 -Action Status
.\lde\sonic-vm\sonic-vm.ps1 -Action Stop
```

For day-to-day testing, prefer the helpers below.

## Run Commands

```powershell
.\lde\sonic-vm\Invoke-SonicCommand.ps1 "hostname"
.\lde\sonic-vm\Invoke-SonicCommand.ps1 "redis-cli -n 4 --scan --pattern 'TACPLUS*' | sort"
.\lde\sonic-vm\Invoke-SonicCommand.ps1 -ScriptText "set -e`nredis-cli -n 4 CONFIG SET notify-keyspace-events KEA >/dev/null`n/data/configdb_watch --max-events 0"
.\lde\sonic-vm\Invoke-SonicCommand.ps1 -Interactive
```

## Copy Files

Copy a rebuilt binary into persistent guest storage:

```powershell
.\lde\sonic-vm\Copy-ToSonic.ps1 `
  -LocalPath target\debug\examples\configdb_watch `
  -RemotePath /data/configdb_watch `
  -Executable
```

Copy guest output back to the repo:

```powershell
.\lde\sonic-vm\Copy-FromSonic.ps1 `
  -RemotePath /data/configdb_watch.out `
  -LocalPath target\tmp\configdb_watch.out
```

## Build Linux Artifacts Under WSL

Windows `cargo build` produces Windows binaries. SONiC needs Linux ELF
artifacts, so build through WSL and then copy the Linux artifact.

Publish an example binary:

```powershell
.\lde\sonic-vm\Publish-SonicExample.ps1 `
  -Package tacacsrs-sonic `
  -Example configdb_watch
```

Publish a standard Cargo binary such as `tacon`:

```powershell
.\lde\sonic-vm\Publish-SonicBinary.ps1 `
  -Package tacon
```

By default, the binary name is the package name. Use `-Bin` only when a package
produces a differently named binary. The default remote destination is
`/data/<example-or-binary-name>`.

## Run The ConfigDB Watcher Scenario

This drives the add, delete, delete-final-server flow in the running VM and
verifies that `configdb_watch` can cold-start with no TACACS servers:

```powershell
.\lde\sonic-vm\Test-ConfigDbWatch.ps1 -Publish
```

Omit `-Publish` when `/data/configdb_watch` is already the binary you want to
test.

## Notes For Copilot

- Do not use password-oriented SSH options for VM testing. The VM is expected to
  have key authentication configured.
- Keep watcher runs bounded with `--max-events` so terminals do not stay open.
- Use `/data` for copied artifacts and captured logs because it is persistent.
- Use Redis database `4` for SONiC `CONFIG_DB`.
- Enable keyspace notifications before watcher tests:
  `redis-cli -n 4 CONFIG SET notify-keyspace-events KEA`.
