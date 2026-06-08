# tacacsrs-bash-plugin

`tacacsrs-bash-plugin` is a direct implementation of SONiC's bash execve plugin
ABI. It is intended for SONiC images that include the bash plugin architecture
from `src/bash/patches/0001-Add-plugin-support-to-bash.patch`.

The shared object exports the three symbols loaded by patched bash:

```c
int plugin_init(void);
int plugin_uninit(void);
int on_shell_execve(char *user, int shell_level, char *cmd, char **argv);
```

Unlike `tacacsrs-libtac`, this crate does not impersonate `libtac.so.2` or
`libtacsupport.so.2`. It builds the command authorization request directly and
sends it to the central `tacacsrs-agentd` IPC service. The daemon owns upstream
TACACS+ server selection, failover, transport security, and protocol handling.

By default the plugin reads SONiC's existing `/etc/tacplus_nss.conf` only for the
bash authorization policy flags:

- `tacacs_authorization` enables per-command TACACS authorization.
- `local_authorization` allows local fallback when the IPC/TACACS path is
  unavailable.
- `debug` enables stderr diagnostics from the plugin.

Set `TACACSRS_BASH_PLUGIN_CONFIG` to point at a different config file. The local
IPC endpoint defaults to `/run/tacacs/tacacs.sock` on Unix, and can be set with
`ipc_endpoint=<endpoint>` in the config file. If the plugin config omits that
setting, `TACACSRS_AGENT_ENDPOINT` remains available as an explicit override,
then `/etc/tacacsrs-agentd/config.ini` is consulted for `ipc_endpoint`, before
falling back to the built-in Unix default.

## Config File

The default config file is `/etc/tacplus_nss.conf`. This matches SONiC's
existing TACACS config path so the plugin can coexist with the legacy
`bash_tacplus` integration. Set `TACACSRS_BASH_PLUGIN_CONFIG` to read a
different file.

The parser is intentionally small. It reads the file as whitespace- or
comma-separated tokens, ignores blank lines, and ignores lines whose first
non-space character is `#`. Supported settings can be written either as bare
tokens or as `name=on`, `name=yes`, `name=true`, or `name=1`. Unknown tokens are
ignored so the same file can still contain PAM, NSS, accounting, server, secret,
timeout, VRF, and source-IP settings used by other SONiC TACACS components.

Supported tokens:

Token | Effect
--- | ---
`tacacs_authorization` or `tacacs_authorization=on` | Enables per-command authorization through `tacacsrs-agentd`. Without this token, commands are allowed locally and no IPC authorization request is sent.
`local_authorization` or `local_authorization=on` | Allows local fallback when the IPC/TACACS path is unavailable. Without this token, an unavailable authorization path blocks the command.
`debug` or `debug=on` | Emits plugin diagnostics to stderr and syslog.
`ipc_endpoint=/run/tacacs/tacacs.sock` | Sets the local `tacacsrs-agentd` IPC endpoint. Use a Unix socket path on SONiC, or a loopback `host:port` value for developer testing. If omitted here, the plugin next checks `TACACSRS_AGENT_ENDPOINT`, then `/etc/tacacsrs-agentd/config.ini`.

Example:

```text
# Other SONiC TACACS settings may remain in this file and are ignored here.
server=192.0.2.10 secret=example timeout=5

# Enable bash command authorization through tacacsrs-agentd.
tacacs_authorization

# Permit normal local authorization if the IPC/TACACS path is unavailable.
local_authorization

# Optional diagnostics. SONiC's stock config commonly uses debug=on.
debug=on

# Optional tacacsrs-agentd IPC endpoint. If omitted, the plugin uses
# /run/tacacs/tacacs.sock on Unix.
ipc_endpoint=/run/tacacs/tacacs.sock
```

The plugin reloads the config when the file modification time changes. A missing
or unreadable config file behaves as if no tokens were configured, which means
per-command TACACS authorization is disabled.

SONiC's bash TACACS behavior skips local users. If you test with the built-in
`admin` account, the plugin should log that the user is local and then allow the
command without sending an IPC authorization request. To exercise TACACS command
authorization, use an NSS-created remote user whose GECOS field starts with
`remote_user`, matching SONiC's legacy `bash_tacplus` policy.

For VM smoke testing, create a local account with the same GECOS marker:

```powershell
.\lde\sonic-vm\Set-SonicTacacsRemoteTestUser.ps1 -EnableLocalFallback
```

`-EnableLocalFallback` appends `local_authorization=on` to the guest config so
the smoke command can complete even when `tacacsrs-agentd` is not ready yet.

Build:

```bash
cargo build -p tacacsrs-bash-plugin
```

From the Windows development checkout, build the Linux `.so` under WSL and copy
it to the SONiC VM with:

```powershell
.\lde\sonic-vm\Publish-SonicSharedLibrary.ps1 -Package tacacsrs-bash-plugin
```

The default remote path is `/data/libtacacsrs_bash_plugin.so`, which is useful
for smoke testing without replacing SONiC packages.

Install the resulting shared library into a SONiC path and reference it from
`/etc/bash_plugins.conf`:

```text
plugin=/usr/lib/x86_64-linux-gnu/security/tacacsrs_bash_plugin.so
```
