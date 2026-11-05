# Develop and test with the SONiC VM

This guide explains how to run SONiC on a Windows development machine, configure its TACACS+ servers, and test tacacs-rs components inside the guest. The initial setup gives you an admin shell without a physical switch. Building Rust artifacts, observing configuration changes, and testing command authorization are separate workflows that you can follow after the VM is ready.

The VM uses the SONiC virtual-switch image and QEMU, which emulates the computer that runs the image. Your Windows machine is the **host**, and the SONiC virtual machine (VM) is the **guest**. This environment supports development inside SONiC; it does not replace testing on switch hardware or validating a production deployment.

PowerShell examples run on Windows. After the checkout step, all PowerShell examples assume that your current folder is `tacacs-rs\lde\sonic-vm`. Bash examples run inside the SONiC guest unless the surrounding text says otherwise.

## Prepare Windows

The VM manager needs QEMU, Git, and an OpenSSH client on Windows. You do not need Rust, Windows Subsystem for Linux (WSL), or a TACACS+ server just to start the guest and open an admin shell. The later build and authorization procedures explain when those additional components become necessary.

These procedures use PowerShell. If it is not installed, see [Install PowerShell on Windows](https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows).

### Install and check QEMU

If QEMU is not installed, install the Windows package:

```powershell
winget install SoftwareFreedomConservancy.QEMU
```

If Windows cannot find `winget`, follow the [WinGet installation instructions](https://learn.microsoft.com/windows/package-manager/winget/#install-winget). Alternatively, use the installers linked from the [QEMU Windows download page](https://www.qemu.org/download/#windows).

The manager expects the QEMU emulator and disk tool under `C:\Program Files\qemu`. Check both programs before you start the VM:

```powershell
& 'C:\Program Files\qemu\qemu-system-x86_64.exe' --version
& 'C:\Program Files\qemu\qemu-img.exe' --version
```

Both commands should print version information. If your installation uses another folder, use its actual paths and pass them to the manager with `-QemuExe` and `-QemuImgExe`.

The default VM configuration requests 20,480 MB of memory and 10 virtual CPUs. These values are the script's defaults, not established minimum requirements. Leave enough host capacity for Windows and your other tools. You can change the requested resources with `-MemoryMB` and `-Cpus`; those changes take effect when the VM next starts, not while it is already running.

Also leave disk space for the compressed image, extracted image, writable system disk, and data disk. The data disk has a default virtual capacity of 10 GB, and its host file grows as the guest writes data. The operating system image and writable system disk need additional space.

### Check Git and OpenSSH

Git obtains the checkout, and OpenSSH connects to the guest and transfers files. Check the Windows tools:

```powershell
git --version
ssh -V
Get-Command ssh-keygen, scp
```

Git and SSH should print version information, and PowerShell should find `ssh-keygen` and `scp`. If Git is missing, install [Git for Windows](https://git-scm.com/downloads/win), then open a new PowerShell window.

If SSH is missing, follow Microsoft's [OpenSSH installation instructions](https://learn.microsoft.com/windows-server/administration/openssh/openssh_install_firstuse) to install **OpenSSH Client**. Windows initiates the connection, and SONiC accepts it. You do not need to enable OpenSSH Server or open Windows port 22 for this workflow.

### Prepare an SSH key

The helpers use key authentication for routine guest access. The public key goes into the guest, while the private key stays on Windows. The VM manager looks for these public keys in order:

1. `$env:USERPROFILE\.ssh\id_ed25519.pub`
2. `$env:USERPROFILE\.ssh\id_rsa.pub`
3. `$env:USERPROFILE\.ssh\id_ecdsa.pub`

You can reuse an existing suitable key pair. If you have none, create one:

```powershell
ssh-keygen -t ed25519
```

Accept the default location unless you need another path, and do not overwrite an existing key. Follow your organization's policy for protecting the private key. If the key has a passphrase, make it available to your SSH agent before using the helpers; see Microsoft's [OpenSSH key management guidance](https://learn.microsoft.com/windows-server/administration/openssh/openssh_keymanagement).

For a public key outside the standard locations, pass `-PublicKeyPath` during key installation or `Up`. The matching private key must also be available to the Windows SSH client. Specifying a public-key path does not select a private key for subsequent connections.

## Open the checkout

Clone the repository into a path without spaces, then enter the helper folder:

```powershell
git clone https://github.com/AuthScaffold/tacacs-rs.git
Set-Location .\tacacs-rs\lde\sonic-vm
```

If you already have a checkout, navigate to its `lde\sonic-vm` folder instead. The examples that follow use paths relative to that folder. The VM manager resolves its disk and image parameters relative to the script folder, so starting it from another working directory does not move the VM files.

### If PowerShell blocks a downloaded script

If Windows marks a script as downloaded, PowerShell can block it. First review the file and verify that you trust its source. If your organization's policy permits running the script, remove the downloaded-file block:

```powershell
Unblock-File .\sonic-vm.ps1
```

Then retry the command. `Unblock-File` does not add a digital signature or override a policy that requires signed scripts. Apply the same review to any other downloaded helper that Windows blocks, and use your organization's approved process if execution remains restricted. Do not bypass a managed policy or change machine-wide execution policy for this guide.

## Start SONiC

Use [sonic-vm.ps1](sonic-vm.ps1) to prepare the guest for work. Its normal startup action does more than launch QEMU: it waits for SSH, establishes key access, and mounts the data disk.

**Warning:** Use a dedicated development VM, and do not point the disk parameters at unrelated files. First-time setup creates writable disks and initializes a blank data disk. The helpers also use development-image credentials and disable SSH host-key verification, so this configuration is not suitable for production access.

1. Start the guest from the helper folder:

   ```powershell
   .\sonic-vm.ps1 -Action Up
   ```

   Omitting `-Action` runs the same `Up` action. If the named VM is not already running, the helper prepares missing image and disk files, then starts QEMU in the background. The first download and boot can take longer than subsequent starts.

2. For a new boot, follow the guest startup in the QEMU window that opens. If you see an operating-system selection menu or a "press any key" prompt, click inside that window and press **Enter** to accept the default selection or continue. Repeat for any further boot prompts. The PowerShell helper cannot respond to these prompts for you.

3. Wait for the helper to report that SSH is available at `127.0.0.1:2222`. A running QEMU process does not mean that SONiC has finished booting.

4. If first-time key setup prompts for a password, enter the SONiC admin password. The default development image uses `YourPaSsWoRd`, with that capitalization. This is the guest password, not your Windows password. Use the current guest password if the image or account differs. When key access already works, the helper skips this password login.

5. Wait for key installation and the `/data` mount to finish. A successful run ends with a `Ready.` message and returns to PowerShell rather than opening a guest shell.

At this point, SSH access and the data mount are ready. The startup check does not verify every SONiC service. Running `Up` again reuses an active VM and repeats the access and mount checks; it does not reset the guest.

For a QEMU installation outside the default folder, supply both executable paths:

```powershell
.\sonic-vm.ps1 -Action Up `
  -QemuExe 'D:\Tools\qemu\qemu-system-x86_64.exe' `
  -QemuImgExe 'D:\Tools\qemu\qemu-img.exe'
```

### Choose an image source

When neither a base image nor a compressed image exists locally, the manager queries the public SONiC build API for the newest completed successful build. It selects the `sonic-buildimage.vs` artifact, downloads `/target/sonic-vs.img.gz`, and extracts the base image. The selected build ID and artifact name appear in the output.

Existing image files are reused without a build lookup. Running `Up` again does not check for a newer image or upgrade an existing VM. For a separate environment with a newer image, use a different `-VmName` and separate image, compressed-image, overlay, and data-disk paths. If both VMs will run concurrently, choose unused SSH, monitor, and serial ports as well. Do not replace a base image that an existing overlay already depends on.

The discovery parameters let you select another build definition or compatible artifact:

| Parameter | Default | Purpose |
|---|---|---|
| `-BuildApiUrl` | `https://dev.azure.com/mssonic/build/_apis/build` | Azure DevOps build API root. |
| `-BuildDefinitionId` | `142` | Build definition whose newest completed successful build supplies the artifact. |
| `-ImageArtifactName` | `sonic-buildimage.vs` | Artifact name to select from that build. |
| `-ImageArtifactSubPath` | `/target/sonic-vs.img.gz` | Image file within the artifact. |

Use `-ImageUrl` to select an explicit artifact URL instead of discovering the latest build. The downloader rewrites that URL to use `format=file` and the chosen artifact subpath. Like discovery, this override is used only when both local image files are absent; it does not force an existing image to download again.

If the API is unavailable, no successful build exists, or the selected build lacks the artifact, the manager reports an error rather than falling back to an old URL. You can still supply an image locally: for initial setup, place `sonic-vs.img` or `sonic-vs.img.gz` beside the script before running `Up`. The helper uses the uncompressed image if it exists; otherwise, it extracts the compressed file. Use `-ImagePath` and `-CompressedImagePath` for other local file locations.

A browser's authenticated session does not necessarily give the script download access. For other distribution formats or authentication requirements, obtain a suitable SONiC virtual-switch image separately and supply the local file.

## Connect to the guest

Once `Up` finishes, open an admin session:

```powershell
.\sonic-vm.ps1 -Action Ssh
```

The helper connects as `admin` to Windows address `127.0.0.1` on port `2222`. QEMU forwards that connection to port `22` inside SONiC. After the prompt changes to the SONiC shell, commands run in the guest rather than on Windows.

Inspect the guest and its data mount from that shell:

```bash
hostname
show version
df -h /data
```

The version output should identify SONiC, and `df` should show the filesystem mounted at `/data`. The hostname and version depend on your image.

You can also inspect TACACS+ and authentication, authorization, and accounting (AAA) configuration:

```bash
show tacacs
show aaa
```

These commands show configuration, not proof that a server accepts requests. Treat the output as potentially sensitive and redact credentials before sharing it.

To return to PowerShell, run `exit` inside the guest. Exiting SSH leaves QEMU running. Use the `Ssh` action to reconnect; if the VM is stopped, run `Up` first.

## Understand storage and network addresses

The guest's filesystem and network are separate from Windows. Understanding that boundary helps you choose where to copy artifacts and which address to use for a TACACS+ server.

### System disk and persistent data

By default, the manager keeps these files beside the script:

| File | Purpose |
|---|---|
| `sonic-vs.img.gz` | Compressed download of the SONiC base image. |
| `sonic-vs.img` | Base operating system image, marked read-only when the default overlay mode is used. |
| `overlay.qcow2` | Writable system disk that stores guest changes separately from the base image. |
| `data.qcow2` | Separate data disk, mounted at `/data` inside the guest. |

Normal stops and starts preserve the disk files. Use `/data` for Linux artifacts, captured output, and other development files. The manager mounts the data disk during `Up`; the existence of a `/data` directory alone does not prove that the disk is mounted, so use `df -h /data` when in doubt.

Disk persistence is separate from SONiC's saved startup configuration. A TACACS+ change in the running configuration still needs an explicit save to survive a reboot; see [Save SONiC configuration](#save-sonic-configuration).

The overlay and data disk are not interchangeable backups. Resetting the overlay discards guest system changes such as installed software and accounts, even though `/data` survives. The [lifecycle controls](#stop-the-vm-and-manage-its-lifecycle) explain the available snapshot and reset actions.

### Choose the address for each direction

The same loopback address means different machines depending on where a command runs. These are the defaults for the manager's QEMU user-mode network:

| Connection | Address to use |
|---|---|
| Windows to guest SSH | `127.0.0.1:2222` from Windows; QEMU forwards it to guest port `22`. |
| Guest to a TACACS+ server on the QEMU host | `10.0.2.2:49` from SONiC, unless the server uses another TCP port. |
| Guest to a service inside the guest itself | `127.0.0.1` from SONiC. |
| Guest to a server on another machine | That server's address, reachable from the guest. |

The host address `10.0.2.2` comes from QEMU's default user-mode network, not from a Windows network adapter. You do not need to discover the host's LAN address. Guest-to-host TCP connections also do not need another `hostfwd` rule: the existing SSH rule forwards traffic in the opposite direction. See the [QEMU networking guide](https://wiki.qemu.org/Documentation/Networking) for the network model.

The TACACS+ server must listen on the selected TCP port, and the host firewall must permit the connection. If the server runs inside WSL or a container, expose its port on the machine that runs QEMU. A successful Windows connection does not prove guest connectivity, and `ping` is not a substitute for checking the TCP service; QEMU user-mode networking has ICMP limitations.

The SSH forwarding rule does not explicitly bind its Windows listener to loopback. Keep the host firewall appropriate for a local development VM rather than opening external access. The other default host ports are `44001` for the QEMU monitor and `5001` for the serial console.

## Configure TACACS+ servers

The manager's TACACS+ actions configure the running guest through SONiC's native CLI. They require a running VM, working SSH key access, and passwordless `sudo` in the guest. These actions do not start or restart the VM, install keys, or start a TACACS+ server.

Server configuration and login policy are separate. Adding a server makes its connection properties available to SONiC, while enabling TACACS+ changes how new logins authenticate. Neither operation installs the tacacs-rs Bash plugin or enables its per-command authorization path.

### Add a server

For a server on the QEMU host, add the default address and TCP port:

```powershell
.\sonic-vm.ps1 -Action AddTacacsServer
```

This creates an entry for `10.0.2.2` on TCP port `49`, with priority `1`. If your server requires a shared secret or different connection properties, use the following command instead of the default add. The secret comes from a hidden prompt rather than a literal in shell history:

```powershell
$passkey = Read-Host 'TACACS+ shared secret' -AsSecureString
.\sonic-vm.ps1 -Action AddTacacsServer `
  -TacacsPasskey $passkey `
  -TacacsPort 4949 `
  -TacacsPriority 10 `
  -TacacsTimeoutSeconds 5
```

The connection properties have these defaults and limits:

| Parameter | Default | Accepted values |
|---|---|---|
| `-TacacsServer` | `10.0.2.2` for both add and remove | IPv4 or IPv6 address without a scope ID. |
| `-TacacsPort` | `49` | `1..65535`. |
| `-TacacsPriority` | `1` | `1..64`. |
| `-TacacsTimeoutSeconds` | Native global/default inheritance | `1..60` seconds. |
| `-TacacsPasskey` | Native global passkey inheritance | A `SecureString` containing 1 to 256 printable ASCII characters, except space, `#`, and `,`. |

The port, priority, timeout, and passkey parameters apply only to add. The native SONiC configuration determines the authentication type. This helper configures TCP, not TLS; TACACS+ shared-secret obfuscation is not encryption.

For a remote server or a different QEMU network, override the default address. Replace this documentation address with the actual address reachable from the guest:

```powershell
.\sonic-vm.ps1 -Action AddTacacsServer -TacacsServer 192.0.2.10
```

If an entry already exists, add returns an error and leaves its properties unchanged. Changing an entry requires removing it and adding it again. A successful add verifies the requested configuration, not server reachability or accepted credentials.

### Enable or disable login authentication

Enable TACACS+ only when you intend to change login authentication. You can leave login authentication local while testing the Bash plugin's command authorization, which is a separate procedure later in this guide.

**Warning:** Keep a working admin session or console available before enabling TACACS-only login. If no server can authenticate the user, new access can fail.

Select TACACS-only login:

```powershell
.\sonic-vm.ps1 -Action EnableTacacs
```

To return to local login, run:

```powershell
.\sonic-vm.ps1 -Action DisableTacacs
```

These actions change login authentication globally, not individual server entries. Both preserve configured servers, authorization, accounting, and the existing authentication failthrough policy. Enable selects `tacacs+` alone, not `tacacs+` followed by `local`.

With no servers configured, enable warns but still applies TACACS-only login. The warning is not a safety interlock, so verify your server and recovery access before using the command.

### Remove a server

Remove the default host entry with the same address-free interface used for add:

```powershell
.\sonic-vm.ps1 -Action RemoveTacacsServer
```

For an explicitly configured address, supply that address again:

```powershell
.\sonic-vm.ps1 -Action RemoveTacacsServer -TacacsServer 192.0.2.10
```

Removal identifies an entry by its address, regardless of its TCP port. An unknown address returns an error. Removing the final server while TACACS+ login is active produces a warning but still removes the entry; retain your admin session and consider switching login back to local before changing the final server.

### Save SONiC configuration

By default, TACACS+ actions change only the running configuration. Add `-SaveConfig` when you want the action to save the resulting configuration across reboot. The manager saves only after it verifies that the requested change took effect.

**Warning:** Review the running configuration before using `-SaveConfig`. SONiC saves the whole running configuration, including unrelated changes, not just the TACACS+ action.

For example, apply and save the local-login policy:

```powershell
.\sonic-vm.ps1 -Action DisableTacacs -SaveConfig
```

You can also pass `-SaveConfig` when adding or removing a server, or when enabling TACACS+ login. If saving fails, the action reports an error, but the verified running change remains active. A save error does not roll back the configuration.

## Build, copy, and run development artifacts

After the guest is ready, use the other helpers in this folder for the edit-build-test cycle. They share the default SSH destination `admin@127.0.0.1:2222` and expect key authentication to work. Unlike `Up`, they do not prepare a stopped VM.

### Build Linux artifacts through WSL

The SONiC guest needs Linux ELF binaries and shared libraries, not Windows `.exe` or `.dll` files. The publishing helpers run Cargo in WSL from the Windows checkout, then copy the resulting artifact into `/data`. Prepare the Rust toolchain and native build dependencies in the WSL distribution used by `wsl`; see the [SONiC build guide](../../docs/sonic-build-guide.md) for target and build requirements.

Publish the ConfigDB watcher example:

```powershell
.\Publish-SonicExample.ps1 -Package tacacsrs-sonic -Example configdb_watch
```

Publish a standard binary or the Bash plugin shared library:

```powershell
.\Publish-SonicBinary.ps1 -Package tacon
.\Publish-SonicBinary.ps1 -Package tacacsrs-agentd -Profile release
.\Publish-SonicSharedLibrary.ps1 -Package tacacsrs-bash-plugin -Profile release
```

The default destinations are `/data/configdb_watch`, `/data/tacon`, `/data/tacacsrs-agentd`, and `/data/libtacacsrs_bash_plugin.so`. The publishers default to the debug profile; `-Profile release` selects release artifacts. Use `-Bin` when a binary target differs from its package name, or `-LibName` when the shared-library target differs from the package name with hyphens replaced by underscores.

Each publisher also accepts `-RemotePath` and `-NoBuild`. With `-NoBuild`, the expected artifact must already exist under the checkout's `target\debug` or `target\release` tree. If your build uses a different target directory or an explicit target triple, use the copy helper with the actual artifact path.

Publishing transfers a file and makes it executable. It does not install a system service, register the Bash plugin, or start the daemon. The [command authorization procedure](#test-command-authorization-as-a-remote-user) describes the additional integration prerequisites.

### Copy files in either direction

Use [Copy-ToSonic.ps1](Copy-ToSonic.ps1) when you already have an artifact to transfer. This example copies an existing Linux watcher binary from the repository's build directory and marks the guest file executable:

```powershell
.\Copy-ToSonic.ps1 `
  -LocalPath ..\..\target\debug\examples\configdb_watch `
  -RemotePath /data/configdb_watch `
  -Executable
```

After a test creates output in the guest, retrieve it with [Copy-FromSonic.ps1](Copy-FromSonic.ps1):

```powershell
.\Copy-FromSonic.ps1 `
  -RemotePath /data/configdb_watch.out `
  -LocalPath ..\..\target\tmp\configdb_watch.out
```

The copy helpers create the necessary destination directories. Copy-to handles a local directory recursively; use `-Recurse` when copying a directory from the guest. Keep artifacts and logs in `/data` so they remain on the separate data disk.

### Run a command or script without an interactive shell

Use [Invoke-SonicCommand.ps1](Invoke-SonicCommand.ps1) to run a command and return to PowerShell:

```powershell
.\Invoke-SonicCommand.ps1 "hostname"
```

For several Bash commands, use `-ScriptText` with a literal PowerShell here-string. The literal form leaves Bash variables and quoting for the guest to interpret:

```powershell
.\Invoke-SonicCommand.ps1 -ScriptText @'
set -e
hostname
df -h /data
'@
```

The helper also accepts `-ScriptPath` for an existing local script and `-Interactive` for a shell. Remote errors normally become PowerShell errors. Keep that behavior for test procedures rather than using `-AllowFailure` to hide a failed operation.

### Use custom SSH connection settings consistently

The VM manager calls its SSH port parameter `-SshPort`, while the command, copy, publishing, and scenario helpers use `-Port`. Both groups accept `-User`; the non-lifecycle helpers also accept `-HostName`. The upstream TACACS+ port is a separate `-TacacsPort` parameter.

For example, if you start the VM with a different SSH forwarding port, pass that same port to subsequent commands:

```powershell
.\sonic-vm.ps1 -Action Up -SshPort 2223
.\Invoke-SonicCommand.ps1 -Port 2223 "hostname"
.\Publish-SonicBinary.ps1 -Package tacon -Port 2223
```

Use the chosen manager settings again for lifecycle and TACACS+ actions. Changing a parameter while QEMU is already running does not reconfigure its existing port forwarding.

## Observe SONiC configuration changes

The `configdb_watch` example observes TACACS+ configuration in SONiC's Redis `CONFIG_DB`, which is database `4`. It demonstrates configuration loading and change notifications; it does not authenticate a user or prove that a TACACS+ server is reachable. See the [SONiC ConfigDB integration guide](../../docs/sonic-configdb-integration.md) for the mapping and watcher behavior.

After publishing the example, inspect the configured key names and run a bounded initial load:

```powershell
.\Invoke-SonicCommand.ps1 "redis-cli -n 4 --scan --pattern 'TACPLUS*' | sort"
.\Invoke-SonicCommand.ps1 "/data/configdb_watch --max-events 0"
```

Scanning key names avoids printing raw hashes that can contain shared secrets. Keep manual watcher runs bounded with `--max-events` so a test does not leave an unattended watcher running.

### Run the add-and-remove scenario

[Test-ConfigDbWatch.ps1](Test-ConfigDbWatch.ps1) runs a complete scenario: it starts with one server, observes another server's addition and removal, removes the final server, and verifies a cold start with zero servers.

**Warning:** Use this scenario only in a disposable test configuration. It removes all native `TACPLUS_SERVER` rows and the `TACPLUS|global` row, changes Redis keyspace-notification settings, and does not restore the original configuration. Record the configuration you need to restore, and keep an admin session available.

Before the scenario, select local login so that removing the final server does not leave new logins dependent on TACACS+. Then build, publish, and run the test:

```powershell
.\sonic-vm.ps1 -Action DisableTacacs
.\Test-ConfigDbWatch.ps1 -Publish
```

If the intended watcher binary is already at `/data/configdb_watch`, omit `-Publish`. A successful scenario prints `PASS: The SONiC VM configdb_watch scenario passed.` and leaves no native TACACS+ server entries. Its output files are `/data/configdb_watch.out` and `/data/configdb_watch.err`.

Restore your intended server entries and global configuration before other TACACS+ tests. Do not save the scenario's empty configuration unless that is the startup state you want.

## Test command authorization as a remote user

TACACS+ authentication establishes a user's identity, while authorization decides which operations that user can perform. This procedure tests Bash command authorization through `tacacsrs-bash-plugin` and `tacacsrs-agentd`. It does not test SSH login authentication, so you can keep SONiC login authentication local throughout the procedure.

The plugin skips ordinary local accounts such as `admin`. To exercise the remote-user path without a separate login setup, [Set-SonicTacacsRemoteTestUser.ps1](Set-SonicTacacsRemoteTestUser.ps1) creates or updates a local test account with a `remote_user` marker in its account comment field, called GECOS. The plugin recognizes that marker and treats the account as a remote TACACS+ user for command authorization.

### Prepare the authorization path

Starting the VM and copying artifacts are not enough to enable authorization. Before using the test-user helper, prepare these components:

- A SONiC Bash shell with the plugin support expected by [tacacsrs-bash-plugin](../../libraries/tacacsrs_bash_plugin/README.md).
- The plugin installed and referenced by `/etc/bash_plugins.conf`.
- A running `tacacsrs-agentd` process with the intended upstream server configuration.
- Matching plugin and daemon settings for their local Unix socket. The default endpoint is `/run/tacacs/tacacs.sock`, and the test account needs permission to use it.
- A reachable test TACACS+ server with an agreed policy for the test user. Choose an allowed external command and a harmless denied external command before testing.

Use the [SONiC build and installation guide](../../docs/sonic-build-guide.md) and [agent runtime guide](../../docs/tacacsrs-agentd.md) to prepare missing components. If the daemon uses SONiC-backed configuration, the server actions in this guide update its native configuration source. A daemon started with separate CLI or file configuration does not automatically use those server entries.

**Warning:** Keep a separate admin session open before changing authorization settings. The helper changes guest accounts and `/etc/tacplus_nss.conf`, enables debug output, and adds the test account to the `sudo` and `docker` groups if those groups exist. Use the account only in the dedicated development VM, and record the configuration you need to restore.

### Create the marked test account

From Windows PowerShell, run:

```powershell
.\Set-SonicTacacsRemoteTestUser.ps1
```

The default account is `tacacsremote`. The helper marks the account as a remote user, attempts to lock its password login, and prepares plugin configuration tokens. It then uses the admin connection to run `/usr/bin/id` and `/bin/echo` from Bash as the test user. The intended access path is through `sudo` from your admin session, not direct password SSH to the test account.

If your daemon listens on a different socket, supply its actual endpoint when you run the helper. For example, use the following alternative only when the running daemon listens at `/data/tacacs.sock`:

```powershell
.\Set-SonicTacacsRemoteTestUser.ps1 -IpcEndpoint /data/tacacs.sock
```

Check the printed account entry for the `remote_user` marker and the expected account name. The smoke commands can print `TACACS+ remote smoke command completed`, but that message alone does not prove remote authorization. Review the effective plugin configuration and daemon diagnostics before proceeding.

The helper adds missing tokens; it does not reconcile existing disabled or conflicting settings. Confirm that authorization is enabled and that the configured socket matches the running daemon. Resolve conflicts in the guest rather than assuming that another helper run will replace them.

For a test that proves remote authorization, do not enable `-EnableLocalFallback`. Local fallback permits command execution when the remote path is unavailable. Also check for an existing enabled `local_authorization` token: omitting the switch does not remove a previous setting. Disable unavailable-path fallback for fail-closed tests while retaining your admin recovery session.

### Verify an allow decision and a denial

In the admin SSH session, open a login shell as the test user:

```bash
sudo -iu tacacsremote
```

This uses your existing admin access; it does not authenticate the test user against the TACACS+ server. Run the external command that the server policy allows. For example, if the policy allows `/usr/bin/id`, run:

```bash
/usr/bin/id
```

The output should identify `tacacsremote`. Use external programs for these checks, because Bash built-ins such as `cd` do not exercise the plugin's external-command hook.

Verify the authorization path rather than relying on command output alone:

1. Check that the plugin sends an authorization request for `tacacsremote`, rather than treating the account as local or allowing execution because authorization is disabled.
2. Check daemon diagnostics or server logs for the request to the intended server and the expected allow decision.
3. Run the harmless external command configured for denial. Confirm that execution is blocked and that the server records the denial. Do not use a destructive command to test denial.

If the observations disagree, resolve the configuration, socket, or connectivity problem before drawing conclusions about the policy. Keep shared secrets and other credentials out of copied logs and source control.

When finished, run `exit` once to return to the admin shell. Run it again only when you want to close the admin SSH connection and return to PowerShell.

## Stop the VM and manage its lifecycle

Finish guest operations and save the work you need before stopping QEMU. In particular, save SONiC configuration explicitly if you want running changes to survive a reboot. Then close guest shells and stop the VM from PowerShell:

```powershell
.\sonic-vm.ps1 -Action Stop
.\sonic-vm.ps1 -Action Status
```

Status should report that the named VM is not running. Stop requests guest shutdown and then exits QEMU; it can also force-stop a remaining process. Do not treat Stop as a substitute for finishing writes or saving configuration. At your next session, run `Up`, wait for readiness, and reconnect with `Ssh`.

The lifecycle actions serve different purposes:

| Action | Behavior |
|---|---|
| `Up` | Starts the VM if needed, waits for SSH, establishes key access, and mounts `/data`. This is the default action. |
| `Start` | Launches QEMU in the foreground without waiting for SSH or preparing the data mount. Useful for seeing startup errors. |
| `Ssh` | Opens an interactive session to an existing guest, with key setup if necessary. |
| `InstallKey` or `CopyKey` | Installs a public key when key access does not already work. |
| `Mount` | Prepares and mounts the data disk in an existing guest. |
| `Umount` | Unmounts the guest data disk. Finish operations that use `/data` first. |
| `Status` | Shows the named process, connection details, and disk information. It is not a guest-service health check. |
| `Stop` | Requests guest shutdown, exits QEMU, and can force-stop a remaining process. |

### Preserve a system-disk snapshot

For a development checkpoint, the manager can copy a stopped VM's overlay into a named snapshot. Save your work and any required startup configuration before stopping the VM, then create the snapshot:

```powershell
.\sonic-vm.ps1 -Action Stop
.\sonic-vm.ps1 -Action Snapshot -SnapshotName before-auth-tests
.\sonic-vm.ps1 -Action ListSnapshots
```

The snapshot covers the overlay only, not the separate data disk. Reusing the same snapshot name overwrites that snapshot. The `Restore` action requires the VM to be stopped and replaces the current overlay with the named copy; preserve any newer system changes before restoring. The `Reset` action also requires a stopped VM and discards the overlay in favor of a clean base. Neither action is a routine recovery step for an unexplained error.

## Troubleshoot the environment

Start with the exact error and the current VM state. Do not delete disks, reset the overlay, stop unrelated processes, or enable authorization fallback merely to make a test pass. The checks below distinguish setup errors from guest-service and authorization problems.

| Symptom | Check and next action |
|---|---|
| QEMU or `qemu-img` is not found | Verify the installation paths. Use `-QemuExe` and `-QemuImgExe` if they differ from the defaults. |
| Windows cannot find `winget` | Install WinGet or use the manual installer linked under [Install and check QEMU](#install-and-check-qemu). |
| PowerShell cannot find a helper | Return to `tacacs-rs\lde\sonic-vm` and include the `.\` prefix. |
| A downloaded script is blocked or reported as unsigned | Review the script and follow [the execution-policy guidance](#if-powershell-blocks-a-downloaded-script). Unblocking does not satisfy a signed-script requirement. |
| Image discovery or download fails | Check build API access, the build definition, artifact availability, and download access. Use [an explicit image source or local file](#choose-an-image-source) rather than assuming browser authentication applies to the script. |
| `No SSH public key found` | Create a key without overwriting an existing key, or pass `-PublicKeyPath` with an OpenSSH public-key file. Never pass the private-key file. |
| Key installation or `Permission denied (publickey)` errors | Check the current guest password, selected public key, matching private key, and SSH agent. Once SSH is available, `InstallKey` can retry key setup. |
| The VM stops before SSH becomes available | Check `Status`. If it is stopped, use `Start` to see the QEMU console error. Do not launch another copy against the same disks. |
| SSH is unavailable after the 240-second wait | Check the QEMU window for an unanswered boot menu or key prompt, then inspect process state. The guest may still be booting, or startup may have failed; investigate before changing resources or disks. |
| QEMU reports a port conflict | Identify the listener using `2222`, `44001`, or `5001`. Do not stop an unrelated process. Use consistent custom port parameters if needed. |
| `/data` does not show the expected mounted filesystem | Run `df -h /data` in SONiC, then use `Up` for the supported mount procedure. Investigate disk-detection errors rather than formatting a disk manually. |
| A TACACS+ add reports an existing entry | Add does not update properties. Review the entry, retain recovery access, and remove it before adding its replacement. |
| A TACACS+ action reports a save error | The running change can remain active. Inspect the running configuration before retrying a save. |
| The guest cannot run a copied artifact | Check that it is a Linux artifact for the guest's architecture, has executable permissions, and has compatible runtime libraries. A Windows `.exe` cannot run natively in SONiC. |
| Commands work as `admin`, but no authorization requests appear | The Bash plugin skips ordinary local accounts. Use the marked test account and verify that the plugin is installed and authorization is enabled. |
| Commands work as the test user, but the server sees no request | Check for an unloaded plugin, disabled authorization, or enabled local fallback. Successful command output is not proof of a server decision. |
| Remote-user commands fail before reaching the server | Check the daemon, socket path, account permissions, and guest-to-server TCP connectivity. Preserve fail-closed behavior while you diagnose the failure. |

## Run the helper regression tests

The two regression helpers in [tests/](tests/) cover the VM manager without starting a guest. [Test-SonicImageDownload.ps1](tests/Test-SonicImageDownload.ps1) uses mocked build metadata and a small compressed image fixture to check latest-build selection, cached images, explicit overrides, and errors. [Test-SonicTacacsManagement.ps1](tests/Test-SonicTacacsManagement.ps1) replaces SSH and native SONiC commands with local fixtures to check the TACACS+ actions, including validation, warnings, secret handling, result verification, and save behavior.

Use PowerShell 7 to run both tests; the TACACS+ tests also need Bash and Python 3. Neither helper needs Pester or access to the build API. From the helper folder, run:

```powershell
pwsh -NoLogo -NoProfile -File .\tests\Test-SonicImageDownload.ps1
pwsh -NoLogo -NoProfile -File .\tests\Test-SonicTacacsManagement.ps1
```

A successful run prints the number of assertions that passed. These local tests do not replace checking the commands against the SONiC image used for your development work.
