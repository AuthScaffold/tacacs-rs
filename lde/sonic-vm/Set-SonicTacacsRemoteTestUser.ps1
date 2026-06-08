<#
.SYNOPSIS
    Create a SONiC test user that is treated as TACACS remote by the bash plugin.
.DESCRIPTION
    SONiC's legacy bash_tacplus policy treats users as remote TACACS users when
    their passwd GECOS/comment field starts with "remote_user". This helper
    creates or updates a local guest account with that marker so the
    tacacsrs-bash-plugin takes the TACACS authorization path during VM smoke
    testing.
.EXAMPLE
    .\lde\sonic-vm\Set-SonicTacacsRemoteTestUser.ps1
.EXAMPLE
    .\lde\sonic-vm\Set-SonicTacacsRemoteTestUser.ps1 -UserName tacacsremote -EnableLocalFallback
.EXAMPLE
    .\lde\sonic-vm\Set-SonicTacacsRemoteTestUser.ps1 -IpcEndpoint /data/tacacs.sock
.EXAMPLE
    .\lde\sonic-vm\Set-SonicTacacsRemoteTestUser.ps1 -NoSmokeTest
#>
[CmdletBinding()]
param(
    [string]$UserName = 'tacacsremote',
    [string]$Gecos = 'remote_user',
    [string]$Shell = '/bin/bash',
    [string[]]$Groups = @('sudo', 'docker'),
    [string]$ConfigPath = '/etc/tacplus_nss.conf',
    [string]$IpcEndpoint = '/run/tacacs/tacacs.sock',
    [string]$HostName = '127.0.0.1',
    [int]$Port = 2222,
    [string]$User = 'admin',
    [switch]$EnableLocalFallback,
    [switch]$NoSmokeTest
)

$ErrorActionPreference = 'Stop'
. $PSScriptRoot\SonicVm.Common.ps1

if ($UserName -notmatch '^[a-z_][a-z0-9_-]*[$]?$') { throw "Invalid Linux user name: $UserName" }
if ($Shell -notmatch '^/[A-Za-z0-9_./-]+$') { throw "Invalid shell path: $Shell" }
if ($IpcEndpoint -notmatch '^[A-Za-z0-9_./:-]+$') { throw "Invalid IPC endpoint: $IpcEndpoint" }
foreach ($group in $Groups) {
    if ($group -notmatch '^[A-Za-z0-9_-]+$') { throw "Invalid Linux group name: $group" }
}

$quotedUserName = Quote-SonicShellArgument $UserName
$quotedGecos = Quote-SonicShellArgument $Gecos
$quotedShell = Quote-SonicShellArgument $Shell
$quotedConfigPath = Quote-SonicShellArgument $ConfigPath
$quotedIpcEndpoint = Quote-SonicShellArgument $IpcEndpoint
$quotedGroups = Quote-SonicShellArgument ($Groups -join ',')
$enableLocalFallbackValue = if ($EnableLocalFallback) { '1' } else { '0' }
$runSmokeValue = if ($NoSmokeTest) { '0' } else { '1' }

$script = @"
set -euo pipefail
user=$quotedUserName
gecos=$quotedGecos
shell_path=$quotedShell
config_path=$quotedConfigPath
ipc_endpoint=$quotedIpcEndpoint
groups_csv=$quotedGroups
enable_local_fallback=$enableLocalFallbackValue
run_smoke=$runSmokeValue

if getent passwd "`$user" >/dev/null; then
  sudo usermod -c "`$gecos" -s "`$shell_path" "`$user"
else
  sudo useradd -m -s "`$shell_path" -c "`$gecos" "`$user"
fi

IFS=',' read -r -a requested_groups <<< "`$groups_csv"
for group in "`${requested_groups[@]}"; do
  [ -n "`$group" ] || continue
  if getent group "`$group" >/dev/null; then
    sudo usermod -aG "`$group" "`$user"
  else
    echo "Skipping missing group `$group" >&2
  fi
done

# Lock password login; tests use sudo from the admin account.
sudo passwd -l "`$user" >/dev/null 2>&1 || true

sudo touch "`$config_path"
ensure_config_token() {
  token="`$1"
  if ! sudo grep -Eq "(^|[[:space:],])`$token([[:space:],]|=|`$)" "`$config_path"; then
    printf '%s\n' "`$token" | sudo tee -a "`$config_path" >/dev/null
  fi
}

ensure_config_token 'debug=on'
ensure_config_token 'tacacs_authorization'
ensure_config_token "ipc_endpoint=`$ipc_endpoint"
if [ "`$enable_local_fallback" = '1' ]; then
  ensure_config_token 'local_authorization=on'
fi

echo '--- test user passwd entry'
getent passwd "`$user"
echo '--- effective plugin config tokens'
sudo grep -E '^(debug|tacacs_authorization|local_authorization|ipc_endpoint)(=|[[:space:]]|`$)' "`$config_path" || true

if [ "`$run_smoke" = '1' ]; then
  echo '--- smoke command as test user'
  sudo -u "`$user" HOME="/home/`$user" USER="`$user" LOGNAME="`$user" SHELL="`$shell_path" \
    "`$shell_path" --noprofile --norc -c '/usr/bin/id; /bin/echo tacacs remote smoke command completed'
fi
"@

& $PSScriptRoot\Invoke-SonicCommand.ps1 `
    -HostName $HostName `
    -Port $Port `
    -User $User `
    -ScriptText $script `
    -AllowFailure

if ($LASTEXITCODE -ne 0) {
    throw "Remote TACACS test user setup failed with exit code $LASTEXITCODE."
}

Write-Host "Configured SONiC TACACS remote test user '$UserName'."
