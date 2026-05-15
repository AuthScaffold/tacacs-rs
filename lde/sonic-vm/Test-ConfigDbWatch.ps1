<#
.SYNOPSIS
    Run a bounded configdb_watch scenario inside the SONiC QEMU VM.
.DESCRIPTION
    Resets TACPLUS rows in CONFIG_DB, seeds one server, starts configdb_watch,
    adds a second server, deletes it, deletes the final server, and verifies the
    watcher reports a zero-server snapshot. This script assumes the VM is
    already running and reachable with key-based SSH.
.EXAMPLE
    .\lde\sonic-vm\Test-ConfigDbWatch.ps1 -Publish
#>
[CmdletBinding()]
param(
    [string]$WatcherPath = '/data/configdb_watch',
    [string]$PrimaryServer = '127.0.0.1',
    [string]$SecondaryServer = '127.0.0.2',
    [ValidateRange(0, 10000)]
    [int]$DebounceMs = 250,
    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 90,
    [string]$HostName = '127.0.0.1',
    [int]$Port = 2222,
    [string]$User = 'admin',
    [switch]$Publish
)

$ErrorActionPreference = 'Stop'
. $PSScriptRoot\SonicVm.Common.ps1

$invokeScript = Join-Path $PSScriptRoot 'Invoke-SonicCommand.ps1'

function Invoke-Guest {
    param(
        [Parameter(Mandatory)][string]$Command,
        [switch]$ScriptText
    )

    $output = if ($ScriptText) {
        & $invokeScript -HostName $HostName -Port $Port -User $User -ScriptText $Command
    } else {
        & $invokeScript -HostName $HostName -Port $Port -User $User $Command
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Remote command failed: $Command"
    }
    ($output | Out-String).TrimEnd()
}

function Wait-ForGuestOutputText {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Text
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $content = Invoke-Guest "cat $(Quote-SonicShellArgument $Path) 2>/dev/null || true"
        if ($content.Contains($Text)) {
            return $content
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "Timed out waiting for $Path to contain '$Text'."
}

function Wait-ForGuestPidExit {
    param([Parameter(Mandatory)][string]$PidFile)

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $pidFileArgument = Quote-SonicShellArgument $PidFile
        $state = Invoke-Guest ('pid=$(cat ' + $pidFileArgument + ' 2>/dev/null || true); if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then echo running; else echo done; fi')
        if ($state.Trim() -eq 'done') {
            return
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "Timed out waiting for guest process in $PidFile to exit."
}

function Assert-Contains {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$Expected
    )

    if (-not $Text.Contains($Expected)) {
        throw "Expected watcher output to contain: $Expected"
    }
}

if ($Publish) {
    & $PSScriptRoot\Publish-SonicExample.ps1 -HostName $HostName -Port $Port -User $User
}

$quotedWatcherPath = Quote-SonicShellArgument $WatcherPath
$stdoutPath = '/data/configdb_watch.out'
$stderrPath = '/data/configdb_watch.err'
$pidPath = '/data/configdb_watch.pid'

Write-Host 'Preparing SONiC ConfigDB TACACS rows...'
$prepScript = @"
set -e
redis-cli -n 4 CONFIG SET notify-keyspace-events KEA >/dev/null
for key in `$(redis-cli -n 4 --scan --pattern 'TACPLUS_SERVER|*'); do
  redis-cli -n 4 DEL "`$key" >/dev/null
done
redis-cli -n 4 DEL 'TACPLUS|global' >/dev/null
sudo config tacacs add -a pap -o 49 -t 1 $PrimaryServer
rm -f $stdoutPath $stderrPath $pidPath
"@
Invoke-Guest -Command $prepScript -ScriptText | Out-Null

Write-Host 'Starting configdb_watch in the guest...'
Invoke-Guest "nohup $quotedWatcherPath --max-events 3 --debounce-ms $DebounceMs > $stdoutPath 2> $stderrPath < /dev/null & echo `$! > $pidPath" | Out-Null
Wait-ForGuestOutputText -Path $stdoutPath -Text 'watching for TACPLUS keyspace notifications' | Out-Null

Write-Host 'Applying TACACS add/delete sequence...'
Invoke-Guest "sudo config tacacs add -a pap -o 49 -t 1 $SecondaryServer" | Out-Null
Start-Sleep -Milliseconds ($DebounceMs + 500)
Invoke-Guest "sudo config tacacs delete $SecondaryServer" | Out-Null
Start-Sleep -Milliseconds ($DebounceMs + 500)
Invoke-Guest "sudo config tacacs delete $PrimaryServer" | Out-Null

Wait-ForGuestPidExit -PidFile $pidPath
$stdout = Invoke-Guest "cat $stdoutPath"
$stderr = Invoke-Guest "cat $stderrPath 2>/dev/null || true"

Assert-Contains $stdout 'initial_server_count: 1'
Assert-Contains $stdout "added_servers: [`"sonic-server-$SecondaryServer`"]"
Assert-Contains $stdout "removed_servers: [`"sonic-server-$SecondaryServer`"]"
Assert-Contains $stdout "removed_servers: [`"sonic-server-$PrimaryServer`"]"
Assert-Contains $stdout 'current_server_count: 0'

Write-Host 'Verifying cold start with zero TACACS servers...'
$coldStart = Invoke-Guest "$quotedWatcherPath --max-events 0"
Assert-Contains $coldStart 'initial_server_count: 0'

Write-Host ''
Write-Host 'configdb_watch stdout:' -ForegroundColor Cyan
Write-Host $stdout
if (-not [string]::IsNullOrWhiteSpace($stderr)) {
    Write-Host 'configdb_watch stderr:' -ForegroundColor Cyan
    Write-Host $stderr
}
Write-Host 'SONiC VM configdb_watch scenario passed.' -ForegroundColor Green