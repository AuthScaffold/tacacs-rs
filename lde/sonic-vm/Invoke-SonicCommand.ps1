<#
.SYNOPSIS
    Run a command or script in the SONiC QEMU VM over SSH.
.DESCRIPTION
    Uses key-based SSH to admin@127.0.0.1:2222 by default. This wrapper keeps
    the SSH options consistent for Copilot and local smoke testing.
.EXAMPLE
    .\lde\sonic-vm\Invoke-SonicCommand.ps1 "redis-cli -n 4 --scan --pattern 'TACPLUS*' | sort"
.EXAMPLE
    .\lde\sonic-vm\Invoke-SonicCommand.ps1 -ScriptText "set -e`nhostname"
.EXAMPLE
    .\lde\sonic-vm\Invoke-SonicCommand.ps1 -Interactive
#>
[CmdletBinding(DefaultParameterSetName = 'Command')]
param(
    [Parameter(ParameterSetName = 'Command', Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Command,

    [Parameter(ParameterSetName = 'Script', Mandatory)]
    [string]$ScriptPath,

    [Parameter(ParameterSetName = 'ScriptText', Mandatory)]
    [string]$ScriptText,

    [string]$HostName = '127.0.0.1',
    [int]$Port = 2222,
    [string]$User = 'admin',

    [Parameter(ParameterSetName = 'Interactive')]
    [switch]$Interactive,

    [switch]$AllowFailure
)

$ErrorActionPreference = 'Stop'
. $PSScriptRoot\SonicVm.Common.ps1

Test-SonicRequiredCommand ssh
$sshArgs = Get-SonicSshArguments -Port $Port
$target = Get-SonicVmTarget -User $User -HostName $HostName

function Invoke-RemoteBashScript {
    param([Parameter(Mandatory)][string]$Text)

    $normalizedText = $Text -replace "`r`n", "`n"
    $scriptBytes = [Text.Encoding]::UTF8.GetBytes($normalizedText)
    $scriptBase64 = [Convert]::ToBase64String($scriptBytes)
    $quotedBase64 = Quote-SonicShellArgument $scriptBase64
    $remoteCommand = 'tmp=$(mktemp); printf %s ' + $quotedBase64 + ' | base64 -d > "$tmp"; bash "$tmp"; status=$?; rm -f "$tmp"; exit $status'

    & ssh @sshArgs $target $remoteCommand
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and -not $AllowFailure) { throw "remote script failed with exit code $exitCode." }
}

if ($Interactive) {
    & ssh @sshArgs $target
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and -not $AllowFailure) { throw "ssh failed with exit code $exitCode." }
    return
}

if ($PSCmdlet.ParameterSetName -eq 'Script') {
    $resolvedScript = (Resolve-Path $ScriptPath).Path
    Invoke-RemoteBashScript -Text (Get-Content -Path $resolvedScript -Raw)
    return
}

if ($PSCmdlet.ParameterSetName -eq 'ScriptText') {
    Invoke-RemoteBashScript -Text $ScriptText
    return
}

$remoteCommand = ($Command -join ' ').Trim()
if ([string]::IsNullOrWhiteSpace($remoteCommand)) {
    throw 'Provide a remote command, -ScriptPath, or -Interactive.'
}

& ssh @sshArgs $target $remoteCommand
$exitCode = $LASTEXITCODE
if ($exitCode -ne 0 -and -not $AllowFailure) { throw "remote command failed with exit code $exitCode." }