<#
.SYNOPSIS
    Copies a local file or directory to the SONiC QEMU VM.
.DESCRIPTION
    Runs scp with the standard VM SSH options from this repository.
    The local path is first. The remote path is second.
.EXAMPLE
    .\lde\sonic-vm\Copy-ToSonic.ps1 -LocalPath target\debug\examples\configdb_watch -RemotePath /data/configdb_watch -Executable
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$LocalPath,

    [string]$RemotePath = '/data/',
    [string]$HostName = '127.0.0.1',
    [int]$Port = 2222,
    [string]$User = 'admin',
    [switch]$Recurse,
    [switch]$Executable
)

$ErrorActionPreference = 'Stop'
. $PSScriptRoot\SonicVm.Common.ps1

Test-SonicRequiredCommand ssh
Test-SonicRequiredCommand scp

$resolvedLocalPath = (Resolve-Path $LocalPath).Path
$localItem = Get-Item $resolvedLocalPath
$target = Get-SonicVmTarget -User $User -HostName $HostName
$sshArgs = Get-SonicSshArguments -Port $Port
$scpArgs = Get-SonicScpArguments -Port $Port

if ($Recurse -or $localItem.PSIsContainer) {
    $scpArgs = @('-r') + $scpArgs
}

$remoteDirectory = Get-SonicRemoteDirectory -RemotePath $RemotePath
if (-not [string]::IsNullOrWhiteSpace($remoteDirectory) -and $remoteDirectory -ne '.') {
    $quotedRemoteDirectory = Quote-SonicShellArgument $remoteDirectory
    & ssh @sshArgs $target "mkdir -p $quotedRemoteDirectory"
    if ($LASTEXITCODE -ne 0) { throw "The remote mkdir command returned exit code $LASTEXITCODE." }
}

& scp @scpArgs $resolvedLocalPath "${target}:$RemotePath"
if ($LASTEXITCODE -ne 0) { throw "scp to the SONiC VM returned exit code $LASTEXITCODE." }

if ($Executable) {
    $remoteDestination = Get-SonicRemoteDestinationPath -RemotePath $RemotePath -LocalPath $resolvedLocalPath
    $quotedRemoteDestination = Quote-SonicShellArgument $remoteDestination
    & ssh @sshArgs $target "chmod +x $quotedRemoteDestination"
    if ($LASTEXITCODE -ne 0) { throw "The remote chmod command returned exit code $LASTEXITCODE." }
}

Write-Host "Copied $resolvedLocalPath to ${target}:$RemotePath"