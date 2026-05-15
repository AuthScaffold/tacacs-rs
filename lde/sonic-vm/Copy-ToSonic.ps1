<#
.SYNOPSIS
    Copy a local file or directory to the SONiC QEMU VM.
.DESCRIPTION
    Wraps scp with the repository's standard VM SSH options. The local path is
    always first and the remote path is always second to avoid the easy-to-make
    inverted scp command.
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
    if ($LASTEXITCODE -ne 0) { throw "remote mkdir failed with exit code $LASTEXITCODE." }
}

& scp @scpArgs $resolvedLocalPath "${target}:$RemotePath"
if ($LASTEXITCODE -ne 0) { throw "scp to SONiC VM failed with exit code $LASTEXITCODE." }

if ($Executable) {
    $remoteDestination = Get-SonicRemoteDestinationPath -RemotePath $RemotePath -LocalPath $resolvedLocalPath
    $quotedRemoteDestination = Quote-SonicShellArgument $remoteDestination
    & ssh @sshArgs $target "chmod +x $quotedRemoteDestination"
    if ($LASTEXITCODE -ne 0) { throw "remote chmod failed with exit code $LASTEXITCODE." }
}

Write-Host "Copied $resolvedLocalPath to ${target}:$RemotePath"