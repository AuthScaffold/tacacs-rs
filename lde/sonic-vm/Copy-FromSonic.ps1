<#
.SYNOPSIS
    Copies a file or directory from the SONiC QEMU VM to the local machine.
.EXAMPLE
    .\lde\sonic-vm\Copy-FromSonic.ps1 -RemotePath /data/configdb_watch.out -LocalPath target\tmp\configdb_watch.out
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RemotePath,

    [Parameter(Mandatory)]
    [string]$LocalPath,

    [string]$HostName = '127.0.0.1',
    [int]$Port = 2222,
    [string]$User = 'admin',
    [switch]$Recurse
)

$ErrorActionPreference = 'Stop'
. $PSScriptRoot\SonicVm.Common.ps1

Test-SonicRequiredCommand scp

$target = Get-SonicVmTarget -User $User -HostName $HostName
$scpArgs = Get-SonicScpArguments -Port $Port
if ($Recurse) {
    $scpArgs = @('-r') + $scpArgs
}

$localParent = Split-Path $LocalPath -Parent
if (-not [string]::IsNullOrWhiteSpace($localParent)) {
    New-Item -ItemType Directory -Force -Path $localParent | Out-Null
}

& scp @scpArgs "${target}:$RemotePath" $LocalPath
if ($LASTEXITCODE -ne 0) { throw "scp from the SONiC VM returned exit code $LASTEXITCODE." }

Write-Host "Copied ${target}:$RemotePath to $LocalPath"