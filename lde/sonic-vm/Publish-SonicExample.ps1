<#
.SYNOPSIS
    Builds a Rust example for Linux under WSL and copies it to the SONiC VM.
.DESCRIPTION
    SONiC requires a Linux ELF artifact. This script uses WSL to build from the
    Windows checkout. Then it copies the Linux example binary to /data.
    The copied binary has no file extension and is executable.
.EXAMPLE
    .\lde\sonic-vm\Publish-SonicExample.ps1 -Package tacacsrs-sonic -Example configdb_watch
#>
[CmdletBinding()]
param(
    [string]$Package = 'tacacsrs-sonic',
    [string]$Example = 'configdb_watch',
    [ValidateSet('debug', 'release')]
    [string]$Profile = 'debug',
    [string]$RemotePath,
    [string]$HostName = '127.0.0.1',
    [int]$Port = 2222,
    [string]$User = 'admin',
    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'
. $PSScriptRoot\SonicVm.Common.ps1

if ($Package -notmatch '^[A-Za-z0-9_-]+$') { throw "Invalid package name: $Package" }
if ($Example -notmatch '^[A-Za-z0-9_-]+$') { throw "Invalid example name: $Example" }

$repoRoot = (Get-SonicRepoRoot).Path
$repoWslPath = ConvertTo-SonicWslPath -Path $repoRoot

if (-not $RemotePath) {
    $RemotePath = "/data/$Example"
}

if (-not $NoBuild) {
    Test-SonicRequiredCommand wsl
    $profileArg = if ($Profile -eq 'release') { ' --release' } else { '' }
    $buildCommand = 'source "$HOME/.cargo/env" 2>/dev/null || true; cargo build -p ' + $Package + ' --example ' + $Example + $profileArg
    Write-Host "Build example $Example from package $Package under WSL at $repoWslPath."
    & wsl --cd $repoWslPath -- bash -lc $buildCommand
    if ($LASTEXITCODE -ne 0) { throw "The WSL cargo build returned exit code $LASTEXITCODE." }
}

$profileDir = if ($Profile -eq 'release') { 'release' } else { 'debug' }
$artifact = Join-Path $repoRoot "target\$profileDir\examples\$Example"
if (-not (Test-Path $artifact)) {
    throw "Built Linux example was not found at $artifact"
}

& $PSScriptRoot\Copy-ToSonic.ps1 `
    -LocalPath $artifact `
    -RemotePath $RemotePath `
    -HostName $HostName `
    -Port $Port `
    -User $User `
    -Executable

Write-Host "Published $Example to ${User}@${HostName}:$RemotePath"