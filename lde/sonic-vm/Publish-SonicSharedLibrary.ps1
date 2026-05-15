<#
.SYNOPSIS
    Build a Rust shared library for Linux under WSL and copy it to the SONiC VM.
.DESCRIPTION
    SONiC needs a Linux ELF artifact. This script builds a Cargo library target
    through WSL from the Windows checkout path, then copies the resulting .so to
    the VM and marks it executable.
.EXAMPLE
    .\lde\sonic-vm\Publish-SonicSharedLibrary.ps1 -Package tacacsrs-bash-plugin
.EXAMPLE
    .\lde\sonic-vm\Publish-SonicSharedLibrary.ps1 -Package tacacsrs-bash-plugin -RemotePath /data/libtacacsrs_bash_plugin.so
.EXAMPLE
    .\lde\sonic-vm\Publish-SonicSharedLibrary.ps1 -Package tacacsrs-bash-plugin -LibName tacacsrs_bash_plugin -Profile release
#>
[CmdletBinding()]
param(
    [string]$Package = 'tacacsrs-bash-plugin',
    [string]$LibName,
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
if ([string]::IsNullOrWhiteSpace($LibName)) { $LibName = $Package.Replace('-', '_') }
if ($LibName -notmatch '^[A-Za-z0-9_]+$') { throw "Invalid library target name: $LibName" }

$repoRoot = (Get-SonicRepoRoot).Path
$repoWslPath = ConvertTo-SonicWslPath -Path $repoRoot

$artifactFileName = "lib$LibName.so"
if (-not $RemotePath) {
    $RemotePath = "/data/$artifactFileName"
}

if (-not $NoBuild) {
    Test-SonicRequiredCommand wsl
    $profileArg = if ($Profile -eq 'release') { ' --release' } else { '' }
    $buildCommand = 'source "$HOME/.cargo/env" 2>/dev/null || true; cargo build -p ' + $Package + $profileArg
    Write-Host "Building $Package shared library $artifactFileName under WSL at $repoWslPath..."
    & wsl --cd $repoWslPath -- bash -lc $buildCommand
    if ($LASTEXITCODE -ne 0) { throw "WSL cargo build failed with exit code $LASTEXITCODE." }
}

$profileDir = if ($Profile -eq 'release') { 'release' } else { 'debug' }
$artifact = Join-Path $repoRoot "target\$profileDir\$artifactFileName"
if (-not (Test-Path $artifact)) {
    throw "Built Linux shared library was not found at $artifact"
}

& $PSScriptRoot\Copy-ToSonic.ps1 `
    -LocalPath $artifact `
    -RemotePath $RemotePath `
    -HostName $HostName `
    -Port $Port `
    -User $User `
    -Executable

Write-Host "Published $artifactFileName to ${User}@${HostName}:$RemotePath"
