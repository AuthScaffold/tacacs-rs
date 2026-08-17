<#
.SYNOPSIS
    Builds a Rust binary for Linux under WSL and copies it to the SONiC VM.
.DESCRIPTION
    SONiC requires a Linux ELF artifact. This script uses WSL to build a Cargo
    binary from the Windows checkout. Then it copies the Linux binary to /data.
    The copied binary has no file extension and is executable.
.EXAMPLE
    .\lde\sonic-vm\Publish-SonicBinary.ps1 -Package tacon
.EXAMPLE
    .\lde\sonic-vm\Publish-SonicBinary.ps1 -Package tacacsrs-agentd -RemotePath /data/tacacsrs-agentd
.EXAMPLE
    .\lde\sonic-vm\Publish-SonicBinary.ps1 -Package package-name -Bin different-binary-name
#>
[CmdletBinding()]
param(
    [string]$Package = 'tacon',
    [string]$Bin,
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
if ([string]::IsNullOrWhiteSpace($Bin)) { $Bin = $Package }
if ($Bin -notmatch '^[A-Za-z0-9_-]+$') { throw "Invalid binary name: $Bin" }

$repoRoot = (Get-SonicRepoRoot).Path
$repoWslPath = ConvertTo-SonicWslPath -Path $repoRoot

if (-not $RemotePath) {
    $RemotePath = "/data/$Bin"
}

if (-not $NoBuild) {
    Test-SonicRequiredCommand wsl
    $profileArg = if ($Profile -eq 'release') { ' --release' } else { '' }
    $buildCommand = 'source "$HOME/.cargo/env" 2>/dev/null || true; cargo build -p ' + $Package + ' --bin ' + $Bin + $profileArg
    Write-Host "Build the $Bin binary from package $Package under WSL at $repoWslPath."
    & wsl --cd $repoWslPath -- bash -lc $buildCommand
    if ($LASTEXITCODE -ne 0) { throw "The WSL cargo build returned exit code $LASTEXITCODE." }
}

$profileDir = if ($Profile -eq 'release') { 'release' } else { 'debug' }
$artifact = Join-Path $repoRoot "target\$profileDir\$Bin"
if (-not (Test-Path $artifact)) {
    throw "Built Linux binary was not found at $artifact"
}

& $PSScriptRoot\Copy-ToSonic.ps1 `
    -LocalPath $artifact `
    -RemotePath $RemotePath `
    -HostName $HostName `
    -Port $Port `
    -User $User `
    -Executable

Write-Host "Published $Bin to ${User}@${HostName}:$RemotePath"