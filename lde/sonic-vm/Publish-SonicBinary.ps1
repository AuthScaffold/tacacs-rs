<#
.SYNOPSIS
    Build a Rust binary for Linux under WSL and copy it to the SONiC VM.
.DESCRIPTION
    SONiC needs a Linux ELF artifact. This script builds a standard Cargo
    binary through WSL from the Windows checkout path, then copies the
    no-extension Linux binary to /data in the VM and marks it executable.
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
    Write-Host "Building $Package binary $Bin under WSL at $repoWslPath..."
    & wsl --cd $repoWslPath -- bash -lc $buildCommand
    if ($LASTEXITCODE -ne 0) { throw "WSL cargo build failed with exit code $LASTEXITCODE." }
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