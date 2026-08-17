[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir '..')

Push-Location $repoRoot

try {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw 'cargo was not found in PATH. Install Rust via rustup before running this script.'
    }

    if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
        throw 'rustup was not found in PATH. This repository requires nightly rustfmt from rustup.'
    }

    $installedToolchains = rustup toolchain list
    if (-not ($installedToolchains | Select-String -Pattern '^nightly(-|\s|$)')) {
        Write-Host 'Install the nightly toolchain.'
        rustup toolchain install nightly
    }

    $nightlyComponents = rustup component list --toolchain nightly
    if (-not ($nightlyComponents | Select-String -Pattern '^rustfmt-.*\(installed\)$')) {
        Write-Host 'Install rustfmt for the nightly toolchain.'
        rustup component add rustfmt --toolchain nightly
    }

    Write-Host 'Run rustfmt across the workspace.'
    cargo +nightly fmt --all
}
finally {
    Pop-Location
}