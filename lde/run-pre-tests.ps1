<#
.SYNOPSIS
    Runs the reusable CI pipeline pre-tests stage locally.

.DESCRIPTION
    Mirrors .github/workflows/reusable-pipeline.yml job `pre-tests` for the
    selected matrix entry. The script installs Rust toolchains, components, and
    targets through rustup, checks formatting, runs cargo-udeps, clippy, clippy
    nursery advisory lints, documentation, and the Linux GNU metadata checks.

    By default the script runs the matrix entry for the current OS. On Windows
    this is the Windows MSVC entry. Run the Linux entries from Linux or WSL with
    PowerShell installed.

.PARAMETER Matrix
    Matrix entry to run: Local, WindowsMsvc, LinuxGnu, LinuxMusl, or All.

.PARAMETER Task
    Pre-test task or tasks to run. Defaults to All. Explicit task selection
    overrides the Include* toggles for that task.

.PARAMETER FixFormatting
    Run cargo +nightly fmt --all before the CI formatting check.

.PARAMETER ApplyFixes
    Automatically run available fixes for each selected test before running the
    corresponding check. The shorter -Fix alias is also supported.

.PARAMETER IncludeFmt
    Include the rustfmt check. Matches the workflow_call include-fmt input.

.PARAMETER IncludeClippyNursery
    Include advisory clippy nursery lints.

.PARAMETER IncludeOutdated
    Include cargo outdated in metadata checks.

.PARAMETER IncludeProtoCompat
    Include advisory buf protobuf compatibility checks in metadata checks.

.PARAMETER SkipAuditIfNoDepChanges
    Skip cargo audit when Cargo.toml and Cargo.lock did not change relative to
    ChangeBase or the working tree.

.PARAMETER ChangeBase
    Optional git ref used when SkipAuditIfNoDepChanges is set.

.PARAMETER ProtoCompatRef
    Git ref used for buf breaking --against. Defaults to main, matching CI.

.PARAMETER InstallMissingCargoTools
    Install missing cargo-udeps, cargo-audit, and cargo-outdated tools with
    cargo install --locked. Defaults to true.

.PARAMETER SkipSystemDependencyChecks
    Skip local checks for OpenSSL and Linux native packages.

.EXAMPLE
    .\lde\run-pre-tests.ps1

.EXAMPLE
    .\lde\run-pre-tests.ps1 -FixFormatting

.EXAMPLE
    .\lde\run-pre-tests.ps1 -Task Clippy -ApplyFixes

.EXAMPLE
    .\lde\run-pre-tests.ps1 -Matrix LinuxGnu -SkipAuditIfNoDepChanges

.EXAMPLE
    .\lde\run-pre-tests.ps1 -Task Clippy

.EXAMPLE
    .\lde\run-pre-tests.ps1 -Task Udeps,Docs
#>
[CmdletBinding()]
param(
    [ValidateSet('Local', 'WindowsMsvc', 'LinuxGnu', 'LinuxMusl', 'All')]
    [string]$Matrix = 'Local',

    [ValidateSet('All', 'FixFormatting', 'CheckFormatting', 'Udeps', 'Clippy', 'ClippyNursery', 'Docs', 'Audit', 'Outdated', 'ProtoCompat', 'Metadata')]
    [string[]]$Task = @('All'),

    [switch]$FixFormatting,

    [Alias('Fix')]
    [switch]$ApplyFixes,

    [bool]$IncludeFmt = $true,

    [bool]$IncludeClippyNursery = $true,

    [bool]$IncludeOutdated = $true,

    [bool]$IncludeProtoCompat = $true,

    [switch]$SkipAuditIfNoDepChanges,

    [string]$ChangeBase,

    [string]$ProtoCompatRef = 'main',

    [bool]$InstallMissingCargoTools = $true,

    [switch]$SkipSystemDependencyChecks
)

$ErrorActionPreference = 'Stop'

function Get-RepoRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

function Get-HostKind {
    if ($env:OS -eq 'Windows_NT') {
        return 'Windows'
    }

    if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Unix) {
        return 'Linux'
    }

    return 'Other'
}

function Test-CommandExists {
    param([Parameter(Mandatory = $true)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Assert-TaskSelection {
    if ($Task.Count -gt 1 -and $Task -contains 'All') {
        throw 'Use -Task All by itself, or pass one or more specific tasks without All.'
    }
}

function Test-ExplicitTaskSelection {
    return -not ($Task.Count -eq 1 -and $Task[0] -eq 'All')
}

function Test-TaskSelected {
    param([Parameter(Mandatory = $true)][string]$Name)

    if ($Task -contains 'All') {
        return $true
    }

    if ($Task -contains $Name) {
        return $true
    }

    if ($Task -contains 'Metadata' -and $Name -in @('Audit', 'Outdated', 'ProtoCompat')) {
        return $true
    }

    return $false
}

function Test-OptionalTaskSelected {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Include
    )

    if (-not (Test-TaskSelected -Name $Name)) {
        return $false
    }

    if (Test-ExplicitTaskSelection) {
        return $true
    }

    return $Include
}

function Test-MetadataTaskExplicitlySelected {
    if (-not (Test-ExplicitTaskSelection)) {
        return $false
    }

    foreach ($metadataTask in @('Audit', 'Outdated', 'ProtoCompat', 'Metadata')) {
        if ($Task -contains $metadataTask) {
            return $true
        }
    }

    return $false
}

function Test-AutoFixSelected {
    param([Parameter(Mandatory = $true)][string]$Name)

    if ($ApplyFixes -and (Test-TaskSelected -Name $Name)) {
        return $true
    }

    return $false
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [hashtable]$Environment = @{},
        [switch]$Advisory
    )

    $display = $FilePath
    if ($Arguments.Count -gt 0) {
        $display = "$display $($Arguments -join ' ')"
    }

    Write-Host "> $display" -ForegroundColor DarkGray

    $previousValues = @{}
    foreach ($key in $Environment.Keys) {
        $previousValues[$key] = [System.Environment]::GetEnvironmentVariable($key, 'Process')
        [System.Environment]::SetEnvironmentVariable($key, [string]$Environment[$key], 'Process')
    }

    try {
        & $FilePath @Arguments
        $exitCode = $LASTEXITCODE
    }
    finally {
        foreach ($key in $Environment.Keys) {
            [System.Environment]::SetEnvironmentVariable($key, $previousValues[$key], 'Process')
        }
    }

    if ($exitCode -ne 0) {
        if ($Advisory) {
            Write-Warning "Advisory command failed with exit code ${exitCode}: $display"
            return
        }

        throw "Command failed with exit code ${exitCode}: $display"
    }
}

function Invoke-ClippyFix {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [string[]]$LintArgs = @()
    )

    $clippyFixCommand = @(
        '+stable',
        'clippy',
        '--fix',
        '--workspace',
        '--all-targets',
        '--allow-dirty',
        '--target',
        $Config.Target
    ) + $Config.FeatureArgs
    if ($LintArgs.Count -gt 0) {
        $clippyFixCommand += @('--') + $LintArgs
    }

    Invoke-CheckedCommand -FilePath 'cargo' -Arguments $clippyFixCommand
}

function Assert-CommandExists {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$InstallHint
    )

    if (-not (Test-CommandExists $Name)) {
        if ($InstallHint) {
            throw "$Name was not found in PATH. $InstallHint"
        }

        throw "$Name was not found in PATH."
    }
}

function Get-MatrixConfigs {
    $configs = @(
        [PSCustomObject]@{
            Name = 'Linux GNU'
            Id = 'LinuxGnu'
            HostKind = 'Linux'
            Target = 'x86_64-unknown-linux-gnu'
            FeatureArgs = @('--all-features')
            InstallMuslTools = $false
            InstallLibseccompDev = $true
            InstallOpenSsl = $true
            MetadataChecks = $true
        },
        [PSCustomObject]@{
            Name = 'Linux MUSL'
            Id = 'LinuxMusl'
            HostKind = 'Linux'
            Target = 'x86_64-unknown-linux-musl'
            FeatureArgs = @()
            InstallMuslTools = $true
            InstallLibseccompDev = $true
            InstallOpenSsl = $true
            MetadataChecks = $false
        },
        [PSCustomObject]@{
            Name = 'Windows MSVC'
            Id = 'WindowsMsvc'
            HostKind = 'Windows'
            Target = 'x86_64-pc-windows-msvc'
            FeatureArgs = @('--all-features')
            InstallMuslTools = $false
            InstallLibseccompDev = $false
            InstallOpenSsl = $true
            MetadataChecks = $false
        }
    )

    return $configs
}

function Select-MatrixConfigs {
    param(
        [Parameter(Mandatory = $true)][string]$RequestedMatrix,
        [Parameter(Mandatory = $true)][string]$HostKind
    )

    $configs = @(Get-MatrixConfigs)

    if ($RequestedMatrix -eq 'All') {
        return $configs
    }

    if ($RequestedMatrix -eq 'Local') {
        $local = @($configs | Where-Object { $_.HostKind -eq $HostKind })
        if ($local.Count -eq 0) {
            throw "No pre-tests matrix entry matches this host kind: $HostKind"
        }
        return $local
    }

    return @($configs | Where-Object { $_.Id -eq $RequestedMatrix })
}

function Assert-ConfigCanRunHere {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][string]$HostKind
    )

    if ($Config.HostKind -ne $HostKind) {
        throw "The '$($Config.Name)' matrix entry requires $($Config.HostKind). Current host is $HostKind. Run that entry under Linux/WSL or choose -Matrix Local."
    }
}

function Install-RustToolchain {
    param(
        [Parameter(Mandatory = $true)][string]$Toolchain,
        [string[]]$Components = @(),
        [string[]]$Targets = @()
    )

    $rustupCommand = @('toolchain', 'install', $Toolchain, '--profile', 'minimal')

    foreach ($component in $Components) {
        if ($component) {
            $rustupCommand += @('--component', $component)
        }
    }

    foreach ($target in $Targets) {
        if ($target) {
            $rustupCommand += @('--target', $target)
        }
    }

    Invoke-CheckedCommand -FilePath 'rustup' -Arguments $rustupCommand
}

function Assert-CargoTool {
    param(
        [Parameter(Mandatory = $true)][string]$CargoSubcommand,
        [Parameter(Mandatory = $true)][string]$CrateName,
        [string]$Toolchain
    )

    $versionCommand = @()
    if ($Toolchain) {
        $versionCommand += "+$Toolchain"
    }
    $versionCommand += @($CargoSubcommand, '--version')

    & cargo @versionCommand *> $null
    if ($LASTEXITCODE -eq 0) {
        return
    }

    if (-not $InstallMissingCargoTools) {
        throw "cargo $CargoSubcommand is not installed. Install it with: cargo install $CrateName --locked"
    }

    Write-Host "Installing $CrateName..." -ForegroundColor Yellow
    Invoke-CheckedCommand -FilePath 'cargo' -Arguments @('install', $CrateName, '--locked')
}

function Assert-LinuxPackages {
    param([Parameter(Mandatory = $true)]$Config)

    if ($SkipSystemDependencyChecks) {
        return
    }

    $packages = @()
    if ($Config.InstallMuslTools) {
        $packages += @('gcc', 'gperf', 'linux-libc-dev', 'make', 'musl-tools')
    }
    if ($Config.InstallLibseccompDev) {
        $packages += 'libseccomp-dev'
    }
    if ($Config.InstallOpenSsl) {
        $packages += @('pkg-config', 'libssl-dev')
    }

    if ($packages.Count -eq 0 -or -not (Test-CommandExists 'dpkg')) {
        return
    }

    $missing = @()
    foreach ($package in $packages | Select-Object -Unique) {
        & dpkg -s $package *> $null
        if ($LASTEXITCODE -ne 0) {
            $missing += $package
        }
    }

    if ($missing.Count -gt 0) {
        $install = "sudo apt-get update && sudo apt-get install -y $($missing -join ' ')"
        throw "Missing Linux build dependencies: $($missing -join ', '). Run: $install"
    }
}

function Set-WindowsOpenSslEnvironment {
    if ($SkipSystemDependencyChecks) {
        return
    }

    if ($env:OPENSSL_DIR -and (Test-Path $env:OPENSSL_DIR)) {
        return
    }

    $vcpkgOpenSsl = 'C:\vcpkg\installed\x64-windows'
    if (Test-Path $vcpkgOpenSsl) {
        $env:OPENSSL_DIR = $vcpkgOpenSsl
        $env:OPENSSL_LIB_DIR = Join-Path $vcpkgOpenSsl 'lib'
        Write-Host "OpenSSL configured from $vcpkgOpenSsl" -ForegroundColor DarkGray
        return
    }

    if (Test-CommandExists 'vcpkg') {
        Write-Host 'Installing OpenSSL through vcpkg...' -ForegroundColor Yellow
        Invoke-CheckedCommand -FilePath 'vcpkg' -Arguments @('install', 'openssl:x64-windows')
        Invoke-CheckedCommand -FilePath 'vcpkg' -Arguments @('integrate', 'install')
        if (Test-Path $vcpkgOpenSsl) {
            $env:OPENSSL_DIR = $vcpkgOpenSsl
            $env:OPENSSL_LIB_DIR = Join-Path $vcpkgOpenSsl 'lib'
            return
        }
    }

    throw 'OpenSSL for x64-windows was not found. Install vcpkg OpenSSL or set OPENSSL_DIR before running all-features checks.'
}

function Get-ChangedFiles {
    param([string]$BaseRef)

    $files = @()

    if ($BaseRef) {
        & git rev-parse --verify $BaseRef *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "ChangeBase '$BaseRef' was not found. Fetch it or omit -ChangeBase."
        }

        $files += @(git diff --name-only "$BaseRef...HEAD")
    }
    else {
        $files += @(git diff --name-only)
        $files += @(git diff --name-only --cached)
    }

    return @($files | Where-Object { $_ } | Select-Object -Unique)
}

function Test-DependencyFilesChanged {
    param([string]$BaseRef)

    $files = @(Get-ChangedFiles -BaseRef $BaseRef)
    foreach ($file in $files) {
        $normalized = $file -replace '\\', '/'
        if ($normalized -eq 'Cargo.lock' -or $normalized.EndsWith('/Cargo.toml') -or $normalized -eq 'Cargo.toml') {
            return $true
        }
    }

    return $false
}

function Confirm-ProtoCompatRef {
    param([Parameter(Mandatory = $true)][string]$RefName)

    & git rev-parse --verify $RefName *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Ref '$RefName' already exists locally" -ForegroundColor DarkGray
        return
    }

    $originRef = "origin/$RefName"
    & git rev-parse --verify $originRef *> $null
    if ($LASTEXITCODE -eq 0) {
        Invoke-CheckedCommand -FilePath 'git' -Arguments @('branch', $RefName, $originRef)
        Write-Host "Created local branch '$RefName' from '$originRef'" -ForegroundColor DarkGray
        return
    }

    throw "Ref '$RefName' not found locally or on origin."
}

function Invoke-PreTestsForConfig {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][string]$HostKind
    )

    Assert-ConfigCanRunHere -Config $Config -HostKind $HostKind

    if ((Test-MetadataTaskExplicitlySelected) -and -not $Config.MetadataChecks) {
        throw "Metadata tasks only run in the Linux GNU pre-tests matrix entry. Run with -Matrix LinuxGnu under Linux/WSL."
    }

    Write-Host "`n=== Pre-Tests ($($Config.Name)) ===" -ForegroundColor Cyan

    if ($HostKind -eq 'Linux') {
        Assert-LinuxPackages -Config $Config
    }
    elseif ($HostKind -eq 'Windows' -and $Config.InstallOpenSsl -and ($Config.FeatureArgs -contains '--all-features')) {
        Set-WindowsOpenSslEnvironment
    }

    $needsNightly = (Test-TaskSelected -Name 'FixFormatting') -or (Test-TaskSelected -Name 'CheckFormatting') -or (Test-TaskSelected -Name 'Udeps')
    $needsStable = (Test-TaskSelected -Name 'Clippy') -or (Test-TaskSelected -Name 'ClippyNursery') -or (Test-TaskSelected -Name 'Docs')

    if ($needsNightly) {
        Write-Host "`n--- Setup nightly Rust ---" -ForegroundColor Yellow
        Install-RustToolchain -Toolchain 'nightly' -Components @('rustfmt') -Targets @($Config.Target)
    }

    $formattingFixTaskSelected = Test-TaskSelected -Name 'FixFormatting'
    $formattingFixRequested = (Test-ExplicitTaskSelection) -or $FixFormatting
    $explicitFormattingFix = $formattingFixTaskSelected -and $formattingFixRequested
    $checkFormattingFix = $ApplyFixes -and (Test-OptionalTaskSelected -Name 'CheckFormatting' -Include $IncludeFmt)
    $runFormattingFix = $explicitFormattingFix -or $checkFormattingFix
    if ($runFormattingFix) {
        Write-Host "`n--- Fix formatting ---" -ForegroundColor Yellow
        Invoke-CheckedCommand -FilePath 'cargo' -Arguments @('+nightly', 'fmt', '--all')
    }

    if (Test-OptionalTaskSelected -Name 'CheckFormatting' -Include $IncludeFmt) {
        Write-Host "`n--- Check formatting ---" -ForegroundColor Yellow
        Invoke-CheckedCommand -FilePath 'cargo' -Arguments @('+nightly', 'fmt', '--all', '--', '--check')
    }

    if (Test-TaskSelected -Name 'Udeps') {
        Write-Host "`n--- Check unused dependencies ---" -ForegroundColor Yellow
        Assert-CargoTool -CargoSubcommand 'udeps' -CrateName 'cargo-udeps' -Toolchain 'nightly'
        $udepsCommand = @('+nightly', 'udeps', '--workspace', '--all-targets', '--target', $Config.Target) + $Config.FeatureArgs
        Invoke-CheckedCommand -FilePath 'cargo' -Arguments $udepsCommand
    }

    if ($needsStable) {
        Write-Host "`n--- Setup stable Rust ---" -ForegroundColor Yellow
        Install-RustToolchain -Toolchain 'stable' -Components @('clippy') -Targets @($Config.Target)
    }

    if (Test-TaskSelected -Name 'Clippy') {
        if (Test-AutoFixSelected -Name 'Clippy') {
            Write-Host "`n--- Fix Clippy suggestions ---" -ForegroundColor Yellow
            Invoke-ClippyFix -Config $Config
        }

        Write-Host "`n--- Run Clippy ---" -ForegroundColor Yellow
        $clippyCommand = @('+stable', 'clippy', '--workspace', '--all-targets', '--target', $Config.Target) + $Config.FeatureArgs + @('--', '-D', 'warnings')
        Invoke-CheckedCommand -FilePath 'cargo' -Arguments $clippyCommand
    }

    if (Test-OptionalTaskSelected -Name 'ClippyNursery' -Include $IncludeClippyNursery) {
        # Probably a bad idea since the Clippy Nursery is very opinionated about drop and const stuff that
        # sometimes doesn't matter....
        # if (Test-AutoFixSelected -Name 'ClippyNursery') {
        #     Write-Host "`n--- Fix Clippy nursery suggestions ---" -ForegroundColor Yellow
        #     Invoke-ClippyFix -Config $Config -LintArgs @('-W', 'clippy::nursery')
        # }

        Write-Host "`n--- Clippy nursery lints (advisory) ---" -ForegroundColor Yellow
        $nurseryCommand = @('+stable', 'clippy', '--workspace', '--all-targets', '--target', $Config.Target) + $Config.FeatureArgs + @('--', '-W', 'clippy::nursery')
        Invoke-CheckedCommand -FilePath 'cargo' -Arguments $nurseryCommand -Advisory
    }

    if (Test-TaskSelected -Name 'Docs') {
        Write-Host "`n--- Build documentation ---" -ForegroundColor Yellow
        $docCommand = @('+stable', 'doc', '--workspace', '--no-deps', '--document-private-items', '--target', $Config.Target) + $Config.FeatureArgs
        Invoke-CheckedCommand -FilePath 'cargo' -Arguments $docCommand -Environment @{ RUSTDOCFLAGS = '-D warnings' }
    }

    if ($Config.MetadataChecks) {
        if (Test-TaskSelected -Name 'Audit') {
            Write-Host "`n--- Security audit ---" -ForegroundColor Yellow
            $runAudit = $true
            if ($SkipAuditIfNoDepChanges) {
                $runAudit = Test-DependencyFilesChanged -BaseRef $ChangeBase
            }

            if ($runAudit) {
                Assert-CargoTool -CargoSubcommand 'audit' -CrateName 'cargo-audit'
                Invoke-CheckedCommand -FilePath 'cargo' -Arguments @('generate-lockfile')
                Invoke-CheckedCommand -FilePath 'cargo' -Arguments @('audit')
            }
            else {
                Write-Host 'Skipping audit - no dependency changes detected' -ForegroundColor DarkGray
            }
        }

        if (Test-OptionalTaskSelected -Name 'Outdated' -Include $IncludeOutdated) {
            Write-Host "`n--- Check outdated dependencies ---" -ForegroundColor Yellow
            Assert-CargoTool -CargoSubcommand 'outdated' -CrateName 'cargo-outdated'
            Invoke-CheckedCommand -FilePath 'cargo' -Arguments @('outdated', '--workspace', '--exit-code', '1')
        }

        if (Test-OptionalTaskSelected -Name 'ProtoCompat' -Include $IncludeProtoCompat) {
            Write-Host "`n--- Protobuf compatibility (advisory) ---" -ForegroundColor Yellow
            Assert-CommandExists -Name 'buf' -InstallHint 'Install buf from https://buf.build/docs/installation before running protobuf compatibility checks.'
            Confirm-ProtoCompatRef -RefName $ProtoCompatRef
            Invoke-CheckedCommand -FilePath 'buf' -Arguments @('breaking', '--against', ".git#branch=$ProtoCompatRef") -Advisory
        }
    }
}

$repoRoot = Get-RepoRoot
$hostKind = Get-HostKind

Push-Location $repoRoot

try {
    Assert-TaskSelection

    Assert-CommandExists -Name 'cargo' -InstallHint 'Install Rust via rustup before running this script.'
    Assert-CommandExists -Name 'rustup' -InstallHint 'Install Rust via rustup before running this script.'
    Assert-CommandExists -Name 'git' -InstallHint 'Install git before running this script.'

    $selectedConfigs = @(Select-MatrixConfigs -RequestedMatrix $Matrix -HostKind $hostKind)
    foreach ($config in $selectedConfigs) {
        Invoke-PreTestsForConfig -Config $config -HostKind $hostKind
    }

    Write-Host "`nPre-tests completed." -ForegroundColor Green
}
finally {
    Pop-Location
}