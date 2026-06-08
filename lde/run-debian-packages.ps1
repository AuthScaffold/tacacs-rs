<#
.SYNOPSIS
    Builds and verifies TACACS-rs Debian packages locally on Linux.

.DESCRIPTION
    Mirrors the Linux GNU packaging flow used by the shared CI pipeline for the
    official TACACS-rs Debian packages. The script builds the Linux artifacts,
    generates package-local changelog, man page, and SBOM assets, runs
    `cargo deb --no-build --dbgsym`, executes `lintian`, displays package
    metadata, and copies the resulting `.deb` and `.ddeb` files into
    `packaged/`.

    This script is intended to run from Linux or WSL with PowerShell installed.

.PARAMETER Package
    Package or packages to build: All, tacon, tacacsrs-agentd,
    tacacsrs-bash-plugin.

.PARAMETER Target
    Rust target triple to build. Defaults to x86_64-unknown-linux-gnu.

.PARAMETER InstallMissingCargoTools
    Install missing cargo-deb and cargo-cyclonedx tools with cargo install
    --locked. Defaults to true.

.PARAMETER SkipSystemDependencyChecks
    Skip local checks for Linux package dependencies.

.EXAMPLE
    ./lde/run-debian-packages.ps1

.EXAMPLE
    ./lde/run-debian-packages.ps1 -Package tacacsrs-agentd
#>
[CmdletBinding()]
param(
    [ValidateSet('All', 'tacon', 'tacacsrs-agentd', 'tacacsrs-bash-plugin')]
    [string[]]$Package = @('All'),

    [string]$Target = 'x86_64-unknown-linux-gnu',

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

function Initialize-RustEnvironment {
    if ((Get-HostKind) -ne 'Linux') {
        return
    }

    $cargoBin = Join-Path $HOME '.cargo/bin'
    if (-not (Test-Path $cargoBin -PathType Container)) {
        return
    }

    $pathEntries = $env:PATH -split [System.IO.Path]::PathSeparator
    if ($pathEntries -contains $cargoBin) {
        return
    }

    $env:PATH = "$cargoBin$([System.IO.Path]::PathSeparator)$env:PATH"
}

function Test-CommandExists {
    param([Parameter(Mandatory = $true)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Assert-PackageSelection {
    if ($Package.Count -gt 1 -and $Package -contains 'All') {
        throw 'Use -Package All by itself, or pass one or more specific package names without All.'
    }
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [switch]$Advisory
    )

    $display = $FilePath
    if ($Arguments.Count -gt 0) {
        $display = "$display $($Arguments -join ' ')"
    }

    Write-Host "> $display" -ForegroundColor DarkGray

    & $FilePath @Arguments
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        if ($Advisory) {
            Write-Warning "Advisory command failed with exit code ${exitCode}: $display"
            return
        }

        throw "Command failed with exit code ${exitCode}: $display"
    }
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

function Assert-CargoTool {
    param(
        [Parameter(Mandatory = $true)][string]$CargoSubcommand,
        [Parameter(Mandatory = $true)][string]$CrateName
    )

    & cargo $CargoSubcommand --version *> $null
    if ($LASTEXITCODE -eq 0) {
        return
    }

    if (-not $InstallMissingCargoTools) {
        throw "cargo $CargoSubcommand is not installed. Install it with: cargo install $CrateName --locked"
    }

    Write-Host "Installing $CrateName..." -ForegroundColor Yellow
    Invoke-CheckedCommand -FilePath 'cargo' -Arguments @('install', $CrateName, '--locked')
}

function Enable-GitWorktreeForWsl {
    & git rev-parse --is-inside-work-tree *> $null
    if ($LASTEXITCODE -eq 0) {
        return
    }

    if (-not (Test-Path .git -PathType Leaf)) {
        throw "git metadata is unavailable in $((Get-Location).Path)"
    }

    $gitdirLine = Get-Content .git | Where-Object { $_ -like 'gitdir: *' } | Select-Object -First 1
    if (-not $gitdirLine) {
        throw "Unable to parse gitdir from $((Get-Location).Path)/.git"
    }

    $gitdir = $gitdirLine.Substring('gitdir: '.Length).Replace('\', '/')
    if ($gitdir -match '^(?<drive>[A-Za-z]):/(?<rest>.+)$') {
        $drive = $Matches.drive.ToLowerInvariant()
        $rest = $Matches.rest
        $gitdir = "/mnt/$drive/$rest"
    }

    $env:GIT_DIR = $gitdir
    $env:GIT_WORK_TREE = (Get-Location).Path

    & git rev-parse --is-inside-work-tree *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to activate git worktree metadata from $gitdir"
    }
}

function Assert-LinuxPackages {
    if ($SkipSystemDependencyChecks) {
        return
    }

    $packages = @('build-essential', 'lintian', 'pkg-config', 'libssl-dev')
    $missing = @()
    foreach ($packageName in $packages) {
        & dpkg -s $packageName *> $null
        if ($LASTEXITCODE -ne 0) {
            $missing += $packageName
        }
    }

    if ($missing.Count -gt 0) {
        throw "Missing Linux build dependencies: $($missing -join ', '). Run: sudo apt-get update && sudo apt-get install -y $($missing -join ' ')"
    }
}

function Get-PackageConfigs {
    return @(
        [PSCustomObject]@{
            PackageName = 'tacon'
            PackageRoot = 'executables/tacon'
            AssetName = 'tacon-linux-gnu-x86_64'
            ArtifactName = 'tacon'
            ArtifactKind = 'bin'
            Features = @('psk')
            SbomDescribe = 'binaries'
            ManPageName = 'tacon'
        },
        [PSCustomObject]@{
            PackageName = 'tacacsrs-agentd'
            PackageRoot = 'executables/tacacsrs_agentd'
            AssetName = 'tacacsrs-agentd-linux-gnu-x86_64'
            ArtifactName = 'tacacsrs-agentd'
            ArtifactKind = 'bin'
            Features = @('psk')
            SbomDescribe = 'binaries'
            ManPageName = 'tacacsrs-agentd'
        },
        [PSCustomObject]@{
            PackageName = 'tacacsrs-bash-plugin'
            PackageRoot = 'libraries/tacacsrs_bash_plugin'
            AssetName = 'tacacsrs-bash-plugin-linux-gnu-x86_64'
            ArtifactName = 'tacacsrs_bash_plugin'
            ArtifactKind = 'cdylib'
            Features = @()
            SbomDescribe = 'all-cargo-targets'
            ManPageName = ''
        }
    )
}

function Select-PackageConfigs {
    $configs = @(Get-PackageConfigs)
    if ($Package.Count -eq 1 -and $Package[0] -eq 'All') {
        return $configs
    }

    return @($configs | Where-Object { $_.PackageName -in $Package })
}

function Get-ArtifactFileName {
    param([Parameter(Mandatory = $true)]$Config)

    if ($Config.ArtifactKind -eq 'cdylib') {
        return "lib$($Config.ArtifactName).so"
    }

    return $Config.ArtifactName
}

function Get-SbomOutputBaseName {
    param([Parameter(Mandatory = $true)]$Config)

    $assetSuffix = $Config.AssetName
    if ($assetSuffix.StartsWith("$($Config.PackageName)-")) {
        $assetSuffix = $assetSuffix.Substring($Config.PackageName.Length + 1)
    }

    return "sbom-$assetSuffix"
}

function Get-RepoUrl {
    $remoteUrl = @(& git config --get remote.origin.url)
    if ($LASTEXITCODE -ne 0 -or $remoteUrl.Count -eq 0) {
        return $null
    }

    $value = $remoteUrl[0]
    if ($value -match '^git@github\.com:(?<repo>.+?)(\.git)?$') {
        return "https://github.com/$($Matches.repo)"
    }

    if ($value -match '^https://github\.com/(?<repo>.+?)(\.git)?$') {
        return "https://github.com/$($Matches.repo)"
    }

    return $value -replace '\.git$',''
}

function Invoke-BuildArtifact {
    param([Parameter(Mandatory = $true)]$Config)

    $arguments = @('build', '--release', '--target', $Target, '--package', $Config.PackageName)
    if ($Config.ArtifactKind -eq 'bin') {
        $arguments += @('--bin', $Config.ArtifactName)
    }
    elseif ($Config.ArtifactKind -eq 'cdylib') {
        $arguments += '--lib'
    }
    else {
        throw "Unsupported artifact kind: $($Config.ArtifactKind)"
    }

    if ($Config.Features.Count -gt 0) {
        $arguments += @('--features', ($Config.Features -join ' '))
    }

    Invoke-CheckedCommand -FilePath 'cargo' -Arguments $arguments
}

function Invoke-GenerateSboms {
    param([Parameter(Mandatory = $true)]$Config)

    Get-ChildItem -Path $Config.PackageRoot -Filter '*.cdx.json' -File -ErrorAction SilentlyContinue | Remove-Item -Force
    Get-ChildItem -Path $Config.PackageRoot -Filter '*.cdx.xml' -File -ErrorAction SilentlyContinue | Remove-Item -Force

    foreach ($format in @('json', 'xml')) {
        $arguments = @(
            'cyclonedx',
            '--format',
            $format,
            '--manifest-path',
            "$($Config.PackageRoot)/Cargo.toml",
            '--describe',
            $Config.SbomDescribe,
            '--target',
            $Target,
            '--target-in-filename'
        )

        if ($Config.Features.Count -gt 0) {
            $arguments += @('--features', ($Config.Features -join ' '))
        }

        Invoke-CheckedCommand -FilePath 'cargo' -Arguments $arguments
    }

    $jsonSource = Get-ChildItem -Path $Config.PackageRoot -Filter '*.cdx.json' -File | Select-Object -First 1
    $xmlSource = Get-ChildItem -Path $Config.PackageRoot -Filter '*.cdx.xml' -File | Select-Object -First 1
    if (-not $jsonSource -or -not $xmlSource) {
        throw "Generated SBOM files were not found under $($Config.PackageRoot)"
    }

    $packageDir = Join-Path 'staging' $Config.AssetName
    $sbomBaseName = Get-SbomOutputBaseName -Config $Config
    New-Item -ItemType Directory -Path $packageDir -Force | Out-Null
    Copy-Item -Path $jsonSource.FullName -Destination (Join-Path $packageDir "$sbomBaseName.json") -Force
    Copy-Item -Path $xmlSource.FullName -Destination (Join-Path $packageDir "$sbomBaseName.xml") -Force
}

function Get-GitLogLines {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $lines = @(& git @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }

    return @($lines | Where-Object { $_ -ne $null -and $_ -ne '' })
}

function Get-ChangelogLines {
    param([Parameter(Mandatory = $true)]$Config)

    $version = '0.0.0-dev'
    $tagPrefix = "$($Config.PackageName)-"
    $maintainer = 'AuthScaffold <support@authscaffold.com>'
    $tags = @(Get-GitLogLines -Arguments @('tag', '--list', "$tagPrefix*", '--sort=v:refname'))
    $lines = New-Object System.Collections.ArrayList

    if ($tags.Count -gt 0) {
        $lastTag = $tags[$tags.Count - 1]
        $commits = @(Get-GitLogLines -Arguments @('--no-pager', 'log', '--pretty=format:  * %s', "$lastTag..HEAD", '--', $Config.PackageRoot))
    }
    else {
        $commits = @(Get-GitLogLines -Arguments @('--no-pager', 'log', '--pretty=format:  * %s', '--', $Config.PackageRoot))
    }

    if ($commits.Count -eq 0) {
        $commits = @("  * Release $version")
    }

    [void]$lines.Add("$($Config.PackageName) ($version) stable; urgency=medium")
    [void]$lines.Add('')
    foreach ($line in $commits) {
        [void]$lines.Add($line)
    }
    [void]$lines.Add('')
    [void]$lines.Add(" -- $maintainer  $(Get-Date -AsUTC -Format 'ddd, dd MMM yyyy HH:mm:ss +0000')")

    for ($i = $tags.Count - 1; $i -ge 0; $i--) {
        $tag = $tags[$i]
        $tagVersion = $tag.Substring($tagPrefix.Length)
        $tagDate = @(Get-GitLogLines -Arguments @('--no-pager', 'log', '-1', '--format=%aD', $tag)) | Select-Object -First 1

        if ($i -gt 0) {
            $previousTag = $tags[$i - 1]
            $tagCommits = @(Get-GitLogLines -Arguments @('--no-pager', 'log', '--pretty=format:  * %s', "$previousTag..$tag", '--', $Config.PackageRoot))
        }
        else {
            $tagCommits = @(Get-GitLogLines -Arguments @('--no-pager', 'log', '--pretty=format:  * %s', $tag, '--', $Config.PackageRoot))
        }

        if ($tagCommits.Count -eq 0) {
            $tagCommits = @("  * Release $tagVersion")
        }

        [void]$lines.Add('')
        [void]$lines.Add("$($Config.PackageName) ($tagVersion) stable; urgency=medium")
        [void]$lines.Add('')
        foreach ($line in $tagCommits) {
            [void]$lines.Add($line)
        }
        [void]$lines.Add('')
        [void]$lines.Add(" -- $maintainer  $tagDate")
    }

    return ,$lines.ToArray()
}

function Get-ManPagePath {
    param([Parameter(Mandatory = $true)]$Config)

    if ([string]::IsNullOrEmpty($Config.ManPageName)) {
        return $null
    }

    $candidateDirs = @(
        (Join-Path 'target' "$Target/release/build"),
        (Join-Path 'target' 'release/build'),
        (Join-Path 'target' 'debug/build')
    )

    foreach ($dir in $candidateDirs) {
        if (-not (Test-Path $dir -PathType Container)) {
            continue
        }

        $match = Get-ChildItem -Path $dir -Recurse -File -Filter "$($Config.ManPageName).1" | Select-Object -First 1
        if ($match) {
            return $match.FullName
        }
    }

    throw "Generated man page not found for $($Config.ManPageName)"
}

function Invoke-GzipFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $arguments = @('-9', '-n', '-c', $Source)
    Write-Host "> gzip $($arguments -join ' ') > $Destination" -ForegroundColor DarkGray
    $destinationDirectory = Split-Path $Destination -Parent
    if ($destinationDirectory) {
        New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    }

    & gzip @arguments > $Destination
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "gzip failed with exit code ${exitCode}: $Source"
    }
}

function Prepare-PackageAssets {
    param([Parameter(Mandatory = $true)]$Config)

    $artifactFileName = Get-ArtifactFileName -Config $Config
    $artifactPath = Join-Path 'target' "$Target/release/$artifactFileName"
    if (-not (Test-Path $artifactPath -PathType Leaf)) {
        throw "Expected artifact not found at $artifactPath"
    }

    New-Item -ItemType Directory -Path 'target/release' -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $Config.PackageRoot 'debian') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path 'staging' $Config.AssetName) -Force | Out-Null
    New-Item -ItemType Directory -Path 'packaged' -Force | Out-Null
    New-Item -ItemType Directory -Path 'target/debian' -Force | Out-Null

    $stagedArtifactPath = Join-Path (Join-Path 'staging' $Config.AssetName) $artifactFileName
    Copy-Item -Path $artifactPath -Destination $stagedArtifactPath -Force
    Copy-Item -Path $stagedArtifactPath -Destination (Join-Path 'target/release' $artifactFileName) -Force
    Invoke-CheckedCommand -FilePath 'chmod' -Arguments @('+x', (Join-Path 'target/release' $artifactFileName))
    Invoke-CheckedCommand -FilePath 'strip' -Arguments @((Join-Path 'target/release' $artifactFileName))

    $sbomBaseName = Get-SbomOutputBaseName -Config $Config
    Copy-Item -Path (Join-Path (Join-Path 'staging' $Config.AssetName) "$sbomBaseName.json") -Destination (Join-Path $Config.PackageRoot 'debian/sbom.json') -Force
    Copy-Item -Path (Join-Path (Join-Path 'staging' $Config.AssetName) "$sbomBaseName.xml") -Destination (Join-Path $Config.PackageRoot 'debian/sbom.xml') -Force

    if (-not [string]::IsNullOrEmpty($Config.ManPageName)) {
        $manPagePath = Get-ManPagePath -Config $Config
        $manPageDestination = Join-Path $Config.PackageRoot "debian/$($Config.ManPageName).1"
        Copy-Item -Path $manPagePath -Destination $manPageDestination -Force
        Invoke-GzipFile -Source $manPageDestination -Destination (Join-Path $Config.PackageRoot "debian/$($Config.ManPageName).1.gz")
    }

    $changelogPath = Join-Path $Config.PackageRoot 'debian/changelog'
    $changelogLines = @(Get-ChangelogLines -Config $Config)
    Set-Content -Path $changelogPath -Value $changelogLines
    Invoke-GzipFile -Source $changelogPath -Destination (Join-Path $Config.PackageRoot 'debian/changelog.gz')
}

function Invoke-DebianPackageBuild {
    param([Parameter(Mandatory = $true)]$Config)

    Invoke-CheckedCommand -FilePath 'cargo' -Arguments @('deb', '--package', $Config.PackageName, '--no-build', '--dbgsym')
}

function Invoke-DebianPackageVerify {
    param([Parameter(Mandatory = $true)]$Config)

    Invoke-CheckedCommand -FilePath 'lintian' -Arguments @("target/debian/$($Config.PackageName)_*.deb") -Advisory
    Invoke-CheckedCommand -FilePath 'dpkg' -Arguments @('--info', "target/debian/$($Config.PackageName)_*.deb")

    if (Get-ChildItem -Path 'target/debian' -Filter "$($Config.PackageName)-dbgsym_*.ddeb" -File -ErrorAction SilentlyContinue) {
        Invoke-CheckedCommand -FilePath 'dpkg' -Arguments @('--info', "target/debian/$($Config.PackageName)-dbgsym_*.ddeb")
    }
}

function Collect-DebianPackages {
    param([Parameter(Mandatory = $true)]$Config)

    Copy-Item -Path "target/debian/$($Config.PackageName)_*.deb" -Destination 'packaged' -Force
    Copy-Item -Path "target/debian/$($Config.PackageName)-dbgsym_*.ddeb" -Destination 'packaged' -Force -ErrorAction SilentlyContinue
}

$repoRoot = Get-RepoRoot
$hostKind = Get-HostKind

Initialize-RustEnvironment

if ($hostKind -ne 'Linux') {
    throw 'run-debian-packages.ps1 only supports Linux/WSL. Run it from Linux or WSL with PowerShell installed.'
}

Push-Location $repoRoot

try {
    Assert-PackageSelection
    Enable-GitWorktreeForWsl

    Assert-CommandExists -Name 'cargo' -InstallHint 'Install Rust via rustup before running this script.'
    Assert-CommandExists -Name 'git' -InstallHint 'Install git before running this script.'
    Assert-CommandExists -Name 'dpkg' -InstallHint 'Install dpkg before running this script.'
    Assert-CommandExists -Name 'gzip' -InstallHint 'Install gzip before running this script.'
    Assert-CommandExists -Name 'strip' -InstallHint 'Install binutils before running this script.'

    Assert-LinuxPackages
    Assert-CargoTool -CargoSubcommand 'deb' -CrateName 'cargo-deb'
    Assert-CargoTool -CargoSubcommand 'cyclonedx' -CrateName 'cargo-cyclonedx'

    Remove-Item 'packaged', 'staging', 'target/debian' -Recurse -Force -ErrorAction SilentlyContinue

    $selectedConfigs = @(Select-PackageConfigs)
    foreach ($config in $selectedConfigs) {
        Write-Host "`n=== Debian Packages ($($config.PackageName)) ===" -ForegroundColor Cyan
        Invoke-BuildArtifact -Config $config
        Invoke-GenerateSboms -Config $config
        Prepare-PackageAssets -Config $config
        Invoke-DebianPackageBuild -Config $config
        Invoke-DebianPackageVerify -Config $config
        Collect-DebianPackages -Config $config
    }

    Write-Host "`nDebian package validation completed." -ForegroundColor Green
}
finally {
    Pop-Location
}