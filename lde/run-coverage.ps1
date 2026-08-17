<#
.SYNOPSIS
    Runs code-coverage tests for one crate or the workspace.

.DESCRIPTION
    Uses cargo-llvm-cov to show a coverage summary. The script can also create
    HTML and LCOV reports. Before you run this script, install cargo-llvm-cov.

.PARAMETER Package
    The crate name, for example, tacacsrs-messages or tacacsrs-networking.
    If you omit this parameter, the script covers the workspace.

.PARAMETER Html
    Creates an HTML coverage report and opens it in the default browser.

.PARAMETER Lcov
    Exports an LCOV profile to the specified path.
    The default path is target/llvm-cov/lcov.info.

.PARAMETER FailUnderLines
    If total line coverage is less than this percentage, returns exit code 1.

.PARAMETER AllFeatures
    Activates all available features.

.PARAMETER Branch
    Activates branch-coverage instrumentation. Adds a Branch % column to the
    file table. The summary includes branch and MC/DC totals.
    If you also set -Lcov, the script shows each uncovered source location.
    The script reads BRDA:line,block,branch,0 records.

.EXAMPLE
    # Show the workspace coverage summary.
    .\lde\run-coverage.ps1

.EXAMPLE
    # Create an HTML report for one crate.
    .\lde\run-coverage.ps1 -Package tacacsrs-messages -Html

.EXAMPLE
    # Export LCOV for one crate and require the minimum coverage.
    .\lde\run-coverage.ps1 -Package tacacsrs-networking -Lcov -FailUnderLines 80

.EXAMPLE
    # Activate all features.
    .\lde\run-coverage.ps1 -Package tacacsrs-config -AllFeatures -Html

.EXAMPLE
    # Find missed branches during branch-coverage analysis.
    .\lde\run-coverage.ps1 -Package tacacsrs-config -AllFeatures -Branch -Lcov
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Package,

    [switch]$Html,

    [switch]$Lcov,

    [ValidateRange(0, 100)]
    [int]$FailUnderLines = 0,

    [switch]$AllFeatures,

    [switch]$Branch
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir '..')

Push-Location $repoRoot

try {
    # --- prerequisites ---
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw 'cargo was not found in PATH. Install Rust via rustup before running this script.'
    }

    $llvmCovVersion = $null
    try { $llvmCovVersion = cargo llvm-cov --version 2>&1 } catch { }
    if (-not $llvmCovVersion) {
        throw 'cargo-llvm-cov was not found. Run: cargo install cargo-llvm-cov'
    }
    Write-Host "Using $llvmCovVersion" -ForegroundColor DarkGray

    # --- make sure that the specified package name is valid ---
    if ($Package) {
        $members = cargo metadata --no-deps --format-version 1 2>&1 |
            ConvertFrom-Json |
            Select-Object -ExpandProperty packages |
            Select-Object -ExpandProperty name
        if ($Package -notin $members) {
            $available = $members -join ', '
            throw "Unknown package '$Package'. Available: $available"
        }
    }

    # --- build argument list ---
    $scopeArgs = @()

    if ($Package) {
        $scopeArgs += '--package', $Package
        Write-Host "Run coverage for package: $Package" -ForegroundColor Cyan
    }
    else {
        $scopeArgs += '--workspace'
        Write-Host 'Run coverage for the workspace' -ForegroundColor Cyan
    }

    # Feature flags apply to instrumented test runs.
    # They do not apply to the `cargo llvm-cov report` subcommand.
    $testOnlyArgs = @()
    if ($AllFeatures) {
        $testOnlyArgs += '--all-features'
    }

    # Branch instrumentation applies to the test run and each report subcommand.
    # Pass `--branch` to the report subcommand to show the collected branch data.
    $branchArgs = @()
    if ($Branch) {
        $branchArgs += '--branch'
        Write-Host 'Branch coverage is active.' -ForegroundColor DarkGray
    }

    # --- phase 1: run tests and collect coverage ---
    Write-Host "`nBuild the test binaries. Then run the instrumented tests." -ForegroundColor Yellow
    $testArgs = @('llvm-cov', '--no-report') + $scopeArgs + $testOnlyArgs + $branchArgs
    & cargo @testArgs
    if ($LASTEXITCODE -ne 0) { throw 'The test command returned an error.' }

    # --- phase 2: parse the JSON summary into a PowerShell table ---
    Write-Host "`n--- Coverage Summary ---" -ForegroundColor Green
    $jsonArgs = @('llvm-cov', 'report', '--json') + $scopeArgs + $branchArgs
    $rawJson = & cargo @jsonArgs 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'The coverage report command returned an error.' }

    $report = $rawJson | ConvertFrom-Json
    $data = $report.data[0]

    $rows = foreach ($file in $data.files) {
        $rel = $file.filename
        # Show the path relative to the repository root.
        if ($rel.StartsWith($repoRoot.Path, [System.StringComparison]::OrdinalIgnoreCase)) {
            $rel = $rel.Substring($repoRoot.Path.Length).TrimStart('\', '/')
        }
        $s = $file.summary
        [PSCustomObject]@{
            File       = $rel
            'Lines %'  = '{0:N1}' -f $s.lines.percent
            Lines      = "$($s.lines.covered)/$($s.lines.count)"
            'Funcs %'  = '{0:N1}' -f $s.functions.percent
            Funcs      = "$($s.functions.covered)/$($s.functions.count)"
            'Rgns %'   = '{0:N1}' -f $s.regions.percent
            Regions    = "$($s.regions.covered)/$($s.regions.count)"
            'Branch %' = if ($s.branches.count -gt 0) { '{0:N1}' -f $s.branches.percent } else { '-' }
            Branches   = if ($s.branches.count -gt 0) { "$($s.branches.covered)/$($s.branches.count)" } else { '-' }
        }
    }

    $rows | Sort-Object 'Lines %' | Format-Table -AutoSize | Out-String | Write-Host

    # If the report contains branch and MC/DC totals, show them.
    $t = $data.totals
    $branchSummary = if ($t.branches.count -gt 0) { '  Branches: {0:N1}% ({1}/{2})' -f $t.branches.percent, $t.branches.covered, $t.branches.count } else { '' }
    $mcdcSummary   = if ($t.mcdc.count   -gt 0) { '  MC/DC: {0:N1}% ({1}/{2})'      -f $t.mcdc.percent,   $t.mcdc.covered,   $t.mcdc.count   } else { '' }
    Write-Host ('  TOTAL  Lines: {0:N1}% ({1}/{2})  Functions: {3:N1}% ({4}/{5})  Regions: {6:N1}% ({7}/{8}){9}{10}' -f `
        $t.lines.percent, $t.lines.covered, $t.lines.count,
        $t.functions.percent, $t.functions.covered, $t.functions.count,
        $t.regions.percent, $t.regions.covered, $t.regions.count,
        $branchSummary, $mcdcSummary
    ) -ForegroundColor Cyan

    $summaryExit = 0
    if ($FailUnderLines -gt 0 -and $t.lines.percent -lt $FailUnderLines) {
        $summaryExit = 1
    }

    # --- phase 3: optional HTML report ---
    if ($Html) {
        Write-Host "`nCreate the HTML coverage report." -ForegroundColor Yellow
        $htmlArgs = @('llvm-cov', 'report', '--html', '--open') + $scopeArgs + $branchArgs
        & cargo @htmlArgs
        if ($LASTEXITCODE -ne 0) { Write-Warning 'The HTML report command returned an error.' }
    }

    # --- phase 4: optional LCOV export ---
    if ($Lcov) {
        $lcovDir = Join-Path $repoRoot 'target' 'llvm-cov'
        if (-not (Test-Path $lcovDir)) { New-Item -ItemType Directory -Path $lcovDir -Force | Out-Null }
        $lcovPath = Join-Path $lcovDir 'lcov.info'

        Write-Host "`nExport the LCOV profile to $lcovPath." -ForegroundColor Yellow
        $lcovArgs = @('llvm-cov', 'report', '--lcov', '--output-path', $lcovPath) + $scopeArgs + $branchArgs
        & cargo @lcovArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Warning 'The LCOV export command returned an error.'
        }
        else {
            Write-Host "LCOV profile written to $lcovPath" -ForegroundColor Green

            # If `-Branch` is active, parse BRDA records for each uncovered branch.
            # Show the source file and line for each branch with a zero hit count.
            # LCOV format: BRDA:line,block,branch,hit_count
            if ($Branch) {
                $currentSF = ''
                $missed = [System.Collections.Generic.List[string]]::new()
                foreach ($lcovLine in (Get-Content $lcovPath)) {
                    if ($lcovLine -match '^SF:(.+)$') {
                        $currentSF = $Matches[1]
                        if ($currentSF.StartsWith($repoRoot.Path, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $currentSF = $currentSF.Substring($repoRoot.Path.Length).TrimStart('\', '/')
                        }
                    }
                    elseif ($lcovLine -match '^BRDA:(\d+),\d+,\d+,0$') {
                        $missed.Add("  $currentSF : line $($Matches[1])")
                    }
                }
                if ($missed.Count -gt 0) {
                    Write-Host "`nUncovered branches:" -ForegroundColor Yellow
                    $missed | Select-Object -Unique | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
                }
                else {
                    Write-Host "`nAll branches have coverage." -ForegroundColor Green
                }
            }
        }
    }

    # --- final exit code ---
    if ($summaryExit -ne 0) {
        throw "Coverage is below the required threshold ($FailUnderLines% lines)."
    }

    Write-Host "`nCoverage run completed." -ForegroundColor Green
}
finally {
    Pop-Location
}