<#
.SYNOPSIS
    Runs tests with code coverage for a specific crate or the entire workspace.

.DESCRIPTION
    Wraps cargo-llvm-cov to produce a coverage percentage summary and optional
    HTML/LCOV profile output. Requires cargo-llvm-cov to be installed
    (cargo install cargo-llvm-cov).

.PARAMETER Package
    The crate name to test (e.g. tacacsrs-messages, tacacsrs-networking).
    If omitted, runs coverage for the entire workspace.

.PARAMETER Html
    Generate an HTML coverage report and open it in the default browser.

.PARAMETER Lcov
    Export an LCOV profile to the specified path (default: target/llvm-cov/lcov.info).

.PARAMETER FailUnderLines
    Exit with failure if total line coverage is below this percentage.

.PARAMETER AllFeatures
    Activate all available features.

.PARAMETER Branch
    Enable branch coverage instrumentation. Adds a Branch % column to the
    per-file table and includes branch/MC/DC totals in the summary line.
    When combined with -Lcov, automatically prints every source location
    with an uncovered branch (reads BRDA:line,block,branch,0 records).

.EXAMPLE
    # Workspace-wide coverage summary
    .\lde\run-coverage.ps1

.EXAMPLE
    # Single crate with HTML report
    .\lde\run-coverage.ps1 -Package tacacsrs-messages -Html

.EXAMPLE
    # Single crate with LCOV export and minimum threshold
    .\lde\run-coverage.ps1 -Package tacacsrs-networking -Lcov -FailUnderLines 80

.EXAMPLE
    # All features enabled
    .\lde\run-coverage.ps1 -Package tacacsrs-config -AllFeatures -Html

.EXAMPLE
    # Branch coverage with automatic missed-branch analysis
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
    # --- prerequisite checks ---
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw 'cargo was not found in PATH. Install Rust via rustup before running this script.'
    }

    $llvmCovVersion = $null
    try { $llvmCovVersion = cargo llvm-cov --version 2>&1 } catch { }
    if (-not $llvmCovVersion) {
        throw 'cargo-llvm-cov is not installed. Run: cargo install cargo-llvm-cov'
    }
    Write-Host "Using $llvmCovVersion" -ForegroundColor DarkGray

    # --- validate package name if provided ---
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
        Write-Host "Running coverage for package: $Package" -ForegroundColor Cyan
    }
    else {
        $scopeArgs += '--workspace'
        Write-Host 'Running coverage for the entire workspace' -ForegroundColor Cyan
    }

    # Feature flags are valid for test/instrumentation runs, but not for
    # the `cargo llvm-cov report` subcommand.
    $testOnlyArgs = @()
    if ($AllFeatures) {
        $testOnlyArgs += '--all-features'
    }

    # Branch instrumentation applies to both the test run and all report
    # subcommands — the report subcommand must also receive --branch to emit
    # the branch columns from the collected profdata.
    $branchArgs = @()
    if ($Branch) {
        $branchArgs += '--branch'
        Write-Host 'Branch coverage enabled' -ForegroundColor DarkGray
    }

    # --- phase 1: run tests and collect coverage (no report yet) ---
    Write-Host "`nBuilding and running tests with instrumentation..." -ForegroundColor Yellow
    $testArgs = @('llvm-cov', '--no-report') + $scopeArgs + $testOnlyArgs + $branchArgs
    & cargo @testArgs
    if ($LASTEXITCODE -ne 0) { throw 'Test execution failed.' }

    # --- phase 2: JSON summary parsed into a PowerShell table ---
    Write-Host "`n--- Coverage Summary ---" -ForegroundColor Green
    $jsonArgs = @('llvm-cov', 'report', '--json') + $scopeArgs + $branchArgs
    $rawJson = & cargo @jsonArgs 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Coverage report generation failed.' }

    $report = $rawJson | ConvertFrom-Json
    $data = $report.data[0]

    $rows = foreach ($file in $data.files) {
        $rel = $file.filename
        # Make the path relative to the repo root for readability.
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

    # Totals — branch and MC/DC are shown when present in the report data.
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
        Write-Host "`nGenerating HTML coverage report..." -ForegroundColor Yellow
        $htmlArgs = @('llvm-cov', 'report', '--html', '--open') + $scopeArgs + $branchArgs
        & cargo @htmlArgs
        if ($LASTEXITCODE -ne 0) { Write-Warning 'HTML report generation failed.' }
    }

    # --- phase 4: optional LCOV export ---
    if ($Lcov) {
        $lcovDir = Join-Path $repoRoot 'target' 'llvm-cov'
        if (-not (Test-Path $lcovDir)) { New-Item -ItemType Directory -Path $lcovDir -Force | Out-Null }
        $lcovPath = Join-Path $lcovDir 'lcov.info'

        Write-Host "`nExporting LCOV profile to $lcovPath ..." -ForegroundColor Yellow
        $lcovArgs = @('llvm-cov', 'report', '--lcov', '--output-path', $lcovPath) + $scopeArgs + $branchArgs
        & cargo @lcovArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Warning 'LCOV export failed.'
        }
        else {
            Write-Host "LCOV profile written to $lcovPath" -ForegroundColor Green

            # When -Branch is active, parse BRDA records and surface every
            # uncovered branch (hit count 0) alongside its source file and line.
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
                    Write-Host "`nAll branches covered." -ForegroundColor Green
                }
            }
        }
    }

    # --- final exit code ---
    if ($summaryExit -ne 0) {
        throw "Coverage is below the required threshold ($FailUnderLines% lines)."
    }

    Write-Host "`nDone." -ForegroundColor Green
}
finally {
    Pop-Location
}