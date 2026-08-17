<#
.SYNOPSIS
    Runs tacacsrs-agentd with optional profiling.
.DESCRIPTION
    Builds and runs the TACACS+ agent daemon in release mode with full debug
    symbols. The script supports Visual Studio Performance Profiler and
    tokio-console.
.PARAMETER RunProfile
    Profiling mode:
      none           - Runs with verbose logging (default)
      vs             - Builds and runs the agent for the VS Performance Profiler
      tokio-console  - Builds with console-subscriber and runs tokio-console
.PARAMETER Verbosity
    Logging verbosity level (0-4). Default is 3 (debug).
    0=off, 1=warn, 2=info, 3=debug, 4=trace
.PARAMETER TacacsObfuscationKey
    The optional shared secret for TACACS+ body obfuscation.
    If you omit the shared secret, the packets use no obfuscation.
.PARAMETER ServerAddress
    The TACACS+ server address and port. The default is 127.0.0.1:49.
.EXAMPLE
    .\run-tacacsrs-agentd.ps1
    .\run-tacacsrs-agentd.ps1 -RunProfile vs
    .\run-tacacsrs-agentd.ps1 -RunProfile tokio-console
    .\run-tacacsrs-agentd.ps1 -Verbosity 4
#>
[CmdletBinding()]
param(
    [ValidateSet('none', 'vs', 'tokio-console')]
    [string]$RunProfile = 'none',

    [ValidateRange(0, 4)]
    [int]$Verbosity = 3,

    [string]$TacacsObfuscationKey = $null,

    [string]$ServerAddress = "127.0.0.1:49"
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir '..')

Push-Location $repoRoot

try {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw 'cargo was not found in PATH. Install Rust from https://rustup.rs.'
    }

    $verboseFlag = if ($Verbosity -gt 0) { '-' + ('v' * $Verbosity) } else { $null }
    $agentArgs = @(
        '--server-addr', $ServerAddress
    )
    if ($TacacsObfuscationKey) { $agentArgs += @('-k', $TacacsObfuscationKey) }

    if ($verboseFlag) { $agentArgs += $verboseFlag }

    switch ($RunProfile) {

        # -----------------------------------------------------------------
        # Visual Studio Performance Profiler
        # -----------------------------------------------------------------
        'vs' {
            Write-Host '=== Visual Studio Profiling ===' -ForegroundColor Cyan
            Write-Host ''
            Write-Host 'Build the release binary with full debug symbols.'
            cargo build --bin tacacsrs-agentd --release
            if ($LASTEXITCODE -ne 0) { throw 'The cargo build returned an error.' }

            $exe = Resolve-Path '.\target\release\tacacsrs-agentd.exe'
            Write-Host ''
            Write-Host 'Binary: ' -NoNewline
            Write-Host $exe -ForegroundColor Green
            Write-Host ''
            Write-Host 'To profile with Visual Studio:' -ForegroundColor Yellow
            Write-Host '  1. Open Visual Studio'
            Write-Host '  2. Debug > Performance Profiler  (Alt+F2)'
            Write-Host '  3. Set the analysis target to "Running Process".'
            Write-Host '  4. Select "CPU Usage" and, if necessary, "Memory Usage".'
            Write-Host '  5. Attach to the PID shown below.'
            Write-Host '  6. Send requests to the agent.'
            Write-Host '  7. Stop data collection in Visual Studio.'
            Write-Host ''

            # Start the agent. Then Visual Studio can attach to it.
            $process = Start-Process -FilePath $exe -ArgumentList $agentArgs `
                -PassThru -NoNewWindow
            Write-Host "tacacsrs-agentd started. PID: $($process.Id)" -ForegroundColor Green
            Write-Host 'Attach Visual Studio now. Press Ctrl+C to stop the agent.'
            Write-Host ''

            try {
                $process.WaitForExit()
            }
            finally {
                if (-not $process.HasExited) {
                    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                }
            }
        }

        # -----------------------------------------------------------------
        # tokio-console async runtime profiling
        # -----------------------------------------------------------------
        'tokio-console' {
            Write-Host '=== Tokio Console Async Profiling ===' -ForegroundColor Cyan
            Write-Host ''
            Write-Host 'Note: The tracing subscriber replaces log macros in this mode.' `
                -ForegroundColor Yellow
            Write-Host ''

            # The tokio-console build requires the tokio_unstable cfg flag.
            $savedRustflags = $env:RUSTFLAGS
            try {
                $parts = @($savedRustflags, '--cfg tokio_unstable') | Where-Object { $_ }
                $env:RUSTFLAGS = $parts -join ' '

                Write-Host "Build with RUSTFLAGS='$($env:RUSTFLAGS)' --features console."
                cargo build --bin tacacsrs-agentd --release `
                    --features tacacsrs-agentd/console
                if ($LASTEXITCODE -ne 0) { throw 'The cargo build returned an error.' }
            }
            finally {
                $env:RUSTFLAGS = $savedRustflags
            }

            # If tokio-console is not installed, install it.
            $installed = cargo install --list 2>&1 |
                Select-String -Pattern '^tokio-console v'
            if (-not $installed) {
                Write-Host 'Install tokio-console.' -ForegroundColor Green
                cargo install tokio-console
                if ($LASTEXITCODE -ne 0) { throw 'The tokio-console installation returned an error.' }
            }

            Write-Host ''
            Write-Host 'Start the tokio-console viewer.' -ForegroundColor Green
            Start-Process -FilePath 'tokio-console'

            Write-Host 'Start tacacsrs-agentd. Press Ctrl+C to stop it.'
            & '.\target\release\tacacsrs-agentd.exe' @agentArgs
        }

        # -----------------------------------------------------------------
        # Default: normal run
        # -----------------------------------------------------------------
        default {
            cargo run --bin tacacsrs-agentd --release -- @agentArgs
        }
    }
}
finally {
    Pop-Location
}