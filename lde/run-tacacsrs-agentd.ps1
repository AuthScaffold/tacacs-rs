<#
.SYNOPSIS
    Runs tacacsrs-agentd with optional profiling support.
.DESCRIPTION
    Builds and runs the TACACS+ agent daemon in release mode (with full
    debug symbols).  Supports Visual Studio Performance Profiler and
    tokio-console for async runtime profiling.
.PARAMETER RunProfile
    Profiling mode:
      none           - Normal run with verbose logging (default)
      vs             - Build and launch; prints instructions to attach the
                       VS Performance Profiler (CPU Usage / Memory)
      tokio-console  - Build with console-subscriber and launch alongside
                       the tokio-console async runtime profiler
.PARAMETER Verbosity
    Logging verbosity level (0-4). Default is 3 (debug).
    0=off, 1=warn, 2=info, 3=debug, 4=trace
.PARAMETER TacacsObfuscationKey
    Optional obfuscation key to use for TACACS+ packets.  If not provided,
    obfuscation will not be used.
.PARAMETER ServerAddress
    Address and port for the agent to listen on (default: 127.0.0.1:49).
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
        throw 'cargo not found in PATH. Install Rust via https://rustup.rs'
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
            Write-Host 'Building release binary with full debug symbols...'
            cargo build --bin tacacsrs-agentd --release
            if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }

            $exe = Resolve-Path '.\target\release\tacacsrs-agentd.exe'
            Write-Host ''
            Write-Host 'Binary: ' -NoNewline
            Write-Host $exe -ForegroundColor Green
            Write-Host ''
            Write-Host 'To profile with Visual Studio:' -ForegroundColor Yellow
            Write-Host '  1. Open Visual Studio'
            Write-Host '  2. Debug > Performance Profiler  (Alt+F2)'
            Write-Host '  3. Change analysis target to "Running Process"'
            Write-Host '  4. Enable "CPU Usage" (and optionally "Memory Usage")'
            Write-Host '  5. Attach to PID printed below'
            Write-Host '  6. Send requests to the agent, then stop collection in VS'
            Write-Host ''

            # Start the agent so VS can attach
            $process = Start-Process -FilePath $exe -ArgumentList $agentArgs `
                -PassThru -NoNewWindow
            Write-Host "tacacsrs-agentd started — PID: $($process.Id)" -ForegroundColor Green
            Write-Host 'Attach VS now.  Press Ctrl+C to stop the agent.'
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
            Write-Host 'Note: log macros are replaced by the tracing subscriber' `
                'in this mode.' -ForegroundColor Yellow
            Write-Host ''

            # tokio-console requires the tokio_unstable cfg flag at build time
            $savedRustflags = $env:RUSTFLAGS
            try {
                $parts = @($savedRustflags, '--cfg tokio_unstable') | Where-Object { $_ }
                $env:RUSTFLAGS = $parts -join ' '

                Write-Host "Building with RUSTFLAGS='$($env:RUSTFLAGS)' --features console ..."
                cargo build --bin tacacsrs-agentd --release `
                    --features tacacsrs-agentd/console
                if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
            }
            finally {
                $env:RUSTFLAGS = $savedRustflags
            }

            # Install tokio-console if missing
            $installed = cargo install --list 2>&1 |
                Select-String -Pattern '^tokio-console v'
            if (-not $installed) {
                Write-Host 'Installing tokio-console...' -ForegroundColor Green
                cargo install tokio-console
                if ($LASTEXITCODE -ne 0) { throw 'Failed to install tokio-console' }
            }

            Write-Host ''
            Write-Host 'Starting tokio-console viewer...' -ForegroundColor Green
            Start-Process -FilePath 'tokio-console'

            Write-Host 'Starting tacacsrs-agentd (Ctrl+C to stop)...'
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