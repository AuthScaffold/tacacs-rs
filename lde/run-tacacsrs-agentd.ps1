<#
.SYNOPSIS
    Runs tacacsrs-agentd on Linux (WSL or development container) with optional tokio-console profiling.
.DESCRIPTION
    Builds and runs the Linux-only TACACS+ agent daemon in release mode with
    full debug symbols. On Windows hosts, the script stops with instructions to
    run inside WSL or the Linux development container instead.
.PARAMETER RunProfile
    Profiling mode:
      none           - Runs with verbose logging (default)
      tokio-console  - Builds with console-subscriber and runs tokio-console
.PARAMETER Verbosity
    Logging verbosity level (0-4). Default is 3 (debug).
    0=off, 1=warn, 2=info, 3=debug, 4=trace
.PARAMETER TacacsObfuscationKey
    The optional shared secret for TACACS+ body obfuscation.
    If you omit the shared secret, provide another valid upstream credential flag.
.PARAMETER ServerAddress
    The TACACS+ server address and port. The default is 127.0.0.1:49.
.EXAMPLE
    pwsh ./lde/run-tacacsrs-agentd.ps1 -TacacsObfuscationKey test-secret
    pwsh ./lde/run-tacacsrs-agentd.ps1 -RunProfile tokio-console -TacacsObfuscationKey test-secret
    pwsh ./lde/run-tacacsrs-agentd.ps1 -Verbosity 4 -TacacsObfuscationKey test-secret
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

$isLinuxHost = [bool](Get-Variable -Name IsLinux -ValueOnly -ErrorAction SilentlyContinue)
if (-not $isLinuxHost) {
    throw 'tacacsrs-agentd is supported on Linux only and does not build tacacsrs-agentd.exe on Windows. Run tacacsrs-agentd inside WSL or the Linux development container instead (see DEVELOPMENT.md).'
}
if ($RunProfile -eq 'vs') {
    throw 'The Visual Studio Windows profiler mode is unavailable because tacacsrs-agentd is Linux-only. Use -RunProfile none or -RunProfile tokio-console on Linux (WSL or the development container).'
}

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
            & './target/release/tacacsrs-agentd' @agentArgs
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