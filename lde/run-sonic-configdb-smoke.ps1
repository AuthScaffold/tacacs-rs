<#
.SYNOPSIS
    Runs the tacacsrs-sonic ConfigDB watcher smoke test against containerized Redis.
.DESCRIPTION
    Starts a Redis container, seeds SONiC-style TACPLUS / TACPLUS_SERVER rows in
    database 4, runs the configdb_watch example, mutates Redis, and verifies the
    example reports added, modified, and removed server deltas.
.PARAMETER ContainerRuntime
    Container CLI to use. Defaults to podman.
.PARAMETER RedisImage
    Redis image to run.
.PARAMETER RedisPort
    Host TCP port mapped to the Redis container.
.PARAMETER RedisTransport
    Redis connection transport used by the example. UnixSocket requires Linux or WSL.
.PARAMETER KeepContainer
    Leave the Redis container running after the smoke test completes.
.EXAMPLE
    .\lde\run-sonic-configdb-smoke.ps1
#>
[CmdletBinding()]
param(
    [ValidateSet('podman', 'docker')]
    [string]$ContainerRuntime = 'podman',

    [string]$RedisImage = 'docker.io/library/redis:7-alpine',

    [string]$ContainerName = 'tacacsrs-sonic-configdb-smoke',

    [ValidateRange(1, 65535)]
    [int]$RedisPort = 6379,

    [ValidateSet('Tcp', 'UnixSocket')]
    [string]$RedisTransport = 'Tcp',

    [ValidateRange(0, 15)]
    [int]$RedisDb = 4,

    [ValidateRange(0, 10000)]
    [int]$DebounceMs = 100,

    [switch]$KeepContainer
)

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir '..')
$tmpDir = Join-Path $repoRoot 'target\tmp'
$stdoutPath = Join-Path $tmpDir 'sonic-configdb-watch.out'
$stderrPath = Join-Path $tmpDir 'sonic-configdb-watch.err'
$isLinuxHost = Get-Variable -Name IsLinux -ValueOnly -ErrorAction SilentlyContinue
$useTcpTransport = $RedisTransport -eq 'Tcp'
$useUnixSocketTransport = $RedisTransport -eq 'UnixSocket'
$usePodmanHostNetwork = $ContainerRuntime -eq 'podman' -and $isLinuxHost -and $useTcpTransport
$socketDir = if ($useUnixSocketTransport) { Join-Path ([IO.Path]::GetTempPath()) "tacacsrs-sonic-configdb-smoke-$PID" } else { $null }
$socketPath = if ($useUnixSocketTransport) { Join-Path $socketDir 'redis.sock' } else { $null }
$containerSocketDir = '/run/redis'
$containerSocketPath = "$containerSocketDir/redis.sock"

function Test-RequiredCommand {
    param([string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name was not found in PATH."
    }
}

function Invoke-Redis {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$RedisArgs
    )

    if ($useUnixSocketTransport) {
        $output = & $ContainerRuntime exec $ContainerName redis-cli -s $containerSocketPath -n $RedisDb @RedisArgs
    } else {
        $output = & $ContainerRuntime exec $ContainerName redis-cli -n $RedisDb @RedisArgs
    }
    if ($LASTEXITCODE -ne 0) {
        throw "redis-cli failed: $($RedisArgs -join ' ')"
    }
    $output
}

function Wait-ForRedis {
    param([int]$TimeoutSeconds = 60)

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ($useUnixSocketTransport) {
            $output = & $ContainerRuntime exec $ContainerName redis-cli -s $containerSocketPath PING 2>$null
        } else {
            $output = & $ContainerRuntime exec $ContainerName redis-cli PING 2>$null
        }
        if ($LASTEXITCODE -eq 0 -and ($output -contains 'PONG')) {
            return
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw 'Timed out waiting for Redis to accept commands.'
}

function Wait-ForTcpEndpoint {
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutSeconds = 60
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $connect = $client.ConnectAsync($HostName, $Port)
            if ($connect.Wait(500) -and $client.Connected) {
                return
            }
        }
        finally {
            $client.Dispose()
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "Timed out waiting for Redis TCP endpoint ${HostName}:${Port}."
}

function Wait-ForOutputText {
    param(
        [string]$Path,
        [string]$Text,
        [int]$TimeoutSeconds = 60
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ((Test-Path $Path) -and ((Get-Content $Path -Raw) -like "*$Text*")) {
            return
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "Timed out waiting for example output containing '$Text'."
}

function Assert-Contains {
    param(
        [string]$Text,
        [string]$Expected
    )

    if (-not $Text.Contains($Expected)) {
        throw "Expected output to contain: $Expected"
    }
}

Push-Location $repoRoot

try {
    if ($useUnixSocketTransport -and -not $isLinuxHost) {
        throw 'UnixSocket Redis transport requires Linux or WSL.'
    }

    Test-RequiredCommand cargo
    Test-RequiredCommand $ContainerRuntime

    New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
    Remove-Item -Force -ErrorAction SilentlyContinue $stdoutPath, $stderrPath
    if ($useUnixSocketTransport) {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $socketDir
        New-Item -ItemType Directory -Force -Path $socketDir | Out-Null
        & chmod 0777 $socketDir
        if ($LASTEXITCODE -ne 0) { throw "Failed to make Redis socket directory writable: $socketDir" }
    }

    Write-Host "Starting Redis container with $ContainerRuntime..."
    $redisCommand = @()
    if ($useUnixSocketTransport) {
        $redisCommand = @('redis-server', '--port', '0', '--unixsocket', $containerSocketPath, '--unixsocketperm', '777')
    }

    if ($ContainerRuntime -eq 'podman') {
        if ($useUnixSocketTransport) {
            & $ContainerRuntime run --detach --replace --name $ContainerName --volume "${socketDir}:${containerSocketDir}:Z" $RedisImage @redisCommand | Out-Null
        } elseif ($usePodmanHostNetwork) {
            & $ContainerRuntime run --detach --replace --name $ContainerName --network host $RedisImage @redisCommand | Out-Null
        } else {
            & $ContainerRuntime run --detach --replace --name $ContainerName --publish "${RedisPort}:6379" $RedisImage @redisCommand | Out-Null
        }
    } else {
        & $ContainerRuntime rm --force $ContainerName 2>$null | Out-Null
        if ($useUnixSocketTransport) {
            & $ContainerRuntime run --detach --name $ContainerName --volume "${socketDir}:${containerSocketDir}" $RedisImage @redisCommand | Out-Null
        } else {
            & $ContainerRuntime run --detach --name $ContainerName --publish "${RedisPort}:6379" $RedisImage @redisCommand | Out-Null
        }
    }
    if ($LASTEXITCODE -ne 0) { throw 'Failed to start Redis container.' }

    Wait-ForRedis
    if ($useTcpTransport) {
        Wait-ForTcpEndpoint -HostName '127.0.0.1' -Port $RedisPort
    } elseif (-not (Test-Path $socketPath)) {
        throw "Redis Unix socket was not created at $socketPath."
    }

    Write-Host 'Building configdb_watch example...'
    cargo build -p tacacsrs-sonic --example configdb_watch
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed.' }

    $exampleExe = if ($isLinuxHost) { Join-Path $repoRoot 'target\debug\examples\configdb_watch' } else { Join-Path $repoRoot 'target\debug\examples\configdb_watch.exe' }
    if (-not (Test-Path $exampleExe) -and -not $isLinuxHost) {
        $exampleExe = Join-Path $repoRoot 'target\debug\examples\configdb_watch'
    }
    if (-not (Test-Path $exampleExe)) {
        throw 'Could not find built configdb_watch example binary.'
    }

    Write-Host 'Seeding SONiC ConfigDB rows...'
    Invoke-Redis @('CONFIG', 'SET', 'notify-keyspace-events', 'KEA') | Out-Null
    Invoke-Redis @('DEL', 'TACPLUS|global') | Out-Null
    $serverKeys = Invoke-Redis @('KEYS', 'TACPLUS_SERVER|*')
    foreach ($key in $serverKeys) {
        if ($key) { Invoke-Redis @('DEL', $key) | Out-Null }
    }
    Invoke-Redis @(
        'HSET', 'TACPLUS|global',
        'timeout', '5',
        'passkey', 'shared-secret',
        'auth_type', 'pap',
        'src_intf', 'Management0'
    ) | Out-Null
    Invoke-Redis @(
        'HSET', 'TACPLUS_SERVER|192.0.2.10',
        'priority', '1',
        'tcp_port', '49',
        'timeout', '10',
        'passkey', 'server-secret',
        'domain_name', 'tacacs-a.example.test',
        'sni_enabled', 'true',
        'single_connection', 'true'
    ) | Out-Null

    Write-Host 'Starting configdb_watch example...'
    $redisUrl = if ($useUnixSocketTransport) { "unix://${socketPath}?db=$RedisDb" } else { "redis://127.0.0.1:$RedisPort" }
    $exampleArgs = @(
        '--redis-url', $redisUrl,
        '--redis-db', "$RedisDb",
        '--debounce-ms', "$DebounceMs",
        '--max-events', '3'
    )
    $process = Start-Process -FilePath $exampleExe -ArgumentList $exampleArgs `
        -WorkingDirectory $repoRoot -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath -PassThru

    try {
        Wait-ForOutputText -Path $stdoutPath -Text 'watching for TACPLUS keyspace notifications'

        Write-Host 'Mutating Redis rows to trigger add, modify, and remove events...'
        Invoke-Redis @(
            'HSET', 'TACPLUS_SERVER|192.0.2.20',
            'priority', '2',
            'tcp_port', '49',
            'passkey', 'backup-secret'
        ) | Out-Null
        Start-Sleep -Milliseconds ($DebounceMs + 500)

        Invoke-Redis @('HSET', 'TACPLUS_SERVER|192.0.2.10', 'timeout', '20') | Out-Null
        Start-Sleep -Milliseconds ($DebounceMs + 500)

        Invoke-Redis @('DEL', 'TACPLUS_SERVER|192.0.2.20') | Out-Null

        if (-not $process.WaitForExit(60000)) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            throw 'Timed out waiting for configdb_watch to consume all events.'
        }
        if ($process.ExitCode -ne 0) {
            throw "configdb_watch exited with code $($process.ExitCode)."
        }
    }
    finally {
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }

    $stdout = Get-Content $stdoutPath -Raw
    $stderr = if (Test-Path $stderrPath) { Get-Content $stderrPath -Raw } else { '' }

    Assert-Contains $stdout 'initial_server_count: 1'
    Assert-Contains $stdout 'server: sonic-server-192.0.2.10'
    Assert-Contains $stdout 'domain_name: tacacs-a.example.test'
    Assert-Contains $stdout 'sni_enabled: true'
    Assert-Contains $stdout 'single_connection: true'
    Assert-Contains $stdout 'shared_secret_configured: true'
    Assert-Contains $stdout 'change_event: 1'
    Assert-Contains $stdout 'change_event: 2'
    Assert-Contains $stdout 'change_event: 3'
    Assert-Contains $stdout 'added_servers: ["sonic-server-192.0.2.20"]'
    Assert-Contains $stdout 'modified_servers: ["sonic-server-192.0.2.10"]'
    Assert-Contains $stdout 'removed_servers: ["sonic-server-192.0.2.20"]'

    Write-Host ''
    Write-Host 'configdb_watch stdout:' -ForegroundColor Cyan
    Write-Host $stdout
    if ($stderr) {
        Write-Host 'configdb_watch stderr:' -ForegroundColor Cyan
        Write-Host $stderr
    }
    Write-Host 'SONiC ConfigDB smoke test passed.' -ForegroundColor Green
}
finally {
    if (-not $KeepContainer) {
        & $ContainerRuntime rm --force $ContainerName 2>$null | Out-Null
    }
    if ($useUnixSocketTransport -and -not $KeepContainer) {
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $socketDir
    }
    Pop-Location
}