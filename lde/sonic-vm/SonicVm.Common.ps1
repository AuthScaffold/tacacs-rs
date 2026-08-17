Set-StrictMode -Version Latest

function Test-SonicRequiredCommand {
    param([Parameter(Mandatory)][string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name was not found in PATH."
    }
}

function Get-SonicRepoRoot {
    Resolve-Path (Join-Path $PSScriptRoot '..\..')
}

function Get-SonicVmTarget {
    param(
        [Parameter(Mandatory)][string]$User,
        [Parameter(Mandatory)][string]$HostName
    )

    "${User}@${HostName}"
}

function Get-SonicSshArguments {
    param([Parameter(Mandatory)][int]$Port)

    @(
        '-p', "$Port",
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=NUL',
        '-o', 'LogLevel=ERROR',
        '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=10'
    )
}

function Get-SonicScpArguments {
    param([Parameter(Mandatory)][int]$Port)

    @(
        '-P', "$Port",
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=NUL',
        '-o', 'LogLevel=ERROR',
        '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=10'
    )
}

function Quote-SonicShellArgument {
    param([Parameter(Mandatory)][string]$Value)

    $quote = [string][char]39
    $doubleQuote = [string][char]34
    $replacement = "$quote$doubleQuote$quote$doubleQuote$quote"
    "$quote$($Value.Replace($quote, $replacement))$quote"
}

function ConvertTo-SonicWslPath {
    param([Parameter(Mandatory)][string]$Path)

    $resolved = (Resolve-Path $Path).Path
    if ($resolved -notmatch '^([A-Za-z]):\\(.*)$') {
        throw "The script did not convert this path to WSL form: $resolved"
    }

    $drive = $Matches[1].ToLowerInvariant()
    $rest = $Matches[2] -replace '\\', '/'
    "/mnt/$drive/$rest"
}

function Get-SonicRemoteDirectory {
    param([Parameter(Mandatory)][string]$RemotePath)

    if ($RemotePath.EndsWith('/')) {
        return $RemotePath.TrimEnd('/')
    }

    $lastSlash = $RemotePath.LastIndexOf('/')
    if ($lastSlash -lt 0) {
        return '.'
    }

    if ($lastSlash -eq 0) {
        return '/'
    }

    $RemotePath.Substring(0, $lastSlash)
}

function Get-SonicRemoteDestinationPath {
    param(
        [Parameter(Mandatory)][string]$RemotePath,
        [Parameter(Mandatory)][string]$LocalPath
    )

    if (-not $RemotePath.EndsWith('/')) {
        return $RemotePath
    }

    $fileName = Split-Path $LocalPath -Leaf
    ($RemotePath.TrimEnd('/')) + '/' + $fileName
}