<#
.SYNOPSIS
    Runs TACACS+ management regression tests without a SONiC VM.
.DESCRIPTION
    Requires PowerShell 7, Bash, and Python 3.
    Replaces SSH with a local Bash runner and temporary SONiC command fixtures.
    The tests do not change guest configuration or VM lifecycle state.
.EXAMPLE
    pwsh -NoLogo -NoProfile -File ./lde/sonic-vm/Test-SonicTacacsManagement.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
. $PSScriptRoot\SonicVm.Common.ps1

Test-SonicRequiredCommand bash
Test-SonicRequiredCommand python3

$manager = Join-Path $PSScriptRoot 'sonic-vm.ps1'
$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) "sonic-tacacs-tests-$([Guid]::NewGuid().ToString('N'))"
$originalPath = $env:PATH
$originalStatePath = $env:SONIC_TACACS_TEST_STATE
$testContext = @{
    assertions = 0
    sshCalls = 0
    sshArguments = @()
    sshFailure = $false
    sshOutput = ''
    enableWarningBeforeSsh = $false
}

function Assert-True {
    param([bool]$Condition, [string]$Message)

    $testContext.assertions++
    if (-not $Condition) { throw $Message }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)

    Assert-True ($Actual -ceq $Expected) $Message
}

function Reset-State {
    param([hashtable]$Overrides = @{})

    $state = @{
        servers = @{}
        global = @{ passkey = 'fixture-global-key'; timeout = '5'; auth_type = 'pap' }
        aaa = @{
            authentication = @{ login = 'local'; failthrough = 'True' }
            authorization = @{ login = 'tacacs+,local' }
            accounting = @{ login = 'tacacs+' }
        }
        calls = @()
        failure = ''
        noop = ''
    }
    foreach ($key in $Overrides.Keys) { $state[$key] = $Overrides[$key] }
    $state | ConvertTo-Json -Depth 20 | Set-Content -Path $env:SONIC_TACACS_TEST_STATE -Encoding utf8
    $testContext.sshFailure = $false
    $testContext.sshOutput = ''
}

function Read-State {
    Get-Content -Raw $env:SONIC_TACACS_TEST_STATE | ConvertFrom-Json -AsHashtable
}

function Get-ConfigCalls {
    ,@((Read-State).calls | Where-Object { $_.tool -eq 'config' })
}

function ssh {
    $testContext.sshCalls++
    $testContext.sshArguments = @($args)
    $text = @($input) -join "`n"
    Assert-Equal $args[-1] 'bash -s' 'SSH must use a fixed remote command.'
    Assert-True (-not $text.Contains("`r")) 'The guest script must use LF line endings.'
    $scriptPath = Join-Path $temporaryDirectory 'guest.sh'
    [IO.File]::WriteAllText($scriptPath, $text)
    & bash -n $scriptPath
    Assert-Equal $LASTEXITCODE 0 'The generated guest script must pass bash -n.'
    if ($testContext.sshFailure) {
        $global:LASTEXITCODE = 255
        Write-Output 'Fixture SSH connection failed.'
        return
    }
    if ($testContext.sshOutput) { Write-Output $testContext.sshOutput }
    $text | & bash -s 2>&1
    $global:LASTEXITCODE = $LASTEXITCODE
}

function Invoke-Management {
    param([hashtable]$Parameters)

    $testContext.sshCalls = 0
    $testContext.sshArguments = @()
    $testContext.enableWarningBeforeSsh = $false
    $records = [Collections.Generic.List[string]]::new()
    $errorText = ''
    try {
        & $manager @Parameters *>&1 | ForEach-Object {
            $text = $_.ToString()
            $records.Add($text)
            if ($text.Contains('Keep a working session')) {
                $testContext.enableWarningBeforeSsh = $testContext.sshCalls -eq 0
            }
        }
    } catch {
        $errorText = $_.Exception.Message
    }
    @{
        output = $records -join "`n"
        error = $errorText
    }
}

function Assert-Success {
    param([hashtable]$Result)

    Assert-Equal $Result.error '' "The management action failed: $($Result.error)"
    Assert-Equal $testContext.sshCalls 1 'The action must use one SSH call, without key installation or lifecycle operations.'
}

$fixture = @'
import json
import os
import subprocess
import sys

path = os.environ["SONIC_TACACS_TEST_STATE"]
with open(path, encoding="utf-8-sig") as source:
    state = json.load(source)
tool, *args = sys.argv[1:]
state["calls"].append({"tool": tool, "args": args})

def save():
    with open(path, "w", encoding="utf-8") as destination:
        json.dump(state, destination)

save()
if state["failure"] == tool:
    print("Fixture " + tool + " failed.", file=sys.stderr)
    sys.exit(12)

if tool == "sudo":
    assert args.pop(0) == "-n"
    sys.exit(subprocess.run(args, check=False).returncode)

if tool == "redis-cli":
    assert args[:4] == ["--raw", "-e", "-n", "4"]
    args = args[4:]
    if args[0] == "--scan":
        assert args[1:] == ["--pattern", "TACPLUS_SERVER|*"]
        for server in sorted(state["servers"]):
            print("TACPLUS_SERVER|" + server)
    elif args[0] == "EXISTS":
        server = args[1].removeprefix("TACPLUS_SERVER|")
        print(int(server in state["servers"]))
    elif args[0] == "HGET":
        key, field = args[1:]
        if key.startswith("TACPLUS_SERVER|"):
            row = state["servers"].get(key.split("|", 1)[1], {})
        else:
            assert key == "AAA|authentication"
            row = state["aaa"]["authentication"]
        print(row.get(field, ""))
    else:
        raise AssertionError("Unexpected Redis operation")
    sys.exit(0)

assert tool == "config"
operation = args[1] if args[0] == "tacacs" else args[0]
if state["failure"] == operation:
    print("Fixture config failed: " + repr(args), file=sys.stderr)
    sys.exit(17)
if state["noop"] == operation:
    sys.exit(0)
if args[:2] == ["tacacs", "add"]:
    server = args[-1]
    if server in state["servers"]:
        print("server already exists")
        sys.exit(0)
    fields = {"-o": "tcp_port", "-p": "priority", "-t": "timeout", "-k": "passkey"}
    row = {}
    for index in range(2, len(args) - 1, 2):
        row[fields[args[index]]] = args[index + 1]
    state["servers"][server] = row
elif args[:2] == ["tacacs", "delete"]:
    del state["servers"][args[2]]
elif args[:3] == ["aaa", "authentication", "login"]:
    assert len(args) == 4
    state["aaa"]["authentication"]["login"] = args[3]
elif args == ["save", "-y"]:
    state["saved"] = True
else:
    raise AssertionError("Unexpected configuration operation")
save()
'@

try {
    [IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null
    $env:SONIC_TACACS_TEST_STATE = Join-Path $temporaryDirectory 'state.json'
    $fixturePath = Join-Path $temporaryDirectory 'fixture.py'
    [IO.File]::WriteAllText($fixturePath, $fixture)
    foreach ($tool in @('sudo', 'redis-cli', 'config')) {
        $toolPath = Join-Path $temporaryDirectory $tool
        $wrapper = "#!/usr/bin/env bash`nexec python3 $(Quote-SonicShellArgument $fixturePath) $tool `"`$@`"`n"
        [IO.File]::WriteAllText($toolPath, $wrapper)
        & bash -c 'chmod +x "$1"' fixture $toolPath
        if ($LASTEXITCODE -ne 0) { throw "Cannot prepare fixture: $tool" }
    }
    $env:PATH = $temporaryDirectory + [IO.Path]::PathSeparator + $originalPath

    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($manager, [ref]$tokens, [ref]$errors)
    Assert-Equal $errors.Count 0 'The VM manager must parse without errors.'
    $actionParameter = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Action' }
    Assert-Equal $actionParameter.DefaultValue.Value 'Up' 'The default lifecycle action must remain Up.'
    $actionValidation = $actionParameter.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' }
    foreach ($oldAction in @('Start','Up','Stop','Ssh','InstallKey','CopyKey','Mount','Umount','Status',
                            'Reset','Snapshot','Restore','ListSnapshots')) {
        Assert-True ($oldAction -in $actionValidation.PositionalArguments.Value) "The action $oldAction must remain accepted."
    }

    Reset-State
    $result = Invoke-Management @{ Action = 'AddTacacsServer' }
    Assert-Success $result
    $state = Read-State
    Assert-Equal $state.servers['10.0.2.2'].tcp_port '49' 'Add must default to the QEMU host on TCP port 49.'
    Assert-Equal $state.servers['10.0.2.2'].priority '1' 'The default priority must be 1.'
    Assert-True (-not $state.servers['10.0.2.2'].ContainsKey('timeout')) 'An omitted timeout must retain native inheritance.'
    Assert-True (-not $state.servers['10.0.2.2'].ContainsKey('passkey')) 'An omitted passkey must retain native inheritance.'
    Assert-True (-not $state.ContainsKey('saved')) 'The default action must not save the running configuration.'
    Assert-True ($result.output.Contains('10.0.2.2')) 'The output must show the selected host address.'
    Assert-Equal ((Get-ConfigCalls)[0].args -join '|') 'tacacs|add|-o|49|-p|1|10.0.2.2' 'Add must use the native TCP command.'
    Assert-Equal $state.aaa.authentication.login 'local' 'Add must not enable TACACS+ login.'

    $result = Invoke-Management @{ Action = 'RemoveTacacsServer' }
    Assert-Success $result
    Assert-Equal (Read-State).servers.Count 0 'Remove must default to the same QEMU host address.'
    Assert-True (-not $result.output.Contains('final server')) 'Removing the final server with local login must not warn about TACACS+ login.'
    Assert-Equal ((Get-ConfigCalls)[-1].args -join '|') 'tacacs|delete|10.0.2.2' 'Remove must use the native delete command.'

    foreach ($server in @('192.0.2.10', '2001:db8::10')) {
        Reset-State
        $result = Invoke-Management @{
            Action = 'AddTacacsServer'; TacacsServer = $server; TacacsPort = 4949
            TacacsPriority = 64; TacacsTimeoutSeconds = 60; SshPort = 2223; User = 'operator'
        }
        Assert-Success $result
        $state = Read-State
        Assert-Equal $state.servers[$server].tcp_port '4949' 'An explicit TCP port must override the default.'
        Assert-Equal $state.servers[$server].priority '64' 'The requested priority must take effect.'
        Assert-Equal $state.servers[$server].timeout '60' 'The requested timeout must take effect.'
        Assert-True ('2223' -in $testContext.sshArguments) 'SSH must use the requested SSH port.'
        Assert-True ('operator@127.0.0.1' -in $testContext.sshArguments) 'SSH must use the requested user.'
        Assert-True ('BatchMode=yes' -in $testContext.sshArguments) 'SSH must use key authentication.'
        Assert-True ('PreferredAuthentications=publickey' -in $testContext.sshArguments) 'SSH must not use password authentication.'
        $result = Invoke-Management @{ Action = 'RemoveTacacsServer'; TacacsServer = $server }
        Assert-Success $result
        Assert-Equal (Read-State).servers.Count 0 'An explicit address must also override the remove default.'
    }

    Reset-State
    $result = Invoke-Management @{ Action = 'addtacacsserver'; TacacsPort = 1; TacacsPriority = 1; TacacsTimeoutSeconds = 1 }
    Assert-Success $result
    Assert-Equal (Read-State).servers['10.0.2.2'].tcp_port '1' 'The minimum TCP port must be accepted.'
    Assert-Equal (Read-State).servers['10.0.2.2'].timeout '1' 'The minimum timeout must be accepted.'
    Reset-State
    $result = Invoke-Management @{ Action = 'AddTacacsServer'; TacacsPort = 65535 }
    Assert-Success $result
    Assert-Equal (Read-State).servers['10.0.2.2'].tcp_port '65535' 'The maximum TCP port must be accepted.'

    foreach ($action in @('AddTacacsServer', 'RemoveTacacsServer')) {
        foreach ($address in @('', ' ', 'not-an-address', '192.0.2.10;id', 'fe80::1%eth0')) {
            $result = Invoke-Management @{ Action = $action; TacacsServer = $address }
            Assert-True ($result.error.Length -gt 0) 'Invalid addresses must fail.'
            Assert-Equal $testContext.sshCalls 0 'Invalid addresses must fail before SSH.'
        }
    }
    foreach ($parameter in @('TacacsPort', 'TacacsPriority', 'TacacsTimeoutSeconds')) {
        $maximum = @{ TacacsPort = 65535; TacacsPriority = 64; TacacsTimeoutSeconds = 60 }[$parameter]
        foreach ($value in @(0, -1, ($maximum + 1))) {
            $parameters = @{ Action = 'AddTacacsServer'; $parameter = $value }
            $result = Invoke-Management $parameters
            Assert-True ($result.error.Length -gt 0) 'Out-of-range parameters must fail.'
            Assert-Equal $testContext.sshCalls 0 'Out-of-range parameters must fail before SSH.'
        }
    }
    $result = Invoke-Management @{ Action = 'DisableTacacs'; TacacsPort = 49 }
    Assert-True ($result.error.Contains('applies only')) 'Add-only parameters must not be silently ignored.'
    $result = Invoke-Management @{ Action = 'EnableTacacs'; TacacsServer = '192.0.2.10' }
    Assert-True ($result.error.Contains('applies only')) 'Authentication actions must not silently ignore server addresses.'

    $secret = 'fixture-$;''"\`&|()<>key'
    $secureSecret = ConvertTo-SecureString $secret -AsPlainText -Force
    Reset-State
    $testContext.sshOutput = "Fixture SSH diagnostic: $secret"
    $result = Invoke-Management @{ Action = 'AddTacacsServer'; TacacsPasskey = $secureSecret }
    Assert-Success $result
    Assert-Equal (Read-State).servers['10.0.2.2'].passkey $secret 'Supported shell metacharacters must survive secret transport.'
    Assert-True (-not $result.output.Contains($secret)) 'Output must redact the shared secret.'
    Assert-True ($result.output.Contains('[REDACTED]')) 'SSH diagnostics must redact the shared secret.'
    Assert-True (-not ($testContext.sshArguments -join ' ').Contains($secret)) 'SSH command arguments must not contain the shared secret.'
    foreach ($invalidSecret in @('', 'has space', 'has#hash', 'has,comma', "has`nnewline", "trailing`n", ([string][char]233), ('a' * 257))) {
        $secureInvalid = [Security.SecureString]::new()
        foreach ($character in $invalidSecret.ToCharArray()) { $secureInvalid.AppendChar($character) }
        $result = Invoke-Management @{ Action = 'AddTacacsServer'; TacacsPasskey = $secureInvalid }
        Assert-True ($result.error.Contains('passkey must contain')) 'Unsupported passkeys must fail with a constraint error.'
        Assert-Equal $testContext.sshCalls 0 'Unsupported passkeys must fail before SSH.'
        if ($invalidSecret.Length -gt 0) {
            Assert-True (-not $result.error.Contains($invalidSecret)) 'Passkey validation errors must not contain the secret.'
        }
        $secureInvalid.Dispose()
    }
    Reset-State
    $maximumSecret = ConvertTo-SecureString ('a' * 256) -AsPlainText -Force
    $result = Invoke-Management @{ Action = 'AddTacacsServer'; TacacsPasskey = $maximumSecret }
    Assert-Success $result
    Assert-Equal (Read-State).servers['10.0.2.2'].passkey.Length 256 'A passkey at the exact maximum length must be accepted.'
    $maximumSecret.Dispose()

    Reset-State
    $result = Invoke-Management @{ Action = 'AddTacacsServer' }
    Assert-Success $result
    $result = Invoke-Management @{ Action = 'AddTacacsServer'; TacacsPort = 5000; SaveConfig = $true }
    Assert-True ($result.error.Length -gt 0 -and $result.output.Contains('already exists')) 'Duplicate adds must report an error.'
    Assert-Equal (Get-ConfigCalls).Count 1 'Duplicate adds must not change or save the entry.'
    Assert-Equal (Read-State).servers['10.0.2.2'].tcp_port '49' 'Duplicate adds must preserve the existing configuration.'
    Reset-State
    $result = Invoke-Management @{ Action = 'RemoveTacacsServer'; SaveConfig = $true }
    Assert-True ($result.error.Length -gt 0 -and $result.output.Contains('does not exist')) 'Missing removals must report an error.'
    Assert-Equal (Get-ConfigCalls).Count 0 'Missing removals must not mutate or save the configuration.'

    Reset-State @{ servers = @{ '10.0.2.2' = @{ tcp_port = '49'; priority = '1' } } }
    $original = Read-State
    foreach ($action in @('EnableTacacs', 'EnableTacacs', 'DisableTacacs', 'DisableTacacs')) {
        $result = Invoke-Management @{ Action = $action }
        Assert-Success $result
        $state = Read-State
        $expected = if ($action -eq 'EnableTacacs') { 'tacacs+' } else { 'local' }
        if ($action -eq 'EnableTacacs') {
            Assert-True $testContext.enableWarningBeforeSsh 'The lockout warning must precede the SSH operation.'
        }
        Assert-Equal $state.aaa.authentication.login $expected 'Enable and disable must select the exact requested login method.'
        Assert-Equal ($state.servers | ConvertTo-Json -Compress) ($original.servers | ConvertTo-Json -Compress) 'Authentication changes must preserve server entries.'
        Assert-Equal $state.aaa.authentication.failthrough $original.aaa.authentication.failthrough 'Authentication changes must preserve failthrough.'
        Assert-Equal ($state.aaa.authorization | ConvertTo-Json -Compress) ($original.aaa.authorization | ConvertTo-Json -Compress) 'Authentication changes must preserve authorization.'
        Assert-Equal ($state.aaa.accounting | ConvertTo-Json -Compress) ($original.aaa.accounting | ConvertTo-Json -Compress) 'Authentication changes must preserve accounting.'
        Assert-Equal ((Get-ConfigCalls)[-1].args -join '|') "aaa|authentication|login|$expected" 'Authentication changes must use the native login command.'
    }
    Reset-State
    $result = Invoke-Management @{ Action = 'EnableTacacs' }
    Assert-Success $result
    Assert-True ($result.output.Contains('No TACACS+ servers')) 'Enable must warn about an empty server list.'
    Assert-True ($result.output.Contains('Keep a working session')) 'Enable must warn about TACACS-only login.'
    Assert-Equal (Read-State).aaa.authentication.login 'tacacs+' 'An empty server list must not block enable.'
    $result = Invoke-Management @{ Action = 'AddTacacsServer' }
    Assert-Success $result
    $result = Invoke-Management @{ Action = 'RemoveTacacsServer' }
    Assert-Success $result
    Assert-True ($result.output.Contains('final server')) 'Removing the final active server must warn.'
    Assert-Equal (Read-State).servers.Count 0 'The warning must not block removal of the final server.'
    Reset-State @{
        servers = @{
            '10.0.2.2' = @{ tcp_port = '49'; priority = '1' }
            '192.0.2.10' = @{ tcp_port = '49'; priority = '1' }
        }
        aaa = @{ authentication = @{ login = 'tacacs+,local' } }
    }
    $result = Invoke-Management @{ Action = 'RemoveTacacsServer' }
    Assert-Success $result
    Assert-True (-not $result.output.Contains('final server')) 'Removing a non-final server must not warn.'
    $result = Invoke-Management @{ Action = 'RemoveTacacsServer'; TacacsServer = '192.0.2.10' }
    Assert-Success $result
    Assert-True ($result.output.Contains('final server')) 'The final-server warning must also cover TACACS+ with local fallback.'

    foreach ($action in @('AddTacacsServer', 'RemoveTacacsServer', 'EnableTacacs', 'DisableTacacs')) {
        Reset-State
        if ($action -eq 'RemoveTacacsServer') {
            $result = Invoke-Management @{ Action = 'AddTacacsServer' }
            Assert-Success $result
        }
        $result = Invoke-Management @{ Action = $action; SaveConfig = $true }
        Assert-Success $result
        $state = Read-State
        Assert-True $state.saved 'SaveConfig must save the running configuration.'
        Assert-Equal ($state.calls[-1].args -join '|') 'save|-y' 'Save must follow all mutation and verification commands.'
    }

    foreach ($case in @(
        @{ action = 'AddTacacsServer'; operation = 'add' },
        @{ action = 'RemoveTacacsServer'; operation = 'delete' },
        @{ action = 'EnableTacacs'; operation = 'aaa' },
        @{ action = 'DisableTacacs'; operation = 'aaa' }
    )) {
        $servers = if ($case.action -eq 'RemoveTacacsServer') {
            @{ '10.0.2.2' = @{ tcp_port = '49'; priority = '1' } }
        } else { @{} }
        $aaa = @{
            authentication = @{ login = $(if ($case.action -eq 'DisableTacacs') { 'tacacs+' } else { 'local' }); failthrough = 'True' }
            authorization = @{ login = 'local' }; accounting = @{ login = 'local' }
        }
        Reset-State @{ servers = $servers; aaa = $aaa; noop = $case.operation }
        $result = Invoke-Management @{ Action = $case.action; SaveConfig = $true }
        Assert-True ($result.error.Length -gt 0) 'A zero-exit native no-op must fail result verification.'
        Assert-True (-not (Read-State).ContainsKey('saved')) 'Failed verification must prevent saving.'
        Reset-State @{ servers = $servers; aaa = $aaa; failure = $case.operation }
        $result = Invoke-Management @{ Action = $case.action; SaveConfig = $true }
        Assert-True ($result.error.Length -gt 0 -and $result.output.Contains('exit code 17')) 'Native CLI errors must propagate.'
        Assert-True (-not (Read-State).ContainsKey('saved')) 'Native CLI errors must prevent saving.'
    }
    foreach ($failure in @('sudo', 'redis-cli')) {
        Reset-State @{ failure = $failure }
        $result = Invoke-Management @{ Action = 'AddTacacsServer'; SaveConfig = $true }
        Assert-True ($result.error.Length -gt 0) 'Sudo and CONFIG_DB errors must propagate.'
        Assert-Equal (Get-ConfigCalls).Count 0 'Sudo and CONFIG_DB errors must prevent mutation and saving.'
    }
    Reset-State @{ failure = 'add' }
    $result = Invoke-Management @{ Action = 'AddTacacsServer'; TacacsPasskey = $secureSecret }
    Assert-True ($result.error.Length -gt 0) 'A secret-bearing native CLI failure must propagate.'
    Assert-True (-not ($result.output + $result.error).Contains($secret)) 'CLI diagnostics must not expose the passkey.'
    Reset-State @{ failure = 'save' }
    $result = Invoke-Management @{ Action = 'AddTacacsServer'; SaveConfig = $true }
    Assert-True ($result.error.Length -gt 0 -and $result.output.Contains('running change is active')) 'Save errors must explain that the running change remains active.'
    Assert-True ((Read-State).servers.ContainsKey('10.0.2.2')) 'A save error must not pretend to undo the running change.'
    Reset-State
    $testContext.sshFailure = $true
    $result = Invoke-Management @{ Action = 'AddTacacsServer' }
    Assert-True ($result.error.Contains('exit code 255')) 'SSH connection errors must propagate.'
    Assert-Equal (Get-ConfigCalls).Count 0 'SSH errors must not mutate guest state.'

    Write-Host "PASS: $($testContext.assertions) TACACS+ management assertions passed."
} finally {
    $env:PATH = $originalPath
    $env:SONIC_TACACS_TEST_STATE = $originalStatePath
    if (Test-Path $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
