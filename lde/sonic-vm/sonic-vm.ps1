<#
.SYNOPSIS
    Start / manage a SONiC-VS QEMU VM with SSH access and a persistent data disk.

.DESCRIPTION
    Wraps qemu-system-x86_64 to run the SONiC virtual switch image. Boots from
    a qcow2 overlay over the read-only base image, attaches a second qcow2 disk
    for persistent user data (mounted in-guest at /data), and forwards host
    port 2222 -> guest 22 for SSH.

    Move files between Windows and the guest via scp/sftp on port 2222.

.EXAMPLE
    .\sonic-vm.ps1 -Action Up        # boot in background, wait for SSH
    .\sonic-vm.ps1 -Action InstallKey # copy your SSH public key to the guest
    .\sonic-vm.ps1 -Action Mount      # format (first time) + mount /data in guest
    .\sonic-vm.ps1 -Action Ssh       # interactive shell
    .\sonic-vm.ps1 -Action Stop
#>
[CmdletBinding()]
param(
    [ValidateSet('Start','Up','Stop','Ssh','InstallKey','CopyKey','Mount','Umount','Status',
                 'Reset','Snapshot','Restore','ListSnapshots')]
    [string]$Action = 'Up',

    [string]$QemuExe       = 'C:\Program Files\qemu\qemu-system-x86_64.exe',
    [string]$QemuImgExe    = 'C:\Program Files\qemu\qemu-img.exe',
    [string]$ImagePath     = 'X:\tacacs-rs-2\lde\sonic-vm\sonic-vs.img',
    [string]$OverlayPath   = 'X:\tacacs-rs-2\lde\sonic-vm\overlay.qcow2',
    [bool]  $UseOverlay    = $true,
    [string]$SnapshotName,
    [string]$VmName        = 'sonic-simulator_1',
    [int]   $MemoryMB      = 20480,
    [int]   $Cpus          = 10,

    [int]   $SshPort       = 2222,
    [int]   $MonitorPort   = 44001,
    [int]   $SerialPort    = 5001,

    [string]$DataDiskPath  = 'X:\tacacs-rs-2\lde\sonic-vm\data.qcow2',
    [int]   $DataDiskSizeGB = 10,
    [string]$DataMount     = '/data',
    [string]$DataLabel     = 'sonicdata',

    [string]$User          = 'admin',
    [string]$Password      = 'YourPaSsWoRd',
    [string]$PublicKeyPath,

    [switch]$Daemon
)

$ErrorActionPreference = 'Stop'

function Test-Tool($name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "Required tool '$name' not found in PATH."
    }
}

function Get-SshTarget {
    "$User@127.0.0.1"
}

function Get-KeySshArgs {
    @(
        '-p', $SshPort,
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=NUL',
        '-o', 'LogLevel=ERROR',
        '-o', 'BatchMode=yes',
        '-o', 'PreferredAuthentications=publickey',
        '-o', 'ConnectTimeout=10'
    )
}

function Get-PasswordSshArgs {
    @(
        '-p', $SshPort,
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=NUL',
        '-o', 'LogLevel=ERROR',
        '-o', 'PreferredAuthentications=password',
        '-o', 'PubkeyAuthentication=no',
        '-o', 'NumberOfPasswordPrompts=1',
        '-o', 'ConnectTimeout=10'
    )
}

function Invoke-Ssh {
    param([string]$RemoteCmd, [switch]$Interactive)
    Test-Tool ssh
    $common = Get-KeySshArgs
    $target = Get-SshTarget
    if ($Interactive -and -not $RemoteCmd) {
        & ssh @common $target
    } else {
        & ssh @common $target $RemoteCmd
    }
    if ($LASTEXITCODE -ne 0) { throw "ssh failed with exit code $LASTEXITCODE." }
}

function Invoke-PasswordSsh {
    param([string]$RemoteCmd)
    $target = Get-SshTarget
    if (Get-Command plink -ErrorAction SilentlyContinue) {
        if ($RemoteCmd) {
            & plink -ssh -P $SshPort -pw $Password -batch -o "StrictHostKeyChecking=no" "$target" $RemoteCmd
        } else {
            & plink -ssh -P $SshPort -pw $Password -batch -o "StrictHostKeyChecking=no" "$target"
        }
        if ($LASTEXITCODE -eq 0) { return }
        Write-Warning "plink password SSH failed with exit code $LASTEXITCODE; trying native ssh."
    } else {
        Test-Tool ssh
    }

    Write-Host "Enter SSH password for $target when prompted. Default password: $Password"
    $common = Get-PasswordSshArgs
    if ($RemoteCmd) {
        & ssh @common $target $RemoteCmd
    } else {
        & ssh @common $target
    }
    if ($LASTEXITCODE -ne 0) { throw "password SSH failed with exit code $LASTEXITCODE." }
}

function Test-SshKeyAuth {
    Test-Tool ssh
    $target = Get-SshTarget
    $common = Get-KeySshArgs
    & ssh @common $target 'true' 2>$null
    $LASTEXITCODE -eq 0
}

function Resolve-PublicKeyPath {
    if (-not [string]::IsNullOrWhiteSpace($PublicKeyPath)) {
        if (-not (Test-Path $PublicKeyPath)) { throw "SSH public key not found: $PublicKeyPath" }
        return (Resolve-Path $PublicKeyPath).Path
    }

    $candidates = @()
    if ($env:USERPROFILE) {
        $candidates += Join-Path $env:USERPROFILE '.ssh\id_ed25519.pub'
        $candidates += Join-Path $env:USERPROFILE '.ssh\id_rsa.pub'
        $candidates += Join-Path $env:USERPROFILE '.ssh\id_ecdsa.pub'
    }
    if ($HOME) {
        $candidates += Join-Path $HOME '.ssh\id_ed25519.pub'
        $candidates += Join-Path $HOME '.ssh\id_rsa.pub'
        $candidates += Join-Path $HOME '.ssh\id_ecdsa.pub'
    }

    $found = $candidates | Select-Object -Unique | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $found) {
        throw "No SSH public key found. Generate one with 'ssh-keygen -t ed25519' or pass -PublicKeyPath <path-to.pub>."
    }

    (Resolve-Path $found).Path
}

function Get-PublicKeyLine {
    param([Parameter(Mandatory)][string]$Path)
    $line = Get-Content -Path $Path |
        ForEach-Object { ($_ -replace "`r", '').Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -First 1

    if (-not $line) { throw "SSH public key is empty: $Path" }
    if ($line -notmatch '^(ssh-|ecdsa-sha2-|sk-ssh-|sk-ecdsa-)') {
        throw "SSH public key does not look like an OpenSSH public key: $Path"
    }

    $line
}

function Install-SshKey {
    if (Test-SshKeyAuth) {
        Write-Host "SSH key authentication already works."
        return
    }

    $keyPath = Resolve-PublicKeyPath
    $publicKey = Get-PublicKeyLine -Path $keyPath
    $keyB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($publicKey))
    $script = @"
set -e
umask 077
mkdir -p ~/.ssh
touch ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
tmp=`$(mktemp)
tr -d `$'\r' < ~/.ssh/authorized_keys > "`$tmp"
cat "`$tmp" > ~/.ssh/authorized_keys
rm -f "`$tmp"
key=`$(printf %s '$keyB64' | base64 -d | tr -d `$'\r\n')
if grep -qxF "`$key" ~/.ssh/authorized_keys; then
  echo "SSH public key already installed."
else
  printf '%s\n' "`$key" >> ~/.ssh/authorized_keys
  echo "SSH public key installed."
fi
"@

    Write-Host "Installing SSH public key from $keyPath"
    Invoke-RemoteScript -Script $script -UsePassword

    if (-not (Test-SshKeyAuth)) {
        throw "SSH key was copied, but key authentication still failed."
    }
}

function Ensure-SshKeyAuthentication {
    Install-SshKey
}

function Test-SshBanner {
    $client = $null
    $reader = $null
    try {
        $client = New-Object Net.Sockets.TcpClient
        $iar = $client.BeginConnect('127.0.0.1', $SshPort, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(1000)) { return $false }
        $client.EndConnect($iar)

        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::ASCII, $false, 256, $true)
        $banner = $reader.ReadLine()
        return $banner -like 'SSH-*'
    } catch {
        return $false
    } finally {
        if ($reader) { $reader.Dispose() }
        if ($client) { $client.Close() }
    }
}

function Wait-ForSsh {
    param([int]$TimeoutSec = 240)
    Write-Host "Waiting for SSH on 127.0.0.1:$SshPort ..."
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-QemuProc)) {
            throw "VM process exited before SSH became available. Re-run with -Action Start to see QEMU's console error output."
        }
        if (Test-SshBanner) {
            Write-Host "SSH is up."
            return
        }
        Start-Sleep -Seconds 3
        Write-Host "  ... still booting"
    }
    throw "Timed out waiting for SSH after $TimeoutSec seconds."
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-DataDisk {
    if (-not (Test-Path $QemuImgExe)) { throw "qemu-img not found at $QemuImgExe" }
    if (-not (Test-Path $DataDiskPath)) {
        Write-Host "Creating data disk $DataDiskPath ($DataDiskSizeGB GB, qcow2 thin)"
        & $QemuImgExe create -f qcow2 $DataDiskPath "${DataDiskSizeGB}G" | Out-Null
    }
}

function Ensure-BaseReadOnly {
    if (-not (Test-Path $ImagePath)) { return }
    $f = Get-Item $ImagePath
    if (-not $f.IsReadOnly) {
        Write-Host "Marking base image read-only: $ImagePath"
        $f.IsReadOnly = $true
    }
}

function Get-ImageFormat {
    param([string]$Path)
    if (-not (Test-Path $QemuImgExe)) { return 'raw' }
    $info = & $QemuImgExe info --output=json $Path 2>$null | ConvertFrom-Json
    if ($info.format) { return $info.format } else { return 'raw' }
}

function Ensure-Overlay {
    if (-not (Test-Path $QemuImgExe)) { throw "qemu-img not found at $QemuImgExe" }
    if (-not (Test-Path $ImagePath))  { throw "Base image not found at $ImagePath" }
    Ensure-BaseReadOnly
    if (-not (Test-Path $OverlayPath)) {
        $baseFmt = Get-ImageFormat -Path $ImagePath
        Write-Host "Creating overlay $OverlayPath  (backing: $ImagePath, format: $baseFmt)"
        & $QemuImgExe create -f qcow2 -F $baseFmt -b $ImagePath $OverlayPath | Out-Null
    }
}

function Get-DiskPath {
    if ($UseOverlay) { return $OverlayPath } else { return $ImagePath }
}

function Reset-Overlay {
    if (-not $UseOverlay) { throw "Reset only applies when -UseOverlay is true." }
    if (Get-QemuProc) { throw "Stop the VM before resetting the overlay." }
    if (Test-Path $OverlayPath) {
        Write-Host "Deleting $OverlayPath"
        Remove-Item -Force $OverlayPath
    }
    Ensure-Overlay
    Write-Host "Overlay reset. Next boot will be from a clean base."
}

function Snapshot-Overlay {
    if (-not $UseOverlay) { throw "Snapshots use the overlay; enable -UseOverlay." }
    if (-not $SnapshotName) { throw "Provide -SnapshotName <name>." }
    if (Get-QemuProc) { throw "Stop the VM before snapshotting the overlay." }
    if (-not (Test-Path $OverlayPath)) { throw "No overlay at $OverlayPath to snapshot." }
    $dst = Join-Path (Split-Path $OverlayPath) ("overlay.$SnapshotName.qcow2")
    Copy-Item $OverlayPath $dst -Force
    Write-Host "Snapshot saved: $dst"
}

function Restore-Snapshot {
    if (-not $UseOverlay) { throw "Snapshots use the overlay; enable -UseOverlay." }
    if (-not $SnapshotName) { throw "Provide -SnapshotName <name>." }
    if (Get-QemuProc) { throw "Stop the VM before restoring." }
    $src = Join-Path (Split-Path $OverlayPath) ("overlay.$SnapshotName.qcow2")
    if (-not (Test-Path $src)) { throw "Snapshot not found: $src" }
    Copy-Item $src $OverlayPath -Force
    Write-Host "Restored overlay from $src"
}

function List-Snapshots {
    $dir = Split-Path $OverlayPath
    Get-ChildItem -Path $dir -Filter 'overlay.*.qcow2' -ErrorAction SilentlyContinue |
        Select-Object @{n='Name';e={ ($_.BaseName -replace '^overlay\.','') }},
                      @{n='SizeMB';e={[math]::Round($_.Length/1MB,2)}},
                      LastWriteTime, FullName |
        Format-Table -AutoSize
}

function Get-QemuProc {
    Get-CimInstance Win32_Process -Filter "Name='qemu-system-x86_64.exe'" |
        Where-Object { $_.CommandLine -match [regex]::Escape("-name $VmName") }
}

function Start-Vm {
    if (-not (Test-Path $QemuExe))   { throw "QEMU not found at $QemuExe" }
    if (-not (Test-Path $ImagePath)) { throw "Image not found at $ImagePath" }

    if (Get-QemuProc) {
        Write-Host "VM '$VmName' already running."
        return
    }

    if ($UseOverlay) { Ensure-Overlay }
    Ensure-DataDisk
    $disk = Get-DiskPath
    $diskFmt = if ($UseOverlay) { 'qcow2' } else { Get-ImageFormat -Path $disk }

    $netdev = "user,id=net0,hostfwd=tcp::${SshPort}-:22"
    $qemuArgs = @(
        '-name', $VmName,
        '-m', "${MemoryMB}M",
        '-smp', "cpus=$Cpus",
        '-drive', "file=$disk,format=$diskFmt,index=0,media=disk,id=drive0",
        '-drive', "file=$DataDiskPath,format=qcow2,index=1,media=disk,id=datadisk0",
        '-serial', "telnet:127.0.0.1:${SerialPort},server,nowait",
        '-monitor', "tcp:127.0.0.1:${MonitorPort},server,nowait",
        '-display', 'none',
        '-device', 'e1000,netdev=net0',
        '-netdev', $netdev
    )

    Write-Host "Starting VM (root: $disk, data: $DataDiskPath)"
    Write-Host "  $QemuExe $($qemuArgs -join ' ')"

    if ($Daemon) {
        $process = Start-Process -FilePath $QemuExe -ArgumentList $qemuArgs -WindowStyle Minimized -PassThru
        if ($process.WaitForExit(1000)) {
            throw "QEMU exited immediately with code $($process.ExitCode). Re-run with -Action Start to see QEMU's console error output."
        }
        Write-Host "VM launched in background."
    } else {
        & $QemuExe @qemuArgs
        if ($LASTEXITCODE -ne 0) { throw "QEMU exited with code $LASTEXITCODE." }
    }
}

function Stop-Vm {
    $p = Get-QemuProc
    if (-not $p) { Write-Host "VM '$VmName' is not running."; return }
    # Try graceful shutdown via QEMU monitor
    try {
        $tcp = New-Object Net.Sockets.TcpClient('127.0.0.1', $MonitorPort)
        $stream = $tcp.GetStream()
        $writer = New-Object IO.StreamWriter($stream)
        $writer.NewLine = "`n"; $writer.AutoFlush = $true
        $writer.WriteLine('system_powerdown')
        Start-Sleep -Seconds 5
        $writer.WriteLine('quit')
        Start-Sleep -Seconds 2
        $tcp.Close()
    } catch {
        Write-Warning "Monitor shutdown failed: $_  -- killing process."
    }
    Start-Sleep -Seconds 2
    $p = Get-QemuProc
    if ($p) { Stop-Process -Id $p.ProcessId -Force; Write-Host "VM force-killed." }
    else    { Write-Host "VM stopped." }
}

function Invoke-RemoteScript {
    param([string]$Script, [switch]$UsePassword)
    $normalized = $Script -replace "`r`n", "`n"
    $bytes = [Text.Encoding]::UTF8.GetBytes($normalized)
    $b64   = [Convert]::ToBase64String($bytes)
    $remoteCmd = "printf %s $b64 | base64 -d | bash -s"
    if ($UsePassword) {
        Invoke-PasswordSsh -RemoteCmd $remoteCmd
    } else {
        Invoke-Ssh -RemoteCmd $remoteCmd
    }
}

function Mount-DataDisk {
    $expectedSizeBytes = [int64]$DataDiskSizeGB * 1GB
    $script = @"
set -e
PATH=/usr/sbin:/sbin:/usr/bin:/bin:`$PATH
DATA_LABEL='$DataLabel'
DATA_MOUNT='$DataMount'
EXPECTED_SIZE_BYTES='$expectedSizeBytes'

find_by_label() {
    blkid -L "`$DATA_LABEL" 2>/dev/null || true
}

find_blank_data_disk() {
    for candidate in /dev/disk/by-id/*"`$DATA_LABEL"* /dev/vd? /dev/sd?; do
        [ -e "`$candidate" ] || continue
        real=`$(readlink -f "`$candidate")
        [ -b "`$real" ] || continue
        [ "`$(lsblk -dn -o TYPE "`$real" 2>/dev/null)" = "disk" ] || continue
        size=`$(lsblk -b -dn -o SIZE "`$real" 2>/dev/null | tr -d ' ')
        [ "`$size" = "`$EXPECTED_SIZE_BYTES" ] || continue
        if lsblk -nr -o TYPE "`$real" | tail -n +2 | grep -q '^part`$'; then
            continue
        fi
        if lsblk -nr -o MOUNTPOINT "`$real" | grep -q '[^[:space:]]'; then
            continue
        fi
        if blkid "`$real" >/dev/null 2>&1; then
            continue
        fi
        echo "`$real"
        return 0
    done
    return 1
}

find_existing_data_filesystem() {
    for candidate in /dev/vd? /dev/sd?; do
        [ -e "`$candidate" ] || continue
        real=`$(readlink -f "`$candidate")
        [ -b "`$real" ] || continue
        [ "`$(lsblk -dn -o TYPE "`$real" 2>/dev/null)" = "disk" ] || continue
        size=`$(lsblk -b -dn -o SIZE "`$real" 2>/dev/null | tr -d ' ')
        [ "`$size" = "`$EXPECTED_SIZE_BYTES" ] || continue

        while read -r path type fstype mountpoint; do
            [ "`$type" = "part" ] || [ "`$type" = "disk" ] || continue
            [ "`$fstype" = "ext4" ] || continue
            [ -z "`$mountpoint" ] || [ "`$mountpoint" = "`$DATA_MOUNT" ] || continue
            echo "`$path"
            return 0
        done <<EOF
`$(lsblk -nrpo NAME,TYPE,FSTYPE,MOUNTPOINT "`$real")
EOF
    done
    return 1
}

set_ext4_label() {
    device="`$1"
    label="`$2"
    current_label=`$(blkid -s LABEL -o value "`$device" 2>/dev/null || true)
    [ "`$current_label" = "`$label" ] && return 0

    echo "Relabeling `$device from '`$current_label' to '`$label'"
    if command -v e2label >/dev/null 2>&1; then
        sudo e2label "`$device" "`$label"
    else
        sudo tune2fs -L "`$label" "`$device"
    fi
}

CAND=`$(find_by_label)
if [ -n "`$CAND" ]; then
    echo "Found data disk by label `$DATA_LABEL: `$CAND"
else
    CAND=`$(find_existing_data_filesystem || true)
    if [ -n "`$CAND" ]; then
        echo "Found existing data filesystem at `$CAND"
        set_ext4_label "`$CAND" "`$DATA_LABEL"
    fi
fi

if [ -z "`$CAND" ]; then
    CAND=`$(find_blank_data_disk || true)
    if [ -z "`$CAND" ]; then
        echo "no data disk found with label `$DATA_LABEL or blank size `$EXPECTED_SIZE_BYTES bytes" >&2
        echo "available block devices:" >&2
        lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT >&2
        exit 1
    fi
    echo "Using `$CAND as blank data disk"
    echo "Formatting `$CAND as ext4 (label: `$DATA_LABEL)"
    sudo mkfs.ext4 -F -L "`$DATA_LABEL" "`$CAND"
fi

sudo mkdir -p "`$DATA_MOUNT"
if mountpoint -q "`$DATA_MOUNT"; then
    echo "Already mounted at `$DATA_MOUNT"
else
    sudo mount "`$CAND" "`$DATA_MOUNT"
    sudo chown `$(id -u):`$(id -g) "`$DATA_MOUNT"
fi

# Persistent fstab entry (by label so device name doesn't matter)
if grep -Eq "[[:space:]]`$DATA_MOUNT[[:space:]]" /etc/fstab; then
    echo "Updating fstab entry"
    sudo sed -i "\|[[:space:]]`$DATA_MOUNT[[:space:]]|c\LABEL=`$DATA_LABEL  `$DATA_MOUNT  ext4  defaults,nofail  0  2" /etc/fstab
elif ! grep -q "LABEL=`$DATA_LABEL" /etc/fstab; then
    echo "Adding fstab entry"
    echo "LABEL=`$DATA_LABEL  `$DATA_MOUNT  ext4  defaults,nofail  0  2" | sudo tee -a /etc/fstab >/dev/null
fi

df -h "`$DATA_MOUNT"
"@
    Invoke-RemoteScript -Script $script
}

function Umount-DataDisk {
    Invoke-RemoteScript -Script "sudo umount $DataMount && echo unmounted"
}

function Show-Status {
    $p = Get-QemuProc
    if ($p) {
        Write-Host "VM '$VmName' running (PID $($p.ProcessId))"
    } else {
        Write-Host "VM '$VmName' not running"
    }
    $share = $null
    Write-Host "SSH:     ssh -p $SshPort $User@127.0.0.1   (password: $Password)"
    Write-Host "Serial:  telnet 127.0.0.1 $SerialPort"
    Write-Host "Monitor: tcp 127.0.0.1 $MonitorPort"
    Write-Host "Root:    $(Get-DiskPath)  (overlay=$UseOverlay)"
    if ($UseOverlay -and (Test-Path $OverlayPath)) {
        $sz = [math]::Round((Get-Item $OverlayPath).Length / 1MB, 2)
        Write-Host "Overlay: $sz MB  (base: $ImagePath)"
    }
    if (Test-Path $DataDiskPath) {
        $sz = [math]::Round((Get-Item $DataDiskPath).Length / 1MB, 2)
        Write-Host "Data:    $DataDiskPath  ($sz MB on disk, ${DataDiskSizeGB} GB virtual) -> mounts at $DataMount"
    } else {
        Write-Host "Data:    $DataDiskPath  (not yet created; will be ${DataDiskSizeGB} GB on first boot)"
    }
}

switch ($Action) {
    'Start'         { Start-Vm }
    'Stop'          { Stop-Vm }
    'Ssh'           { Ensure-SshKeyAuthentication; Invoke-Ssh -Interactive }
    'InstallKey'    { Ensure-SshKeyAuthentication }
    'CopyKey'       { Ensure-SshKeyAuthentication }
    'Mount'         { Ensure-SshKeyAuthentication; Mount-DataDisk }
    'Umount'        { Umount-DataDisk }
    'Status'        { Show-Status }
    'Reset'         { Reset-Overlay }
    'Snapshot'      { Snapshot-Overlay }
    'Restore'       { Restore-Snapshot }
    'ListSnapshots' { List-Snapshots }
    'Up' {
        $Daemon = $true
        Start-Vm
        Wait-ForSsh
        Ensure-SshKeyAuthentication
        Mount-DataDisk
        Show-Status
        Write-Host "`nReady. '.\sonic-vm.ps1 -Action Ssh' to log in. Persistent storage at $DataMount."
    }
}
