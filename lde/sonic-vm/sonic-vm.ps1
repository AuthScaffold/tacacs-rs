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
    .\sonic-vm.ps1 -Action Mount     # format (first time) + mount /data in guest
    .\sonic-vm.ps1 -Action Ssh       # interactive shell
    .\sonic-vm.ps1 -Action Stop
#>
[CmdletBinding()]
param(
    [ValidateSet('Start','Up','Stop','Ssh','Mount','Umount','Status',
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

    [switch]$Daemon
)

$ErrorActionPreference = 'Stop'

function Test-Tool($name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "Required tool '$name' not found in PATH."
    }
}

function Invoke-Ssh {
    param([string]$RemoteCmd, [switch]$Interactive)
    Test-Tool ssh
    $common = @(
        '-p', $SshPort,
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=NUL',
        '-o', 'LogLevel=ERROR',
        '-o', 'PreferredAuthentications=password',
        '-o', 'PubkeyAuthentication=no',
        '-o', 'NumberOfPasswordPrompts=1'
    )
    $target = "$User@127.0.0.1"
    if ($Interactive -and -not $RemoteCmd) {
        # Try passwordless first via sshpass-like helper if present, else just ssh
        if (Get-Command plink -ErrorAction SilentlyContinue) {
            & plink -ssh -P $SshPort -pw $Password -batch -o "StrictHostKeyChecking=no" "$target"
        } else {
            Write-Host "Password: $Password"
            & ssh @common $target
        }
    } else {
        if (Get-Command plink -ErrorAction SilentlyContinue) {
            & plink -ssh -P $SshPort -pw $Password -batch -o "StrictHostKeyChecking=no" "$target" $RemoteCmd
        } else {
            Write-Host "Password: $Password"
            & ssh @common $target $RemoteCmd
        }
    }
}

function Wait-ForSsh {
    param([int]$TimeoutSec = 240)
    Write-Host "Waiting for SSH on 127.0.0.1:$SshPort ..."
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $c = New-Object Net.Sockets.TcpClient
            $iar = $c.BeginConnect('127.0.0.1', $SshPort, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1000) -and $c.Connected) {
                $c.Close()
                # Also wait for SSH banner
                Start-Sleep -Seconds 3
                Write-Host "SSH is up."
                return $true
            }
            $c.Close()
        } catch { }
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
        Start-Process -FilePath $QemuExe -ArgumentList $qemuArgs -WindowStyle Minimized | Out-Null
        Write-Host "VM launched in background."
    } else {
        & $QemuExe @qemuArgs
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
    param([string]$Script)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Script)
    $b64   = [Convert]::ToBase64String($bytes)
    Invoke-Ssh -RemoteCmd "echo $b64 | base64 -d | bash -s"
}

function Mount-DataDisk {
    $script = @"
set -e
# Find the data disk: it's the block device whose backing file matches our qcow2,
# but from the guest's POV it's just the second IDE/SATA disk. Look for an
# unmounted disk that isn't the root device.
ROOT_DEV=`$(findmnt -no SOURCE / | sed 's/[0-9]*`$//')
CAND=""
for d in /dev/sd? /dev/vd?; do
  [ -b "`$d" ] || continue
  [ "`$d" = "`$ROOT_DEV" ] && continue
  CAND="`$d"
  break
done
if [ -z "`$CAND" ]; then echo "no candidate data disk found"; exit 1; fi
echo "Using `$CAND as data disk (root is `$ROOT_DEV)"

# Format if blank (no filesystem signature)
if ! sudo blkid "`$CAND" >/dev/null 2>&1; then
  echo "Formatting `$CAND as ext4 (label: $DataLabel)"
  sudo mkfs.ext4 -L $DataLabel "`$CAND"
fi

sudo mkdir -p $DataMount
if mountpoint -q $DataMount; then
  echo "Already mounted at $DataMount"
else
  sudo mount "`$CAND" $DataMount
  sudo chown `$(id -u):`$(id -g) $DataMount
fi

# Persistent fstab entry (by label so device name doesn't matter)
if ! grep -q "LABEL=$DataLabel" /etc/fstab; then
  echo "Adding fstab entry"
  echo "LABEL=$DataLabel  $DataMount  ext4  defaults,nofail  0  2" | sudo tee -a /etc/fstab >/dev/null
fi

df -h $DataMount
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
    'Ssh'           { Invoke-Ssh -Interactive }
    'Mount'         { Mount-DataDisk }
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
        Mount-DataDisk
        Show-Status
        Write-Host "`nReady. '.\sonic-vm.ps1 -Action Ssh' to log in. Persistent storage at $DataMount."
    }
}
