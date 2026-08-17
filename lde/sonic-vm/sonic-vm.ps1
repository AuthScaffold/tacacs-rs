<#
.SYNOPSIS
    Starts or manages a SONiC-VS QEMU VM with SSH and a persistent data disk.

.DESCRIPTION
    Runs the SONiC virtual-switch image with qemu-system-x86_64.
    The VM starts from a qcow2 overlay on the read-only base image.
    If the base image is missing, the script downloads and extracts it.
    A second qcow2 disk stores persistent user data at /data in the guest.
    Host port 2222 forwards SSH traffic to guest port 22.

    Move files between Windows and the guest via scp/sftp on port 2222.

.EXAMPLE
    .\sonic-vm.ps1 -Action Up        # Start in the background and wait for SSH.
    .\sonic-vm.ps1 -Action InstallKey # Copy your SSH public key to the guest.
    .\sonic-vm.ps1 -Action Mount      # If necessary, format the disk. Then mount /data.
    .\sonic-vm.ps1 -Action Ssh       # Start an interactive shell.
    .\sonic-vm.ps1 -Action Stop
#>
[CmdletBinding()]
param(
    [ValidateSet('Start','Up','Stop','Ssh','InstallKey','CopyKey','Mount','Umount','Status',
                 'Reset','Snapshot','Restore','ListSnapshots')]
    [string]$Action = 'Up',

    [string]$QemuExe       = 'C:\Program Files\qemu\qemu-system-x86_64.exe',
    [string]$QemuImgExe    = 'C:\Program Files\qemu\qemu-img.exe',
    [string]$ImagePath     = 'sonic-vs.img',
    [string]$CompressedImagePath = 'sonic-vs.img.gz',
    [string]$ImageUrl      = 'https://artprodcus3.artifacts.visualstudio.com/Af91412a5-a906-4990-9d7c-f697b81fc04d/be1b070f-be15-4154-aade-b1d3bfb17054/_apis/artifact/cGlwZWxpbmVhcnRpZmFjdDovL21zc29uaWMvcHJvamVjdElkL2JlMWIwNzBmLWJlMTUtNDE1NC1hYWRlLWIxZDNiZmIxNzA1NC9idWlsZElkLzEwNjQ4NDEvYXJ0aWZhY3ROYW1lL3NvbmljLWJ1aWxkaW1hZ2UudnM1/content?format=zip',
    [string]$ImageArtifactSubPath = '/target/sonic-vs.img.gz',
    [string]$OverlayPath   = 'overlay.qcow2',
    [bool]  $UseOverlay    = $true,
    [string]$SnapshotName,
    [string]$VmName        = 'sonic-simulator_1',
    [int]   $MemoryMB      = 20480,
    [int]   $Cpus          = 10,

    [int]   $SshPort       = 2222,
    [int]   $MonitorPort   = 44001,
    [int]   $SerialPort    = 5001,

    [string]$DataDiskPath  = 'data.qcow2',
    [int]   $DataDiskSizeGB = 10,
    [string]$DataMount     = '/data',
    [string]$DataLabel     = 'sonicdata',

    [string]$User          = 'admin',
    [string]$Password      = 'YourPaSsWoRd',
    [string]$PublicKeyPath,

    [switch]$Daemon
)

$ErrorActionPreference = 'Stop'

function Resolve-ScriptRelativePath {
    param([Parameter(Mandatory)][string]$Path)

    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }

    [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $Path))
}

$ImagePath = Resolve-ScriptRelativePath -Path $ImagePath
$CompressedImagePath = Resolve-ScriptRelativePath -Path $CompressedImagePath
$OverlayPath = Resolve-ScriptRelativePath -Path $OverlayPath
$DataDiskPath = Resolve-ScriptRelativePath -Path $DataDiskPath

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
    if ($LASTEXITCODE -ne 0) { throw "ssh returned exit code $LASTEXITCODE." }
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
        Write-Warning "plink password SSH returned exit code $LASTEXITCODE. The script will try native ssh."
    } else {
        Test-Tool ssh
    }

    Write-Host "When the prompt appears, enter the SSH password for $target. Default password: $Password"
    $common = Get-PasswordSshArgs
    if ($RemoteCmd) {
        & ssh @common $target $RemoteCmd
    } else {
        & ssh @common $target
    }
    if ($LASTEXITCODE -ne 0) { throw "Password SSH returned exit code $LASTEXITCODE." }
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
        throw "The SSH public key does not have the OpenSSH format: $Path"
    }

    $line
}

function Install-SshKey {
    if (Test-SshKeyAuth) {
        Write-Host "SSH key authentication is available."
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

    Write-Host "Install the SSH public key from $keyPath."
    Invoke-RemoteScript -Script $script -UsePassword

    if (-not (Test-SshKeyAuth)) {
        throw "The SSH key was copied, but key authentication returned an error."
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
    Write-Host "Wait for SSH at 127.0.0.1:$SshPort."
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-QemuProc)) {
            throw "The VM stopped before SSH became available. Run with -Action Start to see the QEMU console error."
        }
        if (Test-SshBanner) {
            Write-Host "SSH is available."
            return
        }
        Start-Sleep -Seconds 3
        Write-Host "The VM is still starting."
    }
    throw "SSH was not available after $TimeoutSec seconds."
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Expand-GzipFile {
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DestinationPath
    )

    $destinationDirectory = Split-Path $DestinationPath
    if (-not (Test-Path $destinationDirectory)) {
        New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    }

    $temporaryDestinationPath = "$DestinationPath.extracting"
    if (Test-Path $temporaryDestinationPath) {
        Remove-Item -Force $temporaryDestinationPath
    }

    try {
        $sourceStream = [IO.File]::OpenRead($SourcePath)
        try {
            $gzipStream = [IO.Compression.GZipStream]::new($sourceStream, [IO.Compression.CompressionMode]::Decompress)
            try {
                $destinationStream = [IO.File]::Create($temporaryDestinationPath)
                try {
                    $gzipStream.CopyTo($destinationStream)
                } finally {
                    $destinationStream.Dispose()
                }
            } finally {
                $gzipStream.Dispose()
            }
        } finally {
            $sourceStream.Dispose()
        }

        Move-Item -Force $temporaryDestinationPath $DestinationPath
    } catch {
        if (Test-Path $temporaryDestinationPath) {
            Remove-Item -Force $temporaryDestinationPath
        }
        throw
    }
}

function Get-ImageDownloadUrl {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$SubPath
    )

    $builder = [UriBuilder]::new($Url)
    $query = $builder.Query
    if ($query.StartsWith('?')) {
        $query = $query.Substring(1)
    }

    $queryParts = @()
    if (-not [string]::IsNullOrWhiteSpace($query)) {
        foreach ($part in ($query -split '&')) {
            if ([string]::IsNullOrWhiteSpace($part)) { continue }

            $namePart = $part
            $equalsIndex = $part.IndexOf('=')
            if ($equalsIndex -ge 0) {
                $namePart = $part.Substring(0, $equalsIndex)
            }

            $name = [Uri]::UnescapeDataString($namePart)
            if ($name -ieq 'format' -or $name -ieq 'subPath') { continue }
            $queryParts += $part
        }
    }

    $encodedSubPath = [Uri]::EscapeDataString($SubPath).Replace('%2F', '/')
    $queryParts += 'format=file'
    $queryParts += "subPath=$encodedSubPath"
    $builder.Query = $queryParts -join '&'
    $builder.Uri.AbsoluteUri
}

function Ensure-BaseImage {
    if (Test-Path $ImagePath) { return }
    if ([string]::IsNullOrWhiteSpace($ImageUrl)) {
        throw "Base image not found at $ImagePath and -ImageUrl is empty."
    }

    $imageDirectory = Split-Path $ImagePath
    if (-not (Test-Path $imageDirectory)) {
        New-Item -ItemType Directory -Path $imageDirectory -Force | Out-Null
    }

    $compressedDirectory = Split-Path $CompressedImagePath
    if (-not (Test-Path $compressedDirectory)) {
        New-Item -ItemType Directory -Path $compressedDirectory -Force | Out-Null
    }

    if (-not (Test-Path $CompressedImagePath)) {
        $temporaryDownloadPath = "$CompressedImagePath.download"
        if (Test-Path $temporaryDownloadPath) {
            Remove-Item -Force $temporaryDownloadPath
        }

        Write-Host "The base image is missing: $ImagePath"
        Write-Host "Download the SONiC image to $CompressedImagePath."
        Write-Host "The download can take several minutes."
        $downloadUrl = Get-ImageDownloadUrl -Url $ImageUrl -SubPath $ImageArtifactSubPath
        Invoke-WebRequest -Uri $downloadUrl -OutFile $temporaryDownloadPath -UseBasicParsing
        Move-Item -Force $temporaryDownloadPath $CompressedImagePath
    } else {
        Write-Host "The base image is missing: $ImagePath"
        Write-Host "Use the existing compressed image: $CompressedImagePath"
    }

    Write-Host "Extract $CompressedImagePath to $ImagePath."
    Expand-GzipFile -SourcePath $CompressedImagePath -DestinationPath $ImagePath
}

function Ensure-DataDisk {
    if (-not (Test-Path $QemuImgExe)) { throw "qemu-img not found at $QemuImgExe" }
    if (-not (Test-Path $DataDiskPath)) {
        Write-Host "Create the thin qcow2 data disk $DataDiskPath ($DataDiskSizeGB GB)."
        & $QemuImgExe create -f qcow2 $DataDiskPath "${DataDiskSizeGB}G" | Out-Null
    }
}

function Ensure-BaseReadOnly {
    if (-not (Test-Path $ImagePath)) { return }
    $f = Get-Item $ImagePath
    if (-not $f.IsReadOnly) {
        Write-Host "Set the base image to read-only: $ImagePath"
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
    Ensure-BaseImage
    if (-not (Test-Path $ImagePath))  { throw "Base image not found at $ImagePath" }
    Ensure-BaseReadOnly
    if (-not (Test-Path $OverlayPath)) {
        $baseFmt = Get-ImageFormat -Path $ImagePath
        Write-Host "Create overlay $OverlayPath (base: $ImagePath, format: $baseFmt)."
        & $QemuImgExe create -f qcow2 -F $baseFmt -b $ImagePath $OverlayPath | Out-Null
    }
}

function Get-DiskPath {
    if ($UseOverlay) { return $OverlayPath } else { return $ImagePath }
}

function Reset-Overlay {
    if (-not $UseOverlay) { throw "Before you reset the overlay, set -UseOverlay to true." }
    if (Get-QemuProc) { throw "Before you reset the overlay, stop the VM." }
    if (Test-Path $OverlayPath) {
        Write-Host "Deleting $OverlayPath"
        Remove-Item -Force $OverlayPath
    }
    Ensure-Overlay
    Write-Host "The overlay was reset. The next VM start uses a clean base."
}

function Snapshot-Overlay {
    if (-not $UseOverlay) { throw "Snapshots require the overlay. Set -UseOverlay." }
    if (-not $SnapshotName) { throw "Provide -SnapshotName <name>." }
    if (Get-QemuProc) { throw "Before you create an overlay snapshot, stop the VM." }
    if (-not (Test-Path $OverlayPath)) { throw "No overlay was found at $OverlayPath." }
    $dst = Join-Path (Split-Path $OverlayPath) ("overlay.$SnapshotName.qcow2")
    Copy-Item $OverlayPath $dst -Force
    Write-Host "Snapshot saved: $dst"
}

function Restore-Snapshot {
    if (-not $UseOverlay) { throw "Snapshots require the overlay. Set -UseOverlay." }
    if (-not $SnapshotName) { throw "Provide -SnapshotName <name>." }
    if (Get-QemuProc) { throw "Before you restore a snapshot, stop the VM." }
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

    if (Get-QemuProc) {
        Write-Host "VM '$VmName' is already active."
        return
    }

    Ensure-BaseImage
    if (-not (Test-Path $ImagePath)) { throw "Image not found at $ImagePath" }

    if ($UseOverlay) { Ensure-Overlay }
    Ensure-DataDisk
    $disk = Get-DiskPath
    $diskFmt = if ($UseOverlay) { 'qcow2' } else { Get-ImageFormat -Path $disk }

    $netdev = "user,id=net0,hostfwd=tcp::${SshPort}-:22"
    $qemuArgs = @(
        '-name', $VmName,
        '-m', "${MemoryMB}M",
        '-smp', "cpus=$Cpus",
        '-cpu', 'max',
        '-drive', "file=$disk,format=$diskFmt,index=0,media=disk,id=drive0",
        '-drive', "file=$DataDiskPath,format=qcow2,index=1,media=disk,id=datadisk0",
        '-serial', "telnet:127.0.0.1:${SerialPort},server,nowait",
        '-monitor', "tcp:127.0.0.1:${MonitorPort},server,nowait",
#        '-display', 'none',
        '-device', 'e1000,netdev=net0',
        '-netdev', $netdev
    )

    Write-Host "Start the VM (root: $disk, data: $DataDiskPath)."
    Write-Host "  $QemuExe $($qemuArgs -join ' ')"

    if ($Daemon) {
        $process = Start-Process -FilePath $QemuExe -ArgumentList $qemuArgs -WindowStyle Minimized -PassThru
        if ($process.WaitForExit(1000)) {
            throw "QEMU stopped immediately with exit code $($process.ExitCode). Run with -Action Start to see the QEMU console error."
        }
        Write-Host "The VM started in the background."
    } else {
        & $QemuExe @qemuArgs
        if ($LASTEXITCODE -ne 0) { throw "QEMU exited with code $LASTEXITCODE." }
    }
}

function Stop-Vm {
    $p = Get-QemuProc
    if (-not $p) { Write-Host "VM '$VmName' is not running."; return }
    # Request a normal shutdown from the QEMU monitor.
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
        Write-Warning "The QEMU monitor returned an error: $_. Force-stop the VM."
    }
    Start-Sleep -Seconds 2
    $p = Get-QemuProc
    if ($p) { Stop-Process -Id $p.ProcessId -Force; Write-Host "The VM was force-stopped." }
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
    sudo blkid -L "`$DATA_LABEL" 2>/dev/null || true
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
        if sudo blkid -p "`$real" >/dev/null 2>&1; then
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
    current_label=`$(sudo blkid -s LABEL -o value "`$device" 2>/dev/null || true)
    [ "`$current_label" = "`$label" ] && return 0

    echo "Change the label of `$device from '`$current_label' to '`$label'."
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
        echo "No data disk has label `$DATA_LABEL or blank size `$EXPECTED_SIZE_BYTES bytes." >&2
        echo "Available block devices:" >&2
        lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT >&2
        exit 1
    fi
    echo "Use `$CAND as the blank data disk."
    echo "Format `$CAND as ext4 (label: `$DATA_LABEL)."
    sudo mkfs.ext4 -F -L "`$DATA_LABEL" "`$CAND"
fi

sudo mkdir -p "`$DATA_MOUNT"
if mountpoint -q "`$DATA_MOUNT"; then
    echo "The data disk is already mounted at `$DATA_MOUNT."
else
    sudo mount "`$CAND" "`$DATA_MOUNT"
    sudo chown `$(id -u):`$(id -g) "`$DATA_MOUNT"
fi

# Add a persistent fstab entry by label. Thus, the device name can change.
if grep -Eq "[[:space:]]`$DATA_MOUNT[[:space:]]" /etc/fstab; then
    echo "Update the fstab entry."
    sudo sed -i "\|[[:space:]]`$DATA_MOUNT[[:space:]]|c\LABEL=`$DATA_LABEL  `$DATA_MOUNT  ext4  defaults,nofail  0  2" /etc/fstab
elif ! grep -q "LABEL=`$DATA_LABEL" /etc/fstab; then
    echo "Add the fstab entry."
    echo "LABEL=`$DATA_LABEL  `$DATA_MOUNT  ext4  defaults,nofail  0  2" | sudo tee -a /etc/fstab >/dev/null
fi

df -h "`$DATA_MOUNT"
"@
    Invoke-RemoteScript -Script $script
}

function Umount-DataDisk {
    Invoke-RemoteScript -Script "sudo umount $DataMount && echo 'The data disk is unmounted.'"
}

function Show-Status {
    $p = Get-QemuProc
    if ($p) {
        Write-Host "VM '$VmName' is running (PID $($p.ProcessId))."
    } else {
        Write-Host "VM '$VmName' is not running."
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
        Write-Host "Data:    $DataDiskPath  ($sz MB on disk, ${DataDiskSizeGB} GB virtual). Mount: $DataMount"
    } else {
        Write-Host "Data:    $DataDiskPath is not created. Its first-boot size is ${DataDiskSizeGB} GB."
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
        Write-Host "`nReady. Run '.\sonic-vm.ps1 -Action Ssh' to access the VM through SSH. Persistent storage is at $DataMount."
    }
}
