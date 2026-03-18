param(
    [string]$ip
)

$bytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
[Array]::Reverse($bytes)  # Ensure correct byte order
[uint32]([BitConverter]::ToUInt32($bytes, 0))