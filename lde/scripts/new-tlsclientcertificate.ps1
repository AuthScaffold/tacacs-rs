function get-cacert()
{
    $caCert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=MyRootCA" }
    return $caCert
}

function get-servercert()
{
    $serverCert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=MyServer" }
    return $serverCert
}

function get-clientcert()
{
    $clientCert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Subject -eq "CN=MyClient" }
    return $clientCert
}

function new-cacert()
{
    $cert = New-SelfSignedCertificate `
        -Type Custom `
        -KeySpec Signature `
        -Subject "CN=MyRootCA" `
        -KeyExportPolicy Exportable `
        -HashAlgorithm sha256 `
        -KeyLength 2048 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyUsageProperty Sign `
        -KeyUsage CertSign `
        -NotAfter (Get-Date).AddYears(10)

    return $cert
}

function export-cert
{
    Param (
    [parameter(Mandatory=$true)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
    [parameter(Mandatory=$true)]
    [securestring]$CertPassword,
    [parameter(Mandatory=$true)]
    [string]$CertificatePath,
    [parameter(Mandatory=$true)]
    [string]$CertificateKeyPath
  )
    Export-Certificate `
        -Cert $Certificate `
        -FilePath $CertificatePath
    
    Export-PfxCertificate `
        -Cert $Certificate `
        -FilePath $CertificateKeyPath `
        -Password $password
}

function new-servercert([System.Security.Cryptography.X509Certificates.X509Certificate2]$caCert)
{
    $serverCert = New-SelfSignedCertificate `
        -Subject "CN=MyServer" `
        -Signer $caCert `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyExportPolicy Exportable `
        -HashAlgorithm sha256 `
        -KeyLength 2048 `
        -KeyUsage DigitalSignature, KeyEncipherment `
        -Type SSLServerAuthentication

    return $serverCert
}

function new-clientcert([System.Security.Cryptography.X509Certificates.X509Certificate2]$caCert)
{
    $clientCert = New-SelfSignedCertificate `
        -Subject "CN=MyClient" `
        -Signer $caCert `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyExportPolicy Exportable `
        -HashAlgorithm sha256 `
        -KeyLength 2048 `
        -KeyUsage DigitalSignature, KeyEncipherment `
        -Type SSLClientAuthentication

    return $clientCert
}




$password = ConvertTo-SecureString -String "password" -Force -AsPlainText

$git_directory = git rev-parse --show-toplevel

$server_certificate = Join-Path -Path $git_directory -ChildPath lde containers config certificates server.crt
$server_key = Join-Path -Path $git_directory -ChildPath lde containers config certificates server.key
$client_certificate = Join-Path -Path $git_directory -ChildPath libraries tacacsrs_networking examples samples client.crt
$client_key = Join-Path -Path $git_directory -ChildPath libraries tacacsrs_networking examples samples client.key

$caCert = get-cacert
if ($null -eq $caCert)
{
    $caCert = new-cacert
}

$serverCert = get-servercert
if ($null -eq $serverCert)
{
    $serverCert = new-servercert -caCert $caCert
}

export-cert `
    -Certificate $serverCert `
    -CertPassword $password `
    -CertificatePath $server_certificate `
    -CertificateKeyPath $server_key


$clientCert = get-clientcert
if ($null -eq $clientCert)
{
    $clientCert = new-clientcert -caCert $caCert
}

export-cert `
    -Certificate $clientCert `
    -CertPassword $password `
    -CertificatePath $client_certificate `
    -CertificateKeyPath $client_key