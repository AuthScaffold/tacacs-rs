<#
.SYNOPSIS
    Tests SONiC image discovery and download behavior without a VM or network access.
.DESCRIPTION
    Loads only the image functions from sonic-vm.ps1.
    Uses mocked build metadata and a small compressed image fixture.
.EXAMPLE
    pwsh -NoLogo -NoProfile -File ./lde/sonic-vm/tests/Test-SonicImageDownload.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$helperDirectory = Split-Path $PSScriptRoot -Parent
$manager = Join-Path $helperDirectory 'sonic-vm.ps1'
$temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) "sonic-image-tests-$([Guid]::NewGuid().ToString('N'))"
$testContext = @{
    assertions = 0
    caseNumber = 0
    requests = [Collections.Generic.List[string]]::new()
    downloads = [Collections.Generic.List[string]]::new()
    failApiCall = 0
    failDownload = $false
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

function Assert-Throws {
    param([scriptblock]$Operation, [string]$Expected)

    $errorText = ''
    try {
        & $Operation | Out-Null
    } catch {
        $errorText = $_.Exception.Message
    }
    Assert-True ($errorText.Contains($Expected)) "Expected an error containing '$Expected', received '$errorText'."
}

function Reset-Test {
    $testContext.caseNumber++
    $caseDirectory = Join-Path $temporaryDirectory "case-$($testContext.caseNumber)"
    $script:ImagePath = Join-Path $caseDirectory 'image.img'
    $script:CompressedImagePath = Join-Path $caseDirectory 'compressed/image.img.gz'
    $script:ImageUrl = ''
    $script:BuildApiUrl = 'https://builds.example.test/project/_apis/build'
    $script:BuildDefinitionId = 142
    $script:ImageArtifactName = 'sonic-buildimage.vs'
    $script:ImageArtifactSubPath = '/target/sonic-vs.img.gz'
    $testContext.requests.Clear()
    $testContext.downloads.Clear()
    $testContext.failApiCall = 0
    $testContext.failDownload = $false
    $testContext.builds = [pscustomobject]@{ value = @([pscustomobject]@{ id = 123456 }) }
    $testContext.artifacts = [pscustomobject]@{
        value = @(
            [pscustomobject]@{ name = 'other-image'; resource = [pscustomobject]@{ downloadUrl = 'https://wrong.example.test/' } },
            [pscustomobject]@{
                name = 'sonic-buildimage.vs'
                resource = [pscustomobject]@{
                    downloadUrl = 'https://artifacts.example.test/content?token=fixture&format=zip'
                }
            }
        )
    }
}

function Invoke-RestMethod {
    param([uri]$Uri, [switch]$UseBasicParsing)

    Assert-True $UseBasicParsing 'Build lookups must retain basic parsing compatibility.'
    $testContext.requests.Add($Uri.AbsoluteUri)
    if ($testContext.requests.Count -eq $testContext.failApiCall) {
        throw [Net.WebException]::new('Fixture build API failure.')
    }
    if ($Uri.AbsolutePath.EndsWith('/builds')) { return $testContext.builds }
    if ($Uri.AbsolutePath.EndsWith('/artifacts')) { return $testContext.artifacts }
    throw "Unexpected metadata request: $Uri"
}

function Invoke-WebRequest {
    param([uri]$Uri, [string]$OutFile, [switch]$UseBasicParsing)

    Assert-True $UseBasicParsing 'Image downloads must retain basic parsing compatibility.'
    $testContext.downloads.Add($Uri.AbsoluteUri)
    if ($testContext.failDownload) {
        [IO.File]::WriteAllText($OutFile, 'partial download')
        throw [Net.WebException]::new('Fixture image download failure.')
    }
    [IO.File]::WriteAllBytes($OutFile, $compressedBytes)
}

try {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($manager, [ref]$tokens, [ref]$errors)
    Assert-Equal $errors.Count 0 'The VM manager must parse without errors.'
    foreach ($name in @('Get-ImageDownloadUrl', 'Get-LatestSuccessfulImageArtifactUrl', 'Ensure-BaseImage', 'Expand-GzipFile')) {
        $definition = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
        Assert-True ($null -ne $definition) "The manager must define $name."
        Set-Item -Path "Function:$name" -Value $definition.Body.GetScriptBlock()
    }
    $parameters = @{}
    foreach ($parameter in $ast.ParamBlock.Parameters) {
        $parameters[$parameter.Name.VariablePath.UserPath] = $parameter
    }
    Assert-True ($null -eq $parameters.ImageUrl.DefaultValue) 'ImageUrl must not default to a pinned artifact.'
    Assert-Equal $parameters.BuildApiUrl.DefaultValue.Value 'https://dev.azure.com/mssonic/build/_apis/build' 'The public SONiC build API must remain the default.'
    Assert-Equal $parameters.BuildDefinitionId.DefaultValue.Value 142 'The default build definition must match the SONiC VS pipeline.'
    Assert-Equal $parameters.ImageArtifactName.DefaultValue.Value 'sonic-buildimage.vs' 'The default artifact must be the SONiC VS image.'
    Assert-Equal $parameters.ImageArtifactSubPath.DefaultValue.Value '/target/sonic-vs.img.gz' 'The default artifact image path must remain unchanged.'
    Assert-Throws { & $manager -Action Status -BuildDefinitionId 0 } 'BuildDefinitionId'

    $imageBytes = [Text.Encoding]::UTF8.GetBytes('Synthetic SONiC image fixture.')
    $stream = [IO.MemoryStream]::new()
    try {
        $gzip = [IO.Compression.GZipStream]::new($stream, [IO.Compression.CompressionMode]::Compress, $true)
        try {
            $gzip.Write($imageBytes, 0, $imageBytes.Length)
        } finally {
            $gzip.Dispose()
        }
        $compressedBytes = $stream.ToArray()
    } finally {
        $stream.Dispose()
    }

    Reset-Test
    $url = Get-LatestSuccessfulImageArtifactUrl
    Assert-Equal $url 'https://artifacts.example.test/content?token=fixture&format=zip' 'Discovery must select the named artifact rather than the first artifact.'
    Assert-Equal $testContext.requests.Count 2 'Discovery must request builds and artifacts.'
    $query = ([uri]$testContext.requests[0]).Query
    foreach ($filter in @('definitions=142', 'statusFilter=completed', 'resultFilter=succeeded', '%24top=1', 'queryOrder=finishTimeDescending', 'api-version=7.1')) {
        Assert-True ($query.Contains($filter)) "The build query must include $filter."
    }
    Assert-Equal $testContext.requests[1] 'https://builds.example.test/project/_apis/build/builds/123456/artifacts?api-version=7.1' 'Artifact discovery must use the selected build ID.'

    Reset-Test
    $BuildApiUrl = 'https://custom.example.test/other/_apis/build/'
    $BuildDefinitionId = 77
    $ImageArtifactName = 'custom-vs'
    $testContext.artifacts.value[1].name = 'custom-vs'
    $url = Get-LatestSuccessfulImageArtifactUrl
    Assert-True ($testContext.requests[0].StartsWith('https://custom.example.test/other/_apis/build/builds?definitions=77&')) 'Custom build settings must override the defaults without a doubled slash.'
    Assert-True ($testContext.requests[1].StartsWith('https://custom.example.test/other/_apis/build/builds/123456/artifacts?')) 'Both lookups must use the custom API root.'
    Assert-Equal $url $testContext.artifacts.value[1].resource.downloadUrl 'Custom artifact names must be supported.'

    Reset-Test
    $testContext.builds.value = @()
    Assert-Throws { Get-LatestSuccessfulImageArtifactUrl } 'No successful build was found'
    Assert-Equal $testContext.requests.Count 1 'An empty build result must not trigger an artifact lookup.'
    Reset-Test
    $testContext.artifacts.value = @()
    Assert-Throws { Get-LatestSuccessfulImageArtifactUrl } "does not contain the 'sonic-buildimage.vs' artifact"
    Reset-Test
    $testContext.artifacts.value[1].name = 'SONIC-BUILDIMAGE.VS'
    Assert-Throws { Get-LatestSuccessfulImageArtifactUrl } 'does not contain'
    foreach ($downloadUrl in @($null, '', ' ')) {
        Reset-Test
        $testContext.artifacts.value[1].resource.downloadUrl = $downloadUrl
        Assert-Throws { Get-LatestSuccessfulImageArtifactUrl } 'has no download URL'
    }

    Reset-Test
    Ensure-BaseImage
    Assert-Equal $testContext.requests.Count 2 'A missing local image must trigger latest-build discovery.'
    Assert-Equal $testContext.downloads.Count 1 'The selected image must download once.'
    $download = $testContext.downloads[0]
    Assert-True ($download.Contains('token=fixture')) 'Image URL conversion must preserve unrelated query values.'
    Assert-True ($download.Contains('format=file')) 'The downloader must select a file rather than an artifact ZIP.'
    Assert-True ($download.Contains('subPath=/target/sonic-vs.img.gz')) 'The downloader must select the image within the artifact.'
    Assert-True (-not $download.Contains('format=zip')) 'The artifact ZIP format must be replaced.'
    Assert-Equal ([IO.File]::ReadAllText($ImagePath)) ([Text.Encoding]::UTF8.GetString($imageBytes)) 'The downloaded gzip must extract to the expected base image.'
    Assert-True (Test-Path $CompressedImagePath) 'The compressed image must remain cached.'
    Assert-True (-not (Test-Path "$CompressedImagePath.download")) 'A successful download must not leave the temporary download file.'
    $testContext.requests.Clear()
    $testContext.downloads.Clear()
    Ensure-BaseImage
    Assert-Equal $testContext.requests.Count 0 'An existing base image must skip build discovery.'
    Assert-Equal $testContext.downloads.Count 0 'An existing base image must skip downloading.'

    Reset-Test
    [IO.Directory]::CreateDirectory((Split-Path $CompressedImagePath)) | Out-Null
    [IO.File]::WriteAllBytes($CompressedImagePath, $compressedBytes)
    Ensure-BaseImage
    Assert-Equal $testContext.requests.Count 0 'A cached compressed image must not require metadata access or ImageUrl.'
    Assert-Equal $testContext.downloads.Count 0 'A cached compressed image must not download again.'
    Assert-Equal ([IO.File]::ReadAllText($ImagePath)) ([Text.Encoding]::UTF8.GetString($imageBytes)) 'The cached gzip must extract correctly.'

    Reset-Test
    $ImageUrl = 'https://pinned.example.test/content?format=zip&subPath=old&keep=value'
    $ImageArtifactSubPath = '/custom folder/image.img.gz'
    Ensure-BaseImage
    Assert-Equal $testContext.requests.Count 0 'An explicit ImageUrl must bypass latest-build discovery.'
    $download = $testContext.downloads[0]
    Assert-True ($download.StartsWith('https://pinned.example.test/content?')) 'An explicit artifact URL must select the download source.'
    Assert-True ($download.Contains('subPath=/custom%20folder/image.img.gz')) 'Custom image paths must be URL-encoded.'
    Assert-True ($download.Contains('keep=value')) 'Explicit URLs must retain unrelated query parameters.'
    Assert-Equal ([regex]::Matches($download, 'subPath=')).Count 1 'The old subPath must be replaced, not duplicated.'
    Assert-Equal ([regex]::Matches($download, 'format=')).Count 1 'The old format must be replaced, not duplicated.'

    foreach ($failedCall in @(1, 2)) {
        Reset-Test
        $testContext.failApiCall = $failedCall
        Assert-Throws { Ensure-BaseImage } 'Fixture build API failure'
        Assert-Equal $testContext.downloads.Count 0 'Metadata errors must not fall back to a hardcoded download.'
        Assert-True (-not (Test-Path $ImagePath)) 'Metadata errors must not create a success-shaped base image.'
    }
    Reset-Test
    $testContext.failDownload = $true
    Assert-Throws { Ensure-BaseImage } 'Fixture image download failure'
    Assert-True (-not (Test-Path $CompressedImagePath)) 'A partial download must not become the cached gzip.'
    Assert-True (-not (Test-Path $ImagePath)) 'A failed download must not create a base image.'
    $testContext.failDownload = $false
    Ensure-BaseImage
    Assert-Equal ([IO.File]::ReadAllText($ImagePath)) ([Text.Encoding]::UTF8.GetString($imageBytes)) 'Retry must replace the partial download and extract the complete image.'

    Write-Host "PASS: $($testContext.assertions) SONiC image assertions passed."
} finally {
    if (Test-Path $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
