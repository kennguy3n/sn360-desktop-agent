# Sign the SN360 EDR minifilter driver via the Windows Hardware
# Compatibility Program (WHCP) (Phase E6.2).
#
# Production signing pipeline — requires:
#   * A Microsoft-issued kernel-mode code-signing certificate
#     (EV cert) installed in the local cert store.
#   * The `signtool.exe` from the WDK
#     (`C:\Program Files (x86)\Windows Kits\10\bin\<ver>\<arch>\signtool.exe`).
#   * A registered Hardware Dev Center account to submit the
#     resulting CAB to WHCP for cross-signing.
#
# This is NOT exercised in CI. See
# `docs/edr-parity/PRODUCTISATION-WINDOWS.md` § "WHQL pipeline" for
# the full process including the WHCP submission UI walkthrough.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SysFile,

    [Parameter(Mandatory = $true)]
    [string]$CatalogFile,

    [Parameter(Mandatory = $true)]
    [string]$CertSubject,

    [Parameter(Mandatory = $false)]
    [string]$TimestampUrl = 'http://timestamp.digicert.com',

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = "$PSScriptRoot\..\..\target\windows-driver-signed"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Find-SignTool {
    $kit = 'C:\Program Files (x86)\Windows Kits\10\bin'
    if (-not (Test-Path $kit)) {
        throw "Windows Kits not found at $kit; install the WDK."
    }
    $candidate = Get-ChildItem -Path $kit -Recurse -Filter 'signtool.exe' |
        Where-Object { $_.FullName -like '*\x64\*' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if (-not $candidate) {
        throw "signtool.exe not found under $kit."
    }
    return $candidate.FullName
}

function Test-CertificateAvailable {
    param([string]$Subject)
    $cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -like "*$Subject*" } |
        Select-Object -First 1
    if (-not $cert) {
        throw "No certificate matching subject '$Subject' found in CurrentUser\My or LocalMachine\My."
    }
    return $cert
}

function Invoke-SignFile {
    param(
        [string]$SignToolPath,
        [string]$File,
        [string]$Subject,
        [string]$TimestampUrl
    )
    & $SignToolPath sign /fd SHA256 /td SHA256 /tr $TimestampUrl /sm /n $Subject /v $File
    if ($LASTEXITCODE -ne 0) {
        throw "signtool failed on $File with exit code $LASTEXITCODE."
    }
}

if (-not (Test-Path $SysFile)) {
    throw "Driver .sys not found at $SysFile. Run .\build-driver.ps1 first."
}
if (-not (Test-Path $CatalogFile)) {
    throw "Catalog .cat not found at $CatalogFile."
}

$signTool = Find-SignTool
Write-Host "Using signtool: $signTool"

Test-CertificateAvailable -Subject $CertSubject | Out-Null
Write-Host "Found code-signing certificate for '$CertSubject'."

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
}

Invoke-SignFile -SignToolPath $signTool -File $SysFile -Subject $CertSubject -TimestampUrl $TimestampUrl
Invoke-SignFile -SignToolPath $signTool -File $CatalogFile -Subject $CertSubject -TimestampUrl $TimestampUrl

Write-Host ''
Write-Host 'Local signing complete. Next steps:'
Write-Host "  1. Bundle '$SysFile' and '$CatalogFile' into a WHCP submission CAB."
Write-Host '  2. Sign in to https://partner.microsoft.com/dashboard/hardware/driver/New'
Write-Host '  3. Upload the CAB and request "Attestation" or "Compatibility" signing.'
Write-Host '  4. Download the WHQL-cross-signed CAB once approved (typically 1-3 business days).'
Write-Host '  5. The cross-signed driver is what ships in the agent installer.'
