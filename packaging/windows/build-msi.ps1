# Build the sda-agent.msi installer from a pre-built release binary.
#
# Requires WiX Toolset 3.x (candle.exe and light.exe on PATH). Run on
# a Windows host where the release binary has already been compiled
# via `cargo build --release -p sda-agent`.
#
# Usage:
#   pwsh packaging\windows\build-msi.ps1
#
# Output: dist\sda-agent-<version>.msi
[CmdletBinding()]
param(
    # Default path matches `make release` / `cargo build --release -p sda-agent`
    # output on a Windows host (host-triple directory), not the explicit
    # `x86_64-pc-windows-msvc` target directory that only appears when
    # building with `--target`. The explicit target path is still
    # accepted — callers can pass `-Binary` if they cross-compiled.
    [string]$Binary = "target\release\sda-agent.exe",
    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$cargoToml = Get-Content (Join-Path $root "Cargo.toml") -Raw
$version = ([regex]::Match($cargoToml, '^version\s*=\s*"([^"]+)"', 'Multiline')).Groups[1].Value

if (-not (Test-Path $Binary)) {
    $Binary = Join-Path $root $Binary
}
if (-not (Test-Path $Binary)) {
    throw "binary not found: $Binary — build it first with cargo build --release"
}

$outPath = Join-Path $root $OutDir
New-Item -ItemType Directory -Force -Path $outPath | Out-Null

$wxs     = Join-Path $PSScriptRoot "sda-agent.wxs"
$wixobj  = Join-Path $outPath     "sda-agent.wixobj"
$msi     = Join-Path $outPath     "sda-agent-$version.msi"

& candle.exe -nologo `
    -dVersion="$version" `
    -dBinary="$Binary" `
    -ext WixUtilExtension `
    -o "$wixobj" `
    "$wxs"
if ($LASTEXITCODE -ne 0) { throw "candle failed" }

& light.exe -nologo `
    -ext WixUtilExtension `
    -o "$msi" `
    "$wixobj"
if ($LASTEXITCODE -ne 0) { throw "light failed" }

# ---- Authenticode signing --------------------------------------------------
# If SIGN_CERT_THUMBPRINT is set, sign the binary and .msi with
# signtool so SmartScreen passes. The certificate must be installed
# in the Windows cert store (or available via an EV token).
#
# Env vars:
#   SIGN_CERT_THUMBPRINT  - SHA-1 thumbprint of the code signing cert
#   SIGN_TIMESTAMP_URL    - RFC 3161 timestamp server (default: DigiCert)
$TimestampUrl = if ($env:SIGN_TIMESTAMP_URL) { $env:SIGN_TIMESTAMP_URL } else { "http://timestamp.digicert.com" }

if ($env:SIGN_CERT_THUMBPRINT) {
    Write-Host "[sign] Authenticode-signing binary with thumbprint: $($env:SIGN_CERT_THUMBPRINT)"
    & signtool.exe sign /sha1 $env:SIGN_CERT_THUMBPRINT /fd SHA256 `
        /tr $TimestampUrl /td SHA256 /v "$Binary"
    if ($LASTEXITCODE -ne 0) { throw "signtool binary sign failed" }

    Write-Host "[sign] Authenticode-signing MSI"
    & signtool.exe sign /sha1 $env:SIGN_CERT_THUMBPRINT /fd SHA256 `
        /tr $TimestampUrl /td SHA256 /v "$msi"
    if ($LASTEXITCODE -ne 0) { throw "signtool MSI sign failed" }

    Write-Host "[sign] signed $msi"
} else {
    Write-Host "[sign] skipping Authenticode signing (SIGN_CERT_THUMBPRINT not set)"
}

Write-Host "built $msi"
