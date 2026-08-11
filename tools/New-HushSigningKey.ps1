#Requires -Version 5.1
<#
    New-HushSigningKey.ps1 — one-time keypair generator for the operator.

    Produces an RSA-2048 keypair:
      * hush-public.xml   -> paste into config.json (publicKeyXml) / pass to Install-Hush.ps1.
                             Safe to distribute; this is what every machine pins.
      * hush-private.xml.dpapi -> encrypted with the current Windows user's DPAPI key and
                             intended to remain on the offline signing machine. Anyone who can
                             decrypt this key can author policy your fleet trusts.

    Existing plaintext XML keys remain supported by Protect-HushManifest.ps1 for migration.
#>

[CmdletBinding()]
param([string]$OutDir = '.')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$pubPath = Join-Path $OutDir 'hush-public.xml'
$privPath = Join-Path $OutDir 'hush-private.xml.dpapi'

$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider 2048
try {
    $privateXml = $rsa.ToXmlString($true)
    $securePrivate = New-Object System.Security.SecureString
    foreach ($character in $privateXml.ToCharArray()) { $securePrivate.AppendChar($character) }
    $securePrivate.MakeReadOnly()
    ConvertFrom-SecureString -SecureString $securePrivate | Set-Content -Path $privPath -Encoding ASCII -NoNewline
    Set-Content -Path $pubPath  -Value $rsa.ToXmlString($false) -Encoding ASCII -NoNewline
} finally { $rsa.Dispose() }

Write-Host "Public key  : $pubPath  (distribute / pin in config.json)" -ForegroundColor Green
Write-Host "Private key : $privPath  (KEEP OFFLINE — DPAPI protected; never commit to the repo)" -ForegroundColor Yellow
Write-Host ''
Write-Host '--- public key (publicKeyXml) ---'
Get-Content -Path $pubPath -Raw
