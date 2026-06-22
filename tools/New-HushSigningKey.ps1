#Requires -Version 5.1
<#
    New-HushSigningKey.ps1 — one-time keypair generator for the operator.

    Produces an RSA-2048 keypair:
      * hush-public.xml   -> paste into config.json (publicKeyXml) / pass to Install-Hush.ps1.
                             Safe to distribute; this is what every machine pins.
      * hush-private.xml  -> KEEP OFFLINE. Used only by Protect-HushManifest.ps1 to sign the
                             catalog. Anyone with this key can author policy your fleet trusts.
#>

[CmdletBinding()]
param([string]$OutDir = '.')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$pubPath = Join-Path $OutDir 'hush-public.xml'
$privPath = Join-Path $OutDir 'hush-private.xml'

$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider 2048
try {
    Set-Content -Path $privPath -Value $rsa.ToXmlString($true)  -Encoding ASCII -NoNewline
    Set-Content -Path $pubPath  -Value $rsa.ToXmlString($false) -Encoding ASCII -NoNewline
} finally { $rsa.Dispose() }

Write-Host "Public key  : $pubPath  (distribute / pin in config.json)" -ForegroundColor Green
Write-Host "Private key : $privPath  (KEEP OFFLINE — never commit to the repo)" -ForegroundColor Yellow
Write-Host ''
Write-Host '--- public key (publicKeyXml) ---'
Get-Content -Path $pubPath -Raw
