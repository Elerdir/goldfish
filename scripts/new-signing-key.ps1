<#
  Generates the updater signing key (minisign) for Goldfish.

  Run once on your PC (Windows PowerShell 5.1, no admin):
    powershell -ExecutionPolicy Bypass -File scripts\new-signing-key.ps1

  Creates in %USERPROFILE%\.tauri:
    goldfish.key                 - private key (Forgejo secret TAURI_SIGNING_PRIVATE_KEY)
    goldfish.key.pub             - public key (crates\goldfish-tauri\tauri.conf.json, plugins.updater.pubkey)
    goldfish-password.clixml     - random key password, DPAPI-encrypted (only this user on this PC
                                   can decrypt it); Forgejo secret TAURI_SIGNING_PRIVATE_KEY_PASSWORD

  The key is never overwritten: losing or replacing it means installed versions reject updates.
  Values are never printed; -CopyKey / -CopyPassword put them on the clipboard.
#>
param(
    [switch]$CopyKey,
    [switch]$CopyPassword
)
$ErrorActionPreference = "Stop"

$dir = Join-Path $env:USERPROFILE ".tauri"
$key = Join-Path $dir "goldfish.key"
$passFile = Join-Path $dir "goldfish-password.clixml"

function Get-Password {
    $secure = Import-Clixml $passFile
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

if ($CopyKey) { Get-Content -Raw $key | Set-Clipboard; Write-Host "Private key is on the clipboard."; exit 0 }
if ($CopyPassword) { Get-Password | Set-Clipboard; Write-Host "Key password is on the clipboard."; exit 0 }

if (Test-Path $key) {
    Write-Host "Key $key already exists, nothing generated (replacing it would break updates)."
} else {
    New-Item -ItemType Directory -Force $dir | Out-Null
    # 32 random bytes as hex: no characters that could break a command line.
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $password = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
    ConvertTo-SecureString $password -AsPlainText -Force | Export-Clixml $passFile
    & cargo tauri signer generate --ci -w $key -p $password | Out-Null
    if ($LASTEXITCODE -ne 0) { Remove-Item -Force $passFile; throw "cargo tauri signer generate failed ($LASTEXITCODE)." }
    Write-Host "Generated: $key (+ .pub) and $passFile"
}
Write-Host "Public key ($key.pub) belongs in crates\goldfish-tauri\tauri.conf.json -> plugins.updater.pubkey."
Write-Host "Forgejo: -CopyKey -> TAURI_SIGNING_PRIVATE_KEY, -CopyPassword -> TAURI_SIGNING_PRIVATE_KEY_PASSWORD."
