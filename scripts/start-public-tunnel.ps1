$ErrorActionPreference = 'Stop'

$projectPath = Split-Path -Parent $PSScriptRoot
$cloudflared = Join-Path $projectPath 'bin\cloudflared.exe'
$quickConfig = Join-Path $projectPath 'quick-tunnel.yml'

if (-not (Test-Path -LiteralPath $cloudflared)) {
  $binPath = Split-Path -Parent $cloudflared
  New-Item -ItemType Directory -Path $binPath -Force | Out-Null
  Write-Host 'Downloading the Cloudflare tunnel helper...' -ForegroundColor Cyan
  Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe' -OutFile $cloudflared
}

$signature = Get-AuthenticodeSignature -FilePath $cloudflared
if ($signature.Status -ne 'Valid') { throw "cloudflared.exe signature is not valid: $($signature.Status)" }
Write-Host 'Starting secure browser access...' -ForegroundColor Cyan
Write-Host 'Keep this window open. Your public HTTPS address appears below.'
Write-Host ''

& $cloudflared tunnel --config $quickConfig --url http://127.0.0.1:4173 --no-autoupdate --protocol quic --ha-connections 1
