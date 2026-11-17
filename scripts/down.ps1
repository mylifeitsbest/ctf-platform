# Остановить дойо (данные/счёт сохраняются до reset).
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
docker compose down
Write-Host "Остановлено." -ForegroundColor Yellow
