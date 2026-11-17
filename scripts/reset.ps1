# Полный сброс: удалить контейнеры/тома, обнулить счёт, поднять заново.
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
Write-Host "==> Сношу контейнеры и тома (счёт обнулится)..." -ForegroundColor Yellow
docker compose down -v
& "$PSScriptRoot\up.ps1"
