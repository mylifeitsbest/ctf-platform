# Поднять A/D-дойо. Требует запущенный Docker Desktop.
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

Write-Host "==> Проверяю Docker..." -ForegroundColor Cyan
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker не запущен. Открой Docker Desktop и подожди, пока он стартует, потом снова запусти этот скрипт." -ForegroundColor Red
    exit 1
}

Write-Host "==> Генерирую docker-compose.yml из config/game.json..." -ForegroundColor Cyan
python scripts/gen_compose.py
if ($LASTEXITCODE -ne 0) { Write-Host "Не найден python. Установи Python 3 и добавь в PATH." -ForegroundColor Red; exit 1 }

Write-Host "==> Собираю образы (первый раз ~2-4 мин)..." -ForegroundColor Cyan
docker compose build

Write-Host "==> Запускаю..." -ForegroundColor Cyan
docker compose up -d

$port = (Get-Content config/game.json | ConvertFrom-Json).scoreboard_port
Write-Host ""
Write-Host "ГОТОВО." -ForegroundColor Green
Write-Host "  Scoreboard:  http://localhost:$port" -ForegroundColor Green
Write-Host "  Дашборд:     открой dashboard\index.html в браузере" -ForegroundColor Green
Write-Host "  Логи:        docker compose logs -f checker" -ForegroundColor DarkGray
Write-Host "  Ферма:       cd farm; python farm.py" -ForegroundColor DarkGray
