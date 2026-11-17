# Короткий статус: контейнеры + текущий счёт.
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
docker compose ps
$port = (Get-Content config/game.json | ConvertFrom-Json).scoreboard_port
Write-Host "`n== Счёт ==" -ForegroundColor Cyan
try {
    (Invoke-RestMethod "http://localhost:$port/api/scoreboard") | ConvertTo-Json -Depth 5
} catch {
    Write-Host "Scoreboard ещё не поднялся (http://localhost:$port)" -ForegroundColor DarkGray
}
