# Скопировать эталонные сплойты в ферму (чтобы farm.py реально начал красть флаги).
# Делайте это ПОСЛЕ того, как попробовали написать свои.
$root = Split-Path $PSScriptRoot -Parent
Copy-Item "$root\exploits_reference\*_sploit.py" "$root\farm\sploits\" -Force
Write-Host "Эталонные сплойты скопированы в farm\sploits\. Запускай: cd farm; python farm.py" -ForegroundColor Green
