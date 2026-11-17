#!/usr/bin/env bash
# Скопировать эталонные сплойты в ферму (делайте ПОСЛЕ своих попыток).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cp "$ROOT"/exploits_reference/*_sploit.py "$ROOT"/farm/sploits/
echo "Эталонные сплойты в farm/sploits/. Запуск: cd farm && python3 farm.py --team teamN"
