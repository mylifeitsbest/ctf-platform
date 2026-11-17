#!/usr/bin/env bash
# Поднять A/D-дойо на Linux (ВДС). Нужны docker + docker compose + python3.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Проверяю Docker..."
if ! docker info >/dev/null 2>&1; then
  echo "Docker недоступен. Запусти службу (sudo systemctl start docker) или добавь юзера в группу docker." >&2
  exit 1
fi

echo "==> Генерирую docker-compose.yml (PUBLIC_HOST=${PUBLIC_HOST:-не задан})..."
python3 scripts/gen_compose.py

echo "==> Собираю образы..."
docker compose build

echo "==> Запускаю..."
docker compose up -d

PORT=$(python3 -c "import json;print(json.load(open('config/game.json'))['scoreboard_port'])")
echo ""
echo "ГОТОВО."
echo "  Табло:   http://<IP-ВДС>:${PORT}   (локально http://localhost:${PORT})"
echo "  Логи:    docker compose logs -f checker"
echo "  Ферма:   cd farm && pip3 install -r requirements.txt && python3 farm.py --team teamN"
echo ""
echo "  Чтобы ферма с ноутбуков била по ВДС: PUBLIC_HOST=<IP-ВДС> ./scripts/up.sh  (перегенерит targets.json)"
