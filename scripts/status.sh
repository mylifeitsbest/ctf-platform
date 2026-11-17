#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
docker compose ps
PORT=$(python3 -c "import json;print(json.load(open('config/game.json'))['scoreboard_port'])")
echo ""
echo "== Счёт =="
curl -s "http://localhost:${PORT}/api/scoreboard" || echo "scoreboard ещё не поднялся"
echo ""
