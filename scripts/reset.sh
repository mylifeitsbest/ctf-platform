#!/usr/bin/env bash
# Полный сброс: снести контейнеры/тома (обнулить счёт) и поднять заново.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
echo "==> Сношу контейнеры и тома (счёт обнулится)..."
docker compose down -v
exec "$ROOT/scripts/up.sh"
