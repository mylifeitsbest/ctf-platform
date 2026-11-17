#!/usr/bin/env bash
# Турнкей-деплой A/D Dojo на свежий Ubuntu/Debian ВДС.
# Запуск:  ./scripts/deploy_vds.sh <ПУБЛИЧНЫЙ_IP_ВДС>
set -e

PUBLIC_HOST="${1:-}"
if [ -z "$PUBLIC_HOST" ]; then
  PUBLIC_HOST="$(curl -s https://ifconfig.me 2>/dev/null || echo localhost)"
  echo "IP не задан, определил автоматически: $PUBLIC_HOST"
  echo "(если неверно — запусти: ./scripts/deploy_vds.sh <нужный_IP>)"
fi
cd "$(dirname "$0")/.."

echo "==> Docker..."
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER" 2>/dev/null || true
fi
command -v python3 >/dev/null 2>&1 || { sudo apt-get update -y && sudo apt-get install -y python3; }

echo "==> Генерирую стенд с PUBLIC_HOST=$PUBLIC_HOST ..."
PUBLIC_HOST="$PUBLIC_HOST" python3 scripts/gen_compose.py

echo "==> Сборка и запуск (первый раз ~3-5 мин)..."
sudo PUBLIC_HOST="$PUBLIC_HOST" docker compose up -d --build

echo ""
echo "================================================================"
echo "  ГОТОВО."
echo "  Полигон (вход, задания):  http://$PUBLIC_HOST:9000"
echo "  Табло очков:              http://$PUBLIC_HOST:8080"
echo "  Открой в фаерволе/security-group порты: 9000, 8080, 5100-5399"
echo "================================================================"
