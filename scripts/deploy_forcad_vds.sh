#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Turnkey-деплой РЕАЛЬНОГО A/D-стенда на свежий Ubuntu/Debian ВДС:
#   ForcAD (платформа финала) + наши чекеры + 3 вулнбокса + подсказки по DestructiveFarm.
# Топология: ОДИН хост, 3 команды (team1=ты, team2/team3=боты).
# Каждая команда — вулнбокс со своим СТАТИЧЕСКИМ IP в общей docker-сети, на нём
# notes:5001 / pingtool:5002 / vault:5003 (ровно те порты, что зашиты в чекерах).
#
# ВНИМАНИЕ: сквозной прогон на живом ВДС пока НЕ делался (ВДС был недоступен).
# Скрипт идемпотентный и по шагам; если ForcAD поменял имена контейнеров —
# поправь блок [6/7] (поиск celery-контейнера).
#
# Запуск:   chmod +x scripts/deploy_forcad_vds.sh && ./scripts/deploy_forcad_vds.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
FORCAD_DIR="${FORCAD_DIR:-$HOME/ForcAD}"   # ForcAD кладём в путь БЕЗ кириллицы
NET="adrange"
SUBNET="10.10.1.0/24"
IPS=(10.10.1.1 10.10.1.2 10.10.1.3)        # == forcad/config.yml -> teams[].ip
SVCS=("notes:5001" "pingtool:5002" "vault:5003")

echo "==> [1/7] Пакеты (docker, git, python3)..."
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER" 2>/dev/null || true
  echo "    Docker поставлен. Если ругнётся на права — перелогинься и запусти скрипт заново."
fi
command -v git     >/dev/null 2>&1 || { sudo apt-get update -y && sudo apt-get install -y git; }
command -v python3 >/dev/null 2>&1 || { sudo apt-get update -y && sudo apt-get install -y python3 python3-pip; }

echo "==> [2/7] Клонирую ForcAD в $FORCAD_DIR ..."
if [ ! -d "$FORCAD_DIR/.git" ]; then
  git clone https://github.com/pomo-mondreganto/ForcAD "$FORCAD_DIR"
else
  echo "    уже склонирован, пропускаю."
fi

echo "==> [3/7] Копирую наши чекеры + requirements.txt в $FORCAD_DIR/checkers ..."
mkdir -p "$FORCAD_DIR/checkers"
cp -r "$REPO/forcad/checkers/." "$FORCAD_DIR/checkers/"
# чекеры ForcAD бегут от nobody -> им нужен world read+exec
chmod -R o+rX "$FORCAD_DIR/checkers"
find "$FORCAD_DIR/checkers" -name 'checker.py' -exec chmod o+rx {} \;

echo "==> [4/7] Подставляю наш config.yml ..."
cp "$REPO/forcad/config.yml" "$FORCAD_DIR/config.yml"
echo "    teams[].ip = ${IPS[*]} (статические адреса вулнбоксов в сети $NET)."
echo "    ВАЖНО: открой/выстави start_time в $FORCAD_DIR/config.yml перед стартом игры."

echo "==> [5/7] Общая сеть $NET + 3 вулнбокса (static IP, 3 сервиса на каждом)..."
docker network inspect "$NET" >/dev/null 2>&1 || docker network create --subnet "$SUBNET" "$NET"
# образы наших сервисов (один раз)
for name in notes pingtool vault; do
  docker build -t "addojo/$name" "$REPO/services/$name"
done
for i in 0 1 2; do
  team=$((i+1)); ip="${IPS[$i]}"
  # анкер держит статический IP; остальные контейнеры разделяют его сетевой namespace
  docker rm -f "vb${team}" >/dev/null 2>&1 || true
  docker run -d --name "vb${team}" --hostname "vb${team}" \
    --network "$NET" --ip "$ip" --restart unless-stopped \
    --entrypoint sleep addojo/notes infinity
  for pair in "${SVCS[@]}"; do
    name="${pair%%:*}"; port="${pair##*:}"
    extra=(); [ "$name" = "pingtool" ] && extra=(-e DATA_DIR=/data)
    docker rm -f "vb${team}_${name}" >/dev/null 2>&1 || true
    docker run -d --name "vb${team}_${name}" --restart unless-stopped \
      --network "container:vb${team}" "${extra[@]}" \
      "addojo/${name}" gunicorn -w 1 --threads 8 -b "0.0.0.0:${port}" app:app
  done
  echo "    vb${team} @ ${ip}: notes:5001 pingtool:5002 vault:5003"
done

echo "==> [6/7] Поднимаю ForcAD и подключаю его celery к сети $NET ..."
cd "$FORCAD_DIR"
python3 ./control.py setup
python3 ./control.py start --fast
# celery-контейнер(ы) ForcAD гоняют чекеры -> им нужен доступ к вулнбоксам в $NET
sleep 5
mapfile -t CELERY < <(docker ps --format '{{.Names}}' | grep -iE 'celery' || true)
if [ "${#CELERY[@]}" -eq 0 ]; then
  echo "    !! celery-контейнер не найден — подключи вручную:"
  echo "       docker ps  # найди имя celery"
  echo "       docker network connect $NET <имя_celery>"
else
  for c in "${CELERY[@]}"; do
    docker network connect "$NET" "$c" 2>/dev/null && echo "    подключил $c -> $NET" || echo "    $c уже в сети"
  done
fi

echo "==> [7/7] Токены команд:"
python3 ./control.py print_tokens || true

PUB="$(curl -s https://ifconfig.me 2>/dev/null || echo '<IP-ВДС>')"
cat <<EOF

================================================================
  ГОТОВО (проверь, что чекеры зелёные в админке!).
  Scoreboard / admin / flower:  http://${PUB}:8080  (/admin/, /flower/)
  Открой в фаерволе ВДС порт 8080.

  Перед каждой новой игрой:   cd $FORCAD_DIR && python3 ./control.py reset && ./control.py start --fast
                              затем заново подключи celery: docker network connect $NET <celery>

  DestructiveFarm (ферма сдачи флагов) — ставим отдельно:
    git clone https://github.com/DestructiveVoice/DestructiveFarm && cd DestructiveFarm/server
    В server/config.py:  FLAG_FORMAT=r'[A-Z0-9]{31}=',
      TEAMS={'team2':'10.10.1.2','team3':'10.10.1.3'},  # бей по ботам, не по себе
      SYSTEM_PROTOCOL='ructf_http',              # НЕ forcad_tcp: в ForcAD теперь только HTTP-приёмник
      SYSTEM_URL='http://${PUB}:8080/flags/',    # PUT, заголовок X-Team-Token, JSON-список флагов
      SYSTEM_TOKEN=<твой токен из print_tokens выше>
    ./start_server.sh  -> веб фермы на :5000, клиенты шлют флаги из sploits/.
    Эталонные сплойты: $REPO/exploits_reference/*.py
================================================================
EOF
