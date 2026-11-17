# A/D Dojo — тренировочная платформа Attack-Defense

Локальный стенд, чтобы за 3 дня натаскать команду на Attack-Defense: уязвимые сервисы,
чекер с ротацией флагов и SLA, табло очков, ферма эксплойтов и бот-противник.

Всё на Python, запускается в Docker на одной машине (Windows + Docker Desktop).

---

## Быстрый старт (5 минут)

1. Запусти **Docker Desktop** и дождись, пока он полностью стартует (кит в трее перестанет мигать).
2. В PowerShell из корня проекта:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\up.ps1
```

3. Открой:
   - **Табло:** http://localhost:8080
   - **Учебный дашборд:** файл `dashboard\index.html` (двойной клик) — вся теория, план на 3 дня, роли и чеклисты.

4. Запусти ферму (на этой же или на соседней машине):

```powershell
cd farm
pip install -r requirements.txt
python farm.py
```

Ферма сначала пустая — сплойты пишете вы (см. дашборд). Чтобы увидеть, как всё работает «из коробки», залей эталонные:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\load_reference_sploits.ps1
```

---

## Что внутри

| Папка | Что это |
|---|---|
| `config/game.json` | Единый конфиг: команды, сервисы, длина раунда. **Правь тут.** |
| `services/` | Уязвимые сервисы: `notes` (IDOR+pickle), `pingtool` (инъекция команд), `vault` (слабая крипта). |
| `gameserver/checker/` | Чекер: каждый раунд кладёт флаги и проверяет SLA. |
| `gameserver/scoreboard/` | Табло + приём флагов (`/submit`). |
| `gameserver/attacker_bot/` | Бот-противник: крадёт флаги у всех, кто не запатчился. |
| `farm/` | Ферма эксплойтов (запускается у игрока). Ваши сплойты — в `farm/sploits/`. |
| `exploits_reference/` | Эталонные эксплойты + разбор уязвимостей и патчей. **Сначала пробуйте сами.** |
| `dashboard/index.html` | Учебный дашборд: теория, план, роли, чеклисты. |
| `scripts/` | `up` / `down` / `reset` / `status` / `load_reference_sploits`. |

---

## Команды

```powershell
powershell -File scripts\up.ps1       # собрать и поднять
powershell -File scripts\status.ps1   # контейнеры + текущий счёт
powershell -File scripts\down.ps1     # остановить
powershell -File scripts\reset.ps1    # полный сброс (обнулить счёт) и поднять заново
docker compose logs -f checker        # смотреть, как чекер гоняет раунды
```

## Масштабирование под матч в среду

Чтобы из тренировки сделать матч на 5 человек «каждый сам за себя» — в `config/game.json`
сделай 5 команд (team1..team5, у каждой свой `host_port_base`: 5100, 5200, …), раздай
каждому игроку свою команду (он её патчит), и все запускают ферму с `--team teamN`.
Потом `scripts\up.ps1` пересоберёт стенд. Подробности и правила матча — в дашборде.

---

## Деплой на ВДС (Linux) — для матча в среду

На Linux-ВДС стенд идёт проще, чем на Windows. Пример для Ubuntu/Debian:

```bash
# 1) Docker + compose + python (один раз)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER   # перелогиниться после этого
sudo apt-get install -y python3 python3-pip

# 2) Скопировать проект на ВДС (scp/git/rsync), затем:
cd ad-dojo
chmod +x scripts/*.sh
PUBLIC_HOST=<публичный-IP-ВДС> ./scripts/up.sh
```

- **Табло:** `http://<IP-ВДС>:8080`
- Открой в фаерволе/security-group ВДС порты: **8080** (табло) и диапазон портов сервисов (**5100–55xx** — по числу команд).
- `PUBLIC_HOST=<IP>` прописывает этот IP в `farm/targets.json`, чтобы ферма **с ноутбуков игроков** била по ВДС. Если все запускают ферму прямо на ВДС (по SSH), можно без `PUBLIC_HOST` — там работает `127.0.0.1`.
- Для матча на 5 человек: 5 команд в `config/game.json`, каждому своя `teamN`, все запускают `python3 farm.py --team teamN`. Правила и раздача ролей — в дашборде, раздел «Матч в среду».

> ВДС не Linux (Windows Server)? Тогда там те же `scripts\*.ps1`, что и локально.

## Если что-то не так

- **`docker info` ругается / скрипт пишет «Docker не запущен»** — Docker Desktop ещё не стартовал. Подожди минуту.
- **Порт занят** — поменяй `host_port_base`/`scoreboard_port` в `config/game.json` и `up.ps1` заново.
- **`python` не найден** — поставь Python 3 и поставь галку «Add to PATH».
- **Путь с кириллицей** (`C:\ctf платформа`) — стенд это терпит (код копируется внутрь образов, без монтирования). Но если Docker на твоей сборке капризничает — перенеси проект в `C:\ad-dojo`.
