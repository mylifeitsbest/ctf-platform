# forcad/ — наш реальный A/D-стенд на ForcAD

Это слой «настоящей практики»: мы играем на **ForcAD** (той самой платформе финала) +
ферма **DestructiveFarm**. Здесь лежит то, что нужно, чтобы наши учебные сервисы
стали полноценными заданиями ForcAD.

## Что уже готово и ПРОВЕРЕНО ✅
- `checkers/notes/checker.py`, `checkers/pingtool/checker.py`, `checkers/vault/checker.py`
  — ForcAD-совместимые чекеры (checklib, протокол Hackerdom, тег **pfr**).
- Проверены нативно (без Docker), 21/21:
  `check→OK(101)`, `put→OK` (отдаёт public=attack_data и private=flag_id),
  `get(верный флаг)→OK`, `get(чужой флаг)→CORRUPT(102)`, мёртвый сервис→`DOWN(104)`.
- `config.yml` — черновик игрового конфига ForcAD (3 задания, 3 команды).
- `checkers/requirements.txt` — зависимости чекеров (ForcAD ставит обязательно).
- `vulnbox/docker-compose.yml` — вулнбокс команды: 3 сервиса на 5001/5002/5003
  (ровно те порты, что зашиты в чекерах).
- `test_checkers.py` — нативный тест чекеров (durable, в репозитории).

Ключевая идея чекеров: **SLA-путь идёт через авторизованное чтение владельцем**, а
эксплойт — через дырку (IDOR / command injection / слабая крипта). Поэтому правильный
патч закрывает дырку, но НЕ роняет SLA. Именно этому учимся.

| сервис   | дырка (что ищем и чиним)                    | чем снимает флаг атакующий            |
|----------|---------------------------------------------|---------------------------------------|
| notes    | IDOR: `GET /note/<id>` без авторизации       | перебор id, читаем чужую заметку       |
| pingtool | command injection в `/diag`                  | `host=127.0.0.1; cat /data/*/*`        |
| vault    | `GET /blob/<id>` без авторизации + ключ AES-ECB зашит | забираем шифртекст, дешифруем оффлайн |

## Что осталось — делается на ВДС (нужен доступ/запуск)
1. `git clone https://github.com/pomo-mondreganto/ForcAD` на ВДС.
2. Скопировать `forcad/checkers/*` (вместе с `checkers/requirements.txt`) в каталог
   `checkers/` ForcAD. На Linux выставить бит: `chmod -R o+rx checkers` (чекеры
   бегут от `nobody`). Подставить `forcad/config.yml` и вписать реальные IP
   вулнбоксов в `teams[].ip`, выставить `start_time`.
3. Поднять по одному **вулнбоксу на команду** из `forcad/vulnbox/docker-compose.yml`
   (notes:5001, pingtool:5002, vault:5003) — каждый на своём IP.
   **Порты зашиты в чекерах** (ForcAD не прокидывает `CHECKER_PORT` в чекер,
   меняет только `$PATH`), поэтому per-task порт задавать НЕ нужно — просто один
   вулнбокс = один IP = одна команда.
4. `./control.py setup && ./control.py start --fast` → scoreboard на `:8080`.
5. **DestructiveFarm**: клиент-сервер, протокол сдачи — **ForcAD** (из коробки),
   `server/config.py`: TEAMS = IP вулнбоксов, FLAG_FORMAT = `[A-Z0-9]{31}=`.
   Сюда кладём эталонные сплойты — ферма и учит, и играет за «соперников».
6. (День 2) добавить реальные сервисы из прошлых игр: `explorers` (XXE→JWT),
   `msp` (бэкдор) — у них уже есть checklib-чекеры и сплойты.

## Проверить чекеры локально ещё раз
Нативный тест: `forcad/test_checkers.py` (поднимает сервисы в потоках и гоняет
чекеры как ForcAD: check→put→get своего/чужого флага, мёртвый порт). Последний
прогон — **21/21 PASS**. Требует `checklib==0.7.0`, `requests`, `flask`,
`pycryptodome`, `werkzeug`:

```bash
python -m venv venv && . venv/bin/activate   # или venv\Scripts\activate на Windows
pip install checklib==0.7.0 requests flask pycryptodome
python forcad/test_checkers.py
```
