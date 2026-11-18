# combat — боевая ферма для финала (ForcAD + DestructiveFarm)

Это **боевой** набор сплойтов для реального A/D-финала, в отличие от:

- `exploits_reference/` — эталоны для самопроверки в обучающем портале (`exploit(host, port)`-функции);
- `farm/` — обучающая ферма с собственным `farm.py` против локального стека.

Здесь сплойты в **нативном формате DestructiveFarm**: самостоятельный скрипт,
`argv[1] = IP жертвы`, порт — `argv[2]` или env `PORT`, **флаги печатаются в stdout
построчно**. Это ровно то, что ждёт `start_sploit.py` из DestructiveFarm.

```
combat/
  requirements.txt
  sploits/
    notes.py      # IDOR            (порт по умолч. 5001)
    pingtool.py   # command injection (5002)
    vault.py      # weak crypto / AES-ECB fixed key (5003)
    blog.py       # SQL injection   (5004)
    gallery.py    # path traversal  (5005)
    profile.py    # SSTI (Jinja2)   (5006)
    authn.py      # JWT forgery     (5007)
```

## Установка

```bash
pip install -r combat/requirements.txt
```

`vault.py` требует `pycryptodome`, `authn.py` — `PyJWT`, остальным хватает `requests`.

## Проверка одиночного сплойта

Формат: `python combat/sploits/<svc>.py <IP> [порт]`. Порт можно задать и через env `PORT`,
формат флага — через `FLAG_FORMAT` (по умолчанию `[A-Z0-9]{31}=`).

Против локального обучающего стека (team1 = порты 5100–5106):

```bash
python combat/sploits/notes.py    127.0.0.1 5100
python combat/sploits/pingtool.py 127.0.0.1 5101
python combat/sploits/vault.py    127.0.0.1 5102
python combat/sploits/blog.py     127.0.0.1 5103
python combat/sploits/gallery.py  127.0.0.1 5104
python combat/sploits/profile.py  127.0.0.1 5105
python combat/sploits/authn.py    127.0.0.1 5106
```

Если скрипт печатает строки вида `A1B2...=`, сплойт жив.

## Подключение к DestructiveFarm (реальный финал)

1. Поднимаем сервер DestructiveFarm и в `server/config.py` ставим под текущий ForcAD
   (проверено в этом репо, см. память/коммит 58d1e4e — у ForcAD сейчас только HTTP-ресивер):

   ```python
   SYSTEM_PROTOCOL = 'ructf_http'
   SYSTEM_URL      = 'http://<forcad-host>:8080/flags/'   # PUT, заголовок X-Team-Token
   SYSTEM_TOKEN    = '<наш токен из ./control.py print_tokens>'
   FLAG_FORMAT     = r'[A-Z0-9]{31}='
   TEAMS           = {'team2': '10.60.2.2', ...}           # IP чужих команд
   ```

   `forcad_tcp` НЕ использовать — он для старого TCP-ресивера (31337), которого больше нет.

2. Копируем нужные сплойты в каталог DestructiveFarm-клиента и запускаем на каждую команду:

   ```bash
   ./start_sploit.py combat/sploits/blog.py --server-url http://<farm>:5000 -u <user> -p <pass>
   ```

   DestructiveFarm сам прогонит сплойт по всем целям (IP → `argv[1]`), выдернет флаги из stdout
   по `FLAG_FORMAT` и отправит их на ForcAD пачками. Порт сервиса на боевых хостах общий —
   задаём его env `PORT` или вторым аргументом в обёртке сплойта.

> На локальном стеке порт у каждой команды свой (5100/5200/5300 + индекс сервиса).
> На ForcAD один сервис слушает один порт на всех хостах — тогда дефолтные 5001–5007
> (или свой `PORT`) и один `start_sploit.py` на сервис.
