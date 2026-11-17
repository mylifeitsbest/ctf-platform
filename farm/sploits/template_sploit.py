"""ШАБЛОН сплойта. Скопируй в <сервис>_sploit.py и реализуй exploit().

Ферма вызывает exploit(host, port) по каждой команде-цели и собирает то,
что ты вернёшь. Возвращай список строк — ферма сама отфильтрует по регекспу флага
и сделает сабмит. Таймауты ставь маленькие (2-3с): целей много, раунд короткий.
"""
import requests

# Пока SERVICE = None — ферма этот файл игнорирует.
# Для рабочего сплойта: SERVICE = "notes" / "pingtool" / "vault".
SERVICE = None


def exploit(host, port):
    base = f"http://{host}:{port}"
    flags = []
    # ... твоя атака ...
    # r = requests.get(base + "/...", timeout=3)
    # flags += re.findall(r"[A-Z0-9]{31}=", r.text)
    return flags
