"""Утилиты для чекеров: HTTP и генерация случайных данных."""
import random
import string
import requests

TIMEOUT = 5


def rnd(n=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def base(host, port):
    return f"http://{host}:{port}"


def post(host, port, path, json=None, headers=None):
    return requests.post(base(host, port) + path, json=json, headers=headers, timeout=TIMEOUT)


def get(host, port, path, headers=None):
    return requests.get(base(host, port) + path, headers=headers, timeout=TIMEOUT)


def register(host, port):
    """Общий helper: регистрирует пользователя, возвращает (user, pass, token)."""
    u, p = rnd(8), rnd(12)
    r = post(host, port, "/register", json={"username": u, "password": p})
    r.raise_for_status()
    return u, p, r.json()["token"]
