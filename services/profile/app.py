"""profile — рендерер «карточек профиля».

A/D-учебный сервис. Флаги чекер кладёт как приватные секреты (/secret).
Здесь намеренно оставлена уязвимость — ваша задача на тренировке найти и закрыть её,
НЕ сломав SLA (регистрация -> сохранить bio -> получить карточку с этим же текстом).

Идея сервиса: пользователь задаёт себе «bio», а /card рендерит его как
HTML-карточку. Шаблон bio пропускается через Jinja2, так что в нём можно
использовать плейсхолдеры вида {{ username }}. Вот только контекст рендера
слишком щедрый...
"""
import os
import secrets
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

USERS = {}      # username -> {"password":..., "token":...}
TOKENS = {}     # token -> username
SECRETS = {}    # username -> flag (сюда чекер кладёт флаг через /secret)
BIOS = {}       # username -> bio (СЫРАЯ строка-шаблон, как её прислал пользователь)


def whoami():
    tok = request.headers.get("Authorization", "")
    return TOKENS.get(tok)


@app.get("/health")
def health():
    return jsonify(status="ok", service="profile")


@app.post("/register")
def register():
    d = request.get_json(force=True, silent=True) or {}
    u, p = d.get("username"), d.get("password")
    if not u or not p:
        return jsonify(error="username/password required"), 400
    if u in USERS:
        return jsonify(error="exists"), 409
    tok = secrets.token_hex(16)
    USERS[u] = {"password": p, "token": tok}
    TOKENS[tok] = u
    return jsonify(token=tok)


@app.post("/login")
def login():
    d = request.get_json(force=True, silent=True) or {}
    u, p = d.get("username"), d.get("password")
    rec = USERS.get(u)
    if not rec or rec["password"] != p:
        return jsonify(error="bad creds"), 401
    return jsonify(token=rec["token"])


@app.post("/secret")
def set_secret():
    user = whoami()
    if not user:
        return jsonify(error="auth required"), 401
    d = request.get_json(force=True, silent=True) or {}
    SECRETS[user] = d.get("secret", "")
    return jsonify(ok=True)


@app.get("/secret")
def get_secret():
    # Владелец читает свой собственный секрет (SLA-путь).
    user = whoami()
    if not user:
        return jsonify(error="auth required"), 401
    return jsonify(secret=SECRETS.get(user, ""))


@app.post("/bio")
def set_bio():
    user = whoami()
    if not user:
        return jsonify(error="auth required"), 401
    d = request.get_json(force=True, silent=True) or {}
    BIOS[user] = d.get("bio", "")
    return jsonify(ok=True)


@app.get("/card")
def card():
    user = whoami()
    if not user:
        return jsonify(error="auth required"), 401
    bio = BIOS.get(user, "")
    # Рендерим bio как Jinja2-шаблон, чтобы работали плейсхолдеры типа {{ username }}.
    # В контекст заодно прокидываем secrets=SECRETS «чтобы было удобно» — и вот это зря.
    html = render_template_string(bio, username=user, secrets=SECRETS)
    return jsonify(card=html)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
