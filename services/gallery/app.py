"""gallery — файловая галерея с публичной лентой последних загрузок.

A/D-учебный сервис. Флаги чекер кладёт как загруженные файлы (/upload).
Здесь намеренно оставлена уязвимость (path traversal / broken access control):
  * /recent (БЕЗ авторизации) раскрывает пути хранения последних загрузок
    в виде "<token16>/<name>";
  * /download?path=... (тоже БЕЗ авторизации) открывает os.path.join(DATA, path)
    НЕ ограничивая путь каталогом пользователя и не проверяя владельца.
Связка /recent + /download позволяет кому угодно читать чужие файлы (там флаги).

Задача на тренировке — закрыть это, НЕ сломав SLA:
  register -> login -> upload -> чтение своего файла через безопасный /get/<name>.
"""
import os
import secrets
from flask import Flask, request, jsonify

app = Flask(__name__)
DATA = os.environ.get("DATA_DIR", "/data")
USERS = {}      # username -> {"password":..., "token":...}
TOKENS = {}     # token -> username
RECENT = []     # лента последних загрузок: ["<token16>/<name>", ...]

os.makedirs(DATA, exist_ok=True)


def whoami():
    tok = request.headers.get("Authorization", "")
    return TOKENS.get(tok)


def userdir(token):
    d = os.path.join(DATA, token[:16])
    os.makedirs(d, exist_ok=True)
    return d


@app.get("/health")
def health():
    return jsonify(status="ok", service="gallery")


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
    userdir(tok)
    return jsonify(token=tok)


@app.post("/login")
def login():
    d = request.get_json(force=True, silent=True) or {}
    u, p = d.get("username"), d.get("password")
    rec = USERS.get(u)
    if not rec or rec["password"] != p:
        return jsonify(error="bad creds"), 401
    return jsonify(token=rec["token"])


@app.post("/upload")
def upload():
    user = whoami()
    if not user:
        return jsonify(error="auth required"), 401
    tok = USERS[user]["token"]
    d = request.get_json(force=True, silent=True) or {}
    name = os.path.basename(d.get("name", ""))
    if not name:
        return jsonify(error="name required"), 400
    with open(os.path.join(userdir(tok), name), "w", encoding="utf-8") as f:
        f.write(d.get("content", ""))
    RECENT.append(f"{tok[:16]}/{name}")
    del RECENT[:-100]
    return jsonify(saved=name)


@app.get("/myfiles")
def myfiles():
    user = whoami()
    if not user:
        return jsonify(error="auth required"), 401
    tok = USERS[user]["token"]
    return jsonify(files=sorted(os.listdir(userdir(tok))))


@app.get("/recent")
def recent():
    # Публичная лента последних загрузок. Раскрывает пути хранения ("<token16>/<name>").
    items = [{"path": p} for p in RECENT[-20:]]
    return jsonify(items=items)


@app.get("/download")
def download():
    # Отдаёт файл по пути path. path НЕ ограничен каталогом пользователя и НЕ
    # требует авторизации -> path traversal / чтение чужих файлов.
    p = request.args.get("path", "")
    if not p:
        return jsonify(error="path required"), 400
    path = os.path.join(DATA, p)
    if not os.path.isfile(path):
        return jsonify(error="not found"), 404
    with open(path, "r", encoding="utf-8") as f:
        return jsonify(path=p, content=f.read())


@app.get("/get/<name>")
def get(name):
    user = whoami()
    if not user:
        return jsonify(error="auth required"), 401
    tok = USERS[user]["token"]
    path = os.path.join(userdir(tok), os.path.basename(name))
    if not os.path.exists(path):
        return jsonify(error="not found"), 404
    with open(path, "r", encoding="utf-8") as f:
        return jsonify(name=name, content=f.read())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
