"""pingtool — панель сетевой диагностики + хранилище заметок диагностики.

Флаги чекер кладёт через /save (они ложатся в файлы на диске).
SLA: register -> save -> get (round-trip). Уязвимость искать в /diag.
"""
import os
import secrets
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)
DATA = os.environ.get("DATA_DIR", "/data")
USERS = {}      # username -> {"password":..., "token":..., "dir":...}
TOKENS = {}     # token -> username

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
    return jsonify(status="ok", service="pingtool")


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


@app.post("/save")
def save():
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
    return jsonify(saved=name)


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


@app.post("/diag")
def diag():
    # Пингует указанный хост и возвращает вывод.
    d = request.get_json(force=True, silent=True) or {}
    host = d.get("host", "127.0.0.1")
    cmd = "ping -c 1 -W 1 " + host
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True,
                             text=True, timeout=5)
        return jsonify(cmd=cmd, stdout=out.stdout, stderr=out.stderr, code=out.returncode)
    except subprocess.TimeoutExpired:
        return jsonify(error="timeout"), 504


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
