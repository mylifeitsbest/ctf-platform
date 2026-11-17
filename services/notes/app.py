"""notes — простой сервис заметок.

A/D-учебный сервис. Флаги чекер кладёт как приватные заметки.
Здесь намеренно оставлены уязвимости — ваша задача на тренировке найти и закрыть их,
НЕ сломав SLA (регистрация -> создание заметки -> чтение своей заметки).
"""
import base64
import os
import pickle
import secrets
from flask import Flask, request, jsonify

app = Flask(__name__)

USERS = {}          # username -> {"password":..., "token":...}
TOKENS = {}         # token -> username
NOTES = {}          # id -> {"owner":..., "title":..., "body":...}
NEXT_ID = 1


def whoami():
    tok = request.headers.get("Authorization", "")
    return TOKENS.get(tok)


@app.get("/health")
def health():
    return jsonify(status="ok", service="notes")


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


@app.post("/notes")
def create_note():
    global NEXT_ID
    user = whoami()
    if not user:
        return jsonify(error="auth required"), 401
    d = request.get_json(force=True, silent=True) or {}
    nid = NEXT_ID
    NEXT_ID += 1
    NOTES[nid] = {"owner": user, "title": d.get("title", ""), "body": d.get("body", "")}
    return jsonify(id=nid)


@app.get("/notes")
def list_notes():
    user = whoami()
    if not user:
        return jsonify(error="auth required"), 401
    mine = [{"id": i, "title": n["title"]} for i, n in NOTES.items() if n["owner"] == user]
    return jsonify(notes=mine)


@app.get("/note/<int:nid>")
def get_note(nid):
    # Отдаёт заметку по id.
    n = NOTES.get(nid)
    if not n:
        return jsonify(error="not found"), 404
    return jsonify(id=nid, owner=n["owner"], title=n["title"], body=n["body"])


@app.get("/export")
def export_notes():
    user = whoami()
    if not user:
        return jsonify(error="auth required"), 401
    mine = {i: n for i, n in NOTES.items() if n["owner"] == user}
    blob = base64.b64encode(pickle.dumps(mine)).decode()
    return jsonify(data=blob)


@app.post("/restore")
def restore_notes():
    user = whoami()
    if not user:
        return jsonify(error="auth required"), 401
    d = request.get_json(force=True, silent=True) or {}
    raw = base64.b64decode(d.get("data", ""))
    obj = pickle.loads(raw)
    cnt = 0
    for _i, n in (obj or {}).items():
        if isinstance(n, dict):
            global NEXT_ID
            NOTES[NEXT_ID] = {"owner": user, "title": n.get("title", ""), "body": n.get("body", "")}
            NEXT_ID += 1
            cnt += 1
    return jsonify(restored=cnt)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
