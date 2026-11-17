"""vault — хранилище секретов.

Флаги чекер кладёт через /seal. SLA: register -> seal -> reveal (round-trip).
Криптография тут слабая намеренно — ищите, чем это пахнет, и чините так,
чтобы seal/reveal продолжали работать (иначе упадёт SLA).
"""
import os
import secrets
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

# Один ключ на всех. Он же лежит в исходниках образа, одинакового у всех команд.
KEY = b"dojo-fixed-key!!"       # 16 байт, AES-128
BLOBS = {}                       # id(int) -> ciphertext(bytes)
OWNER = {}                       # id -> token
USERS = {}                       # username -> {"password","token"}
TOKENS = {}                      # token -> username
NEXT_ID = 1


def whoami():
    return TOKENS.get(request.headers.get("Authorization", ""))


def enc(pt: str) -> bytes:
    c = AES.new(KEY, AES.MODE_ECB)
    return c.encrypt(pad(pt.encode(), 16))


def dec(ct: bytes) -> str:
    c = AES.new(KEY, AES.MODE_ECB)
    return unpad(c.decrypt(ct), 16).decode(errors="replace")


@app.get("/health")
def health():
    return jsonify(status="ok", service="vault")


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


@app.post("/seal")
def seal():
    global NEXT_ID
    user = whoami()
    if not user:
        return jsonify(error="auth required"), 401
    d = request.get_json(force=True, silent=True) or {}
    secret = d.get("secret", "")
    sid = NEXT_ID
    NEXT_ID += 1
    BLOBS[sid] = enc(secret)
    OWNER[sid] = USERS[user]["token"]
    return jsonify(id=sid)


@app.get("/reveal/<int:sid>")
def reveal(sid):
    user = whoami()
    if not user:
        return jsonify(error="auth required"), 401
    if sid not in BLOBS or OWNER.get(sid) != USERS[user]["token"]:
        return jsonify(error="forbidden"), 403
    return jsonify(id=sid, secret=dec(BLOBS[sid]))


@app.get("/blob/<int:sid>")
def blob(sid):
    # Экспорт зашифрованного секрета для «шаринга».
    if sid not in BLOBS:
        return jsonify(error="not found"), 404
    return jsonify(id=sid, ciphertext=BLOBS[sid].hex())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
