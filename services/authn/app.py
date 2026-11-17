"""authn — сервис аутентификации с «тайником» (stash).

A/D-учебный сервис. Токен авторизации — это JWT. Флаги чекер кладёт в /stash.
SLA: register -> login -> /stash set -> /stash get (чтение СВОЕГО секрета).

Криптография токенов тут слабая НАМЕРЕННО — ищите, чем это пахнет, и чините так,
чтобы register/login/stash продолжали работать (иначе упадёт SLA).
"""
import os
from flask import Flask, request, jsonify
import jwt  # PyJWT

app = Flask(__name__)

# Слабый, захардкоженный секрет. Он же лежит в исходниках образа, одинакового
# у всех команд, — значит, подписать им токен может кто угодно.
SECRET = "secret"
ALG = "HS256"

USERS = {}      # username -> {"password": ...}
STASH = {}      # username -> flag/secret


def current(req):
    """Достаёт claims из JWT в заголовке Authorization.

    УЯЗВИМОСТЬ: подпись фактически не проверяется (принимается alg:none и слабый
    секрет "secret"), поэтому admin-токен тривиально подделывается.
    """
    tok = req.headers.get("Authorization", "")
    if not tok:
        return None
    try:
        return jwt.decode(
            tok, SECRET,
            algorithms=["HS256", "none"],
            options={"verify_signature": False},
        )
    except jwt.PyJWTError:
        return None


@app.get("/health")
def health():
    return jsonify(status="ok", service="authn")


@app.post("/register")
def register():
    d = request.get_json(force=True, silent=True) or {}
    u, p = d.get("username"), d.get("password")
    if not u or not p:
        return jsonify(error="username/password required"), 400
    if u in USERS:
        return jsonify(error="exists"), 409
    USERS[u] = {"password": p}
    tok = jwt.encode({"user": u, "admin": False}, SECRET, algorithm=ALG)
    return jsonify(token=tok)


@app.post("/login")
def login():
    d = request.get_json(force=True, silent=True) or {}
    u, p = d.get("username"), d.get("password")
    rec = USERS.get(u)
    if not rec or rec["password"] != p:
        return jsonify(error="bad creds"), 401
    tok = jwt.encode({"user": u, "admin": False}, SECRET, algorithm=ALG)
    return jsonify(token=tok)


@app.post("/stash")
def stash_set():
    claims = current(request)
    if not claims:
        return jsonify(error="auth required"), 401
    user = claims.get("user")
    if not user:
        return jsonify(error="auth required"), 401
    d = request.get_json(force=True, silent=True) or {}
    STASH[user] = d.get("secret", "")
    return jsonify(ok=True)


@app.get("/stash")
def stash_get():
    claims = current(request)
    if not claims:
        return jsonify(error="auth required"), 401
    user = claims.get("user")
    if not user:
        return jsonify(error="auth required"), 401
    return jsonify(secret=STASH.get(user))


@app.get("/admin/dump")
def admin_dump():
    claims = current(request)
    if not claims:
        return jsonify(error="auth required"), 401
    if not claims.get("admin"):
        return jsonify(error="forbidden"), 403
    return jsonify(secrets=list(STASH.values()))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
