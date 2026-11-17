"""blog — простой блог с постами.

A/D-учебный сервис. Флаги чекер кладёт как приватные посты.
Здесь намеренно оставлена уязвимость — ваша задача на тренировке найти и закрыть её,
НЕ сломав SLA (регистрация -> логин -> создание поста -> чтение своего поста).

Хранилище — SQLite (stdlib sqlite3), файл /data/blog.db.
"""
import os
import secrets
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_DIR = "/data"
DB_PATH = os.path.join(DB_DIR, "blog.db")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            token TEXT
        );
        CREATE TABLE IF NOT EXISTS posts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT,
            title TEXT,
            body TEXT,
            private INTEGER NOT NULL DEFAULT 1
        );
        """
    )
    conn.commit()
    conn.close()


def whoami():
    tok = request.headers.get("Authorization", "")
    if not tok:
        return None
    conn = db()
    row = conn.execute("SELECT username FROM users WHERE token=?", (tok,)).fetchone()
    conn.close()
    return row["username"] if row else None


@app.get("/health")
def health():
    return jsonify(status="ok", service="blog")


@app.post("/register")
def register():
    d = request.get_json(force=True, silent=True) or {}
    u, p = d.get("username"), d.get("password")
    if not u or not p:
        return jsonify(error="username/password required"), 400
    conn = db()
    if conn.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
        conn.close()
        return jsonify(error="exists"), 409
    tok = secrets.token_hex(16)
    conn.execute("INSERT INTO users(username,password,token) VALUES(?,?,?)", (u, p, tok))
    conn.commit()
    conn.close()
    return jsonify(token=tok)


@app.post("/login")
def login():
    d = request.get_json(force=True, silent=True) or {}
    u, p = d.get("username"), d.get("password")
    conn = db()
    row = conn.execute("SELECT password, token FROM users WHERE username=?", (u,)).fetchone()
    conn.close()
    if not row or row["password"] != p:
        return jsonify(error="bad creds"), 401
    return jsonify(token=row["token"])


@app.post("/posts")
def create_post():
    user = whoami()
    if not user:
        return jsonify(error="auth required"), 401
    d = request.get_json(force=True, silent=True) or {}
    title = d.get("title", "")
    body = d.get("body", "")
    private = d.get("private", 1)          # по умолчанию приватный
    priv = 1 if private else 0
    conn = db()
    cur = conn.execute(
        "INSERT INTO posts(owner,title,body,private) VALUES(?,?,?,?)",
        (user, title, body, priv),
    )
    conn.commit()
    pid = cur.lastrowid
    conn.close()
    return jsonify(id=pid)


@app.get("/posts")
def list_posts():
    user = whoami()
    if not user:
        return jsonify(error="auth required"), 401
    conn = db()
    rows = conn.execute("SELECT id,title FROM posts WHERE owner=?", (user,)).fetchall()
    conn.close()
    return jsonify(posts=[{"id": r["id"], "title": r["title"]} for r in rows])


@app.get("/post/<int:pid>")
def get_post(pid):
    user = whoami()
    if not user:
        return jsonify(error="auth required"), 401
    conn = db()
    row = conn.execute(
        "SELECT id,owner,title,body,private FROM posts WHERE id=?", (pid,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify(error="not found"), 404
    if row["private"] and row["owner"] != user:
        return jsonify(error="forbidden"), 403
    return jsonify(id=row["id"], title=row["title"], body=row["body"], private=row["private"])


@app.get("/search")
def search():
    # Поиск по публичным постам (private=0) с совпадением по заголовку.
    # УЯЗВИМОСТЬ: запрос собирается конкатенацией строк, пользовательский ввод q
    # попадает в SQL без экранирования -> SQL-инъекция (UNION / комментарий).
    q = request.args.get("q", "")
    sql = "SELECT id,title,body FROM posts WHERE private=0 AND title LIKE '%" + q + "%'"
    conn = db()
    try:
        rows = conn.execute(sql).fetchall()
    except sqlite3.Error as e:
        conn.close()
        return jsonify(error=f"query error: {e}"), 400
    conn.close()
    # индексное обращение к колонкам, чтобы работали UNION-пейлоады с любыми именами
    return jsonify(results=[{"id": r[0], "title": r[1], "body": r[2]} for r in rows])


init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
