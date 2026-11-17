"""portal — тренировочный полигон A/D.

Вход по имени -> список живых заданий -> ты сам достаёшь флаг из сервиса и
сдаёшь его сюда -> РЕАЛЬНАЯ проверка (через scoreboard) -> засчитывается.
Плюс проверка патча: портал гоняет эталонный эксплойт по твоему боксу.
Командный лидерборд.
"""
import glob
import importlib.util
import json
import os
import re
import sqlite3
import time

import requests
from flask import Flask, request, session, redirect, jsonify, Response

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET", "dojo-portal-secret-change-me")

SCOREBOARD = os.environ.get("SCOREBOARD", "http://scoreboard:8080")
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "localhost")
DB = os.environ.get("PORTAL_DB", "/data/portal.db")
FLAG_RE = re.compile(r"[A-Z0-9]{31}=")
os.makedirs(os.path.dirname(DB) or ".", exist_ok=True)

with open(os.path.join(os.path.dirname(__file__), "game.json"), encoding="utf-8") as f:
    CFG = json.load(f)
SERVICES = CFG["services"]
TEAMS = CFG["teams"]
MY_TEAM = next((t for t in TEAMS if t.get("owner") == "practice-you"), TEAMS[0])
TARGET = next((t for t in TEAMS if t.get("owner") == "bot"), TEAMS[-1])

# метаданные заданий берём из game.json (поле "challenge" у сервиса), с дефолтами
_DEFAULT_HINTS = {
    "notes": ["Сравни проверку владельца в <code>GET /notes</code> и в <code>GET /note/&lt;id&gt;</code>.",
              "IDOR: <code>/note/&lt;id&gt;</code> отдаёт любую заметку без проверки владельца — перебирай id.",
              "Патч: в get_note сверяй владельца с whoami(), иначе 403."],
    "pingtool": ["Как формируется и запускается команда ping в <code>/diag</code>?",
                 "<code>shell=True</code> + конкатенация host. Пейлоад <code>127.0.0.1; cat /data/*/*</code>.",
                 "Патч: убери shell (<code>subprocess.run([...], shell=False)</code>) и/или валидируй host."],
    "vault": ["Все ли эндпоинты требуют авторизацию? Какой режим AES и откуда ключ?",
              "<code>/blob/&lt;id&gt;</code> без авторизации + фикс-ключ <code>dojo-fixed-key!!</code> → AES-ECB расшифровывается оффлайн.",
              "Патч: закрой <code>/blob</code> авторизацией/убери его; плюс случайный ключ при старте."],
}


def _meta_for(s):
    name = s["name"]
    ch = s.get("challenge", {}) or {}
    return {
        "title": ch.get("title", name),
        "cls": ch.get("cls", s.get("vuln", "")),
        "desc": ch.get("desc", "Найди дыру в сервисе, достань флаг и сдай его, потом запатчи свой бокс."),
        "points": ch.get("points", 100),
        "hints": ch.get("hints", _DEFAULT_HINTS.get(name, [])),
    }


META = {s["name"]: _meta_for(s) for s in SERVICES}


def svc_index(name):
    for i, s in enumerate(SERVICES):
        if s["name"] == name:
            return i
    return 0


def target_url(name):
    return f"http://{PUBLIC_HOST}:{TARGET['host_port_base'] + svc_index(name)}"


def my_internal(name):
    return f"http://{name}_{MY_TEAM['name']}:5000"


# ---------- db ----------
def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, created REAL);
    CREATE TABLE IF NOT EXISTS solves(user TEXT, challenge TEXT, kind TEXT, ts REAL,
        PRIMARY KEY(user, challenge, kind));
    """)
    c.commit()
    c.close()


init()


def user():
    return session.get("user")


def solved(u, ch, kind):
    c = db()
    r = c.execute("SELECT 1 FROM solves WHERE user=? AND challenge=? AND kind=?", (u, ch, kind)).fetchone()
    c.close()
    return bool(r)


def mark(u, ch, kind):
    c = db()
    c.execute("INSERT OR IGNORE INTO solves VALUES(?,?,?,?)", (u, ch, kind, time.time()))
    c.commit()
    c.close()


def user_points(u):
    c = db()
    rows = c.execute("SELECT challenge, kind FROM solves WHERE user=?", (u,)).fetchall()
    c.close()
    pts = 0
    for r in rows:
        pts += META.get(r["challenge"], {}).get("points", 100)
    return pts


# ---------- эталонные атаки: единый источник из sploits/ (кладёт gen_compose) ----------
# Каждый sploits/<svc>_sploit.py задаёт SERVICE и exploit(host, port) -> list[флагов].
# Портал зовёт их для автопроверки патча (это те же сплойты, что и у бота-противника).
def _load_attacks():
    out = {}
    sdir = os.path.join(os.path.dirname(__file__), "sploits")
    for path in sorted(glob.glob(os.path.join(sdir, "*_sploit.py"))):
        name = os.path.basename(path)[:-3]
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            print(f"[portal] сплойт {name} не загрузился: {e}", flush=True)
            continue
        svc = getattr(mod, "SERVICE", None)
        fn = getattr(mod, "exploit", None)
        if svc and callable(fn):
            out[svc] = fn
    return out


ATTACKS = _load_attacks()


def health_ok(base):
    try:
        return requests.get(f"{base}/health", timeout=3).json().get("status") == "ok"
    except requests.RequestException:
        return False


# ---------- UI ----------
CSS = """
:root{--bg:#0a0b0d;--bg2:#101216;--bg3:#161920;--line:#242934;--tx:#e7e9ee;--mut:#9aa4b2;
--dim:#616b7a;--acc:#6ee7a8;--accd:#2c6b4a;--accbg:#0f1a14;--red:#f0637a;--redbg:#1b0f13;--warn:#e8b765}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font:16px/1.6 Inter,system-ui,-apple-system,sans-serif}
a{color:var(--acc);text-decoration:none}
code,.mono{font-family:"JetBrains Mono",ui-monospace,Consolas,monospace}
.nav{display:flex;align-items:center;gap:16px;padding:14px 22px;border-bottom:1px solid var(--line);
background:#0b0d10;position:sticky;top:0;z-index:5}
.nav .b{font-family:"JetBrains Mono",monospace;font-weight:700}.nav .b b{color:var(--acc)}
.nav a{color:var(--mut);font-size:14px}.nav a:hover{color:var(--tx)}
.nav .sp{flex:1}
.wrap{max-width:900px;margin:0 auto;padding:28px 20px 80px}
h1{font-size:26px;margin:0 0 4px;font-family:"Space Grotesk",sans-serif}
h2{font-size:20px;font-family:"Space Grotesk",sans-serif;margin:0 0 6px}
.sub{color:var(--mut);margin:0 0 22px}
.card{display:block;background:var(--bg2);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin:14px 0}
.ch{display:flex;align-items:center;gap:14px}
.ch .t{flex:1;min-width:0}
.ch h3{margin:0;font-size:17px}
.tag{font-family:"JetBrains Mono",monospace;font-size:11px;padding:3px 9px;border-radius:999px;border:1px solid var(--line);color:var(--mut)}
.pts{font-family:"JetBrains Mono",monospace;color:var(--mut);font-size:13px}
.badge{font-family:"JetBrains Mono",monospace;font-size:12px;padding:3px 10px;border-radius:999px}
.badge.ok{background:var(--accbg);color:var(--acc);border:1px solid var(--accd)}
.badge.no{background:var(--bg3);color:var(--dim);border:1px solid var(--line)}
input[type=text]{font-family:"JetBrains Mono",monospace;background:#07080a;border:1px solid var(--line);color:var(--tx);
border-radius:9px;padding:11px 13px;font-size:14px;width:100%;outline:none}
input:focus{border-color:var(--accd)}
.btn{display:inline-block;font-weight:600;font-size:14px;border-radius:9px;padding:10px 16px;cursor:pointer;
border:1px solid var(--line);background:var(--bg3);color:var(--tx)}
.btn:hover{background:#1b1f27}
.btn.p{background:var(--acc);color:#07140c;border-color:var(--acc)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.msg{padding:12px 15px;border-radius:10px;margin:14px 0;font-size:14.5px}
.msg.ok{background:var(--accbg);border:1px solid var(--accd);color:var(--acc)}
.msg.bad{background:var(--redbg);border:1px solid #50222e;color:var(--red)}
.callout{border-left:3px solid var(--acc);background:var(--accbg);border-radius:0 10px 10px 0;padding:12px 15px;margin:14px 0}
table{width:100%;border-collapse:collapse;margin-top:10px}
th,td{padding:11px 14px;text-align:left;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.06em;font-family:"JetBrains Mono",monospace}
.me{color:var(--acc)}
.center{min-height:72vh;display:flex;align-items:center;justify-content:center}
.login{max-width:380px;width:100%;text-align:center}
.step{font-family:"JetBrains Mono",monospace;color:var(--dim);font-size:12px;margin:18px 0 4px;text-transform:uppercase;letter-spacing:.08em}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
"""


def page(title, body, show_nav=True):
    nav = ""
    if show_nav and user():
        nav = (f'<div class="nav"><span class="b">A/D<b>_</b>Полигон</span>'
               f'<a href="/">задания</a><a href="/leaderboard">лидерборд</a>'
               f'<span class="sp"></span><span class="pts">{user()} · {user_points(user())} очк.</span>'
               f'<a href="/logout">выйти</a></div>')
    return Response(f"<!doctype html><html lang=ru><head><meta charset=utf-8>"
                    f"<meta name=viewport content='width=device-width,initial-scale=1'>"
                    f"<title>{title}</title><style>{CSS}</head><body>{nav}<div class='wrap'>{body}</div></body></html>",
                    mimetype="text/html")


@app.get("/")
def index():
    if not user():
        body = """<div class="center"><div class="login">
          <h1>A/D Полигон</h1>
          <p class="sub">Войди под своим именем, чтобы учиться на живых сервисах и сдавать настоящие флаги.</p>
          <form method="post" action="/login" class="row" style="flex-direction:column">
            <input type="text" name="name" placeholder="твоё имя (напр. Рома)" autofocus required>
            <button class="btn p" style="width:100%">Войти →</button>
          </form></div></div>"""
        return page("Вход · A/D Полигон", body, show_nav=False)
    u = user()
    cards = ""
    for s in SERVICES:
        name = s["name"]
        m = META.get(name, {"title": name, "cls": s.get("vuln", ""), "points": 100})
        a = "ok" if solved(u, name, "attack") else "no"
        p = "ok" if solved(u, name, "patch") else "no"
        cards += (f'<a class="card ch" href="/c/{name}">'
                  f'<div class="t"><h3>{m["title"]}</h3>'
                  f'<span class="tag">{m["cls"]}</span> <span class="pts">{m["points"]} очк.</span></div>'
                  f'<span class="badge {a}">атака {"✓" if a=="ok" else "—"}</span>'
                  f'<span class="badge {p}">патч {"✓" if p=="ok" else "—"}</span></a>')
    body = (f'<h1>Задания</h1><p class="sub">Открой сервис, сам найди дыру, достань флаг и сдай его. '
            f'Потом запатчи свой бокс и проверь.</p>{cards}')
    return page("Задания · A/D Полигон", body)


@app.post("/login")
def login():
    name = (request.form.get("name", "") or "").strip()[:24]
    if name:
        c = db()
        c.execute("INSERT OR IGNORE INTO users VALUES(?,?)", (name, time.time()))
        c.commit()
        c.close()
        session["user"] = name
    return redirect("/")


@app.get("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")


@app.get("/c/<name>")
def challenge(name):
    if not user():
        return redirect("/")
    if name not in META:
        return redirect("/")
    m = META[name]
    msg = request.args.get("m", "")
    msg_html = ""
    if msg == "ok":
        msg_html = '<div class="msg ok">✓ Флаг верный! Атака засчитана.</div>'
    elif msg == "bad":
        msg_html = '<div class="msg bad">✗ Флаг не принят: неверный или протух. Достань свежий из сервиса.</div>'
    elif msg == "patched":
        msg_html = '<div class="msg ok">🛡 Патч засчитан: эксплойт больше не достаёт флаг, а сервис жив (SLA ок).</div>'
    elif msg == "notpatched":
        msg_html = '<div class="msg bad">✗ Дыра ещё открыта — эталонный эксплойт достал флаг из твоего бокса. Патчи дальше.</div>'
    elif msg == "down":
        msg_html = '<div class="msg bad">✗ Сервис не отвечает на /health — ты его сломал патчем. Почини (SLA важнее).</div>'
    a = solved(user(), name, "attack")
    p = solved(user(), name, "patch")
    hints_html = ""
    if m.get("hints"):
        items = "".join(
            f'<details style="background:var(--bg3);border:1px solid var(--line);border-radius:9px;'
            f'padding:8px 14px;margin:8px 0"><summary style="cursor:pointer;color:var(--warn)">'
            f'Подсказка {i + 1}</summary><div style="padding:8px 0 4px">{h}</div></details>'
            for i, h in enumerate(m["hints"]))
        hints_html = (f'<div style="margin:14px 0"><div class="step">Застрял? Подсказки '
                      f'(сначала попробуй сам)</div>{items}</div>')
    body = f"""
      <a href="/" style="color:var(--mut);font-size:13px">← ко всем заданиям</a>
      <h1 style="margin-top:10px">{m['title']}</h1>
      <p class="sub"><span class="tag">{m['cls']}</span> · {m['points']} очк.</p>
      {msg_html}
      <div class="callout">{m['desc']}</div>
      {hints_html}

      <div class="step">Шаг 1 — атака {'✓ сделано' if a else ''}</div>
      <div class="card">
        <p>Открой живой сервис соперника и достань из него флаг (сам, руками или эксплойтом):</p>
        <p class="row"><a class="btn" href="{target_url(name)}" target="_blank">Открыть сервис → {target_url(name)}</a></p>
        <form method="post" action="/submit" class="row" style="margin-top:12px">
          <input type="hidden" name="svc" value="{name}">
          <input type="text" name="flag" placeholder="вставь найденный флаг: XXXX...=" style="flex:1;min-width:220px">
          <button class="btn p">Сдать флаг</button>
        </form>
      </div>

      <div class="step">Шаг 2 — защита {'✓ сделано' if p else ''}</div>
      <div class="card">
        <p>Запатчи <b>свой</b> бокс (<code>{name}_{MY_TEAM['name']}</code>) в <code>services/{name}/app.py</code>,
        пересобери (<code>docker compose up -d --build {name}_{MY_TEAM['name']}</code>) и жми проверку —
        портал прогонит эталонный эксплойт по твоему боксу.</p>
        <form method="post" action="/patch/{name}">
          <button class="btn p">Проверить мой патч</button>
        </form>
      </div>
    """
    return page(m["title"] + " · A/D Полигон", body)


@app.post("/submit")
def submit():
    if not user():
        return redirect("/")
    svc = request.form.get("svc", "")
    flag = (request.form.get("flag", "") or "").strip()
    try:
        r = requests.get(f"{SCOREBOARD}/api/check", params={"flag": flag}, timeout=5).json()
    except requests.RequestException:
        r = {"valid": False}
    if r.get("valid") and r.get("service") == svc:
        mark(user(), svc, "attack")
        return redirect(f"/c/{svc}?m=ok")
    return redirect(f"/c/{svc}?m=bad")


@app.post("/patch/<name>")
def patch(name):
    if not user():
        return redirect("/")
    if name not in ATTACKS:
        return redirect("/")
    host = f"{name}_{MY_TEAM['name']}"
    if not health_ok(my_internal(name)):
        return redirect(f"/c/{name}?m=down")
    try:
        stolen = ATTACKS[name](host, 5000)
    except Exception:
        stolen = []
    if stolen:
        return redirect(f"/c/{name}?m=notpatched")
    mark(user(), name, "patch")
    return redirect(f"/c/{name}?m=patched")


@app.get("/leaderboard")
def leaderboard():
    if not user():
        return redirect("/")
    c = db()
    users = [r["name"] for r in c.execute("SELECT name FROM users").fetchall()]
    c.close()
    rows = sorted(((u, user_points(u)) for u in users), key=lambda x: -x[1])
    trs = ""
    for i, (u, pts) in enumerate(rows, 1):
        me = ' class="me"' if u == user() else ""
        trs += f"<tr><td>{i}</td><td{me}>{u}</td><td class='mono'>{pts}</td></tr>"
    if not trs:
        trs = "<tr><td colspan=3 style='color:var(--dim)'>пока никто не вошёл</td></tr>"
    body = (f'<h1>Лидерборд команды</h1><p class="sub">Очки за атаку и патч по каждому заданию.</p>'
            f'<table><tr><th>#</th><th>игрок</th><th>очки</th></tr>{trs}</table>')
    return page("Лидерборд · A/D Полигон", body)


@app.get("/health")
def health():
    return jsonify(status="ok", service="portal")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 9000)))
