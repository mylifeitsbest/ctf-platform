"""scoreboard — приём флагов + табло очков.

Внутренние эндпоинты (зовёт чекер):
    POST /flags    {flag, service, team, round}      — зарегистрировать выданный флаг
    POST /result   {service, team, round, status}    — SLA-результат (UP/DOWN/MUMBLE)
Публичные:
    POST /submit   заголовок X-Team: <имя>; тело — флаги (по одному на строку или JSON {"flags":[...]})
    GET  /api/scoreboard                             — JSON
    GET  /                                           — HTML табло (автообновление)
"""
import os
import re
import sqlite3
import time
from flask import Flask, request, jsonify, Response

app = Flask(__name__)
DB = os.environ.get("SCOREBOARD_DB", "/data/scoreboard.db")
FLAG_RE = re.compile(os.environ.get("FLAG_REGEX", r"[A-Z0-9]{31}="))
TTL = int(os.environ.get("FLAG_TTL_ROUNDS", "5"))

os.makedirs(os.path.dirname(DB) or ".", exist_ok=True)


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS flags(
        flag TEXT PRIMARY KEY, service TEXT, team TEXT, round INTEGER, ts REAL);
    CREATE TABLE IF NOT EXISTS results(
        service TEXT, team TEXT, round INTEGER, status TEXT, ts REAL);
    CREATE TABLE IF NOT EXISTS subs(
        flag TEXT, attacker TEXT, victim TEXT, service TEXT, ts REAL,
        PRIMARY KEY(flag, attacker));
    CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
    """)
    c.commit()
    c.close()


def cur_round():
    c = db()
    r = c.execute("SELECT MAX(round) m FROM flags").fetchone()
    c.close()
    return r["m"] or 0


@app.post("/flags")
def add_flag():
    d = request.get_json(force=True, silent=True) or {}
    c = db()
    c.execute("INSERT OR IGNORE INTO flags VALUES(?,?,?,?,?)",
              (d["flag"], d["service"], d["team"], int(d["round"]), time.time()))
    c.commit()
    c.close()
    return jsonify(ok=True)


@app.post("/result")
def add_result():
    d = request.get_json(force=True, silent=True) or {}
    c = db()
    c.execute("INSERT INTO results VALUES(?,?,?,?,?)",
              (d["service"], d["team"], int(d["round"]), d["status"], time.time()))
    c.commit()
    c.close()
    return jsonify(ok=True)


@app.post("/submit")
def submit():
    attacker = request.headers.get("X-Team", "").strip()
    if not attacker:
        return jsonify(error="X-Team header required"), 400
    body = request.get_data(as_text=True) or ""
    flags = []
    if body.strip().startswith("{"):
        j = request.get_json(force=True, silent=True) or {}
        flags = j.get("flags", [])
    else:
        flags = FLAG_RE.findall(body)
    now_round = cur_round()
    c = db()
    out = {}
    for fl in flags:
        row = c.execute("SELECT service, team, round FROM flags WHERE flag=?", (fl,)).fetchone()
        if not row:
            out[fl] = "INVALID"
            continue
        if row["team"] == attacker:
            out[fl] = "OWN"
            continue
        if now_round - row["round"] >= TTL:
            out[fl] = "EXPIRED"
            continue
        try:
            c.execute("INSERT INTO subs VALUES(?,?,?,?,?)",
                      (fl, attacker, row["team"], row["service"], time.time()))
            out[fl] = "ACCEPTED"
        except sqlite3.IntegrityError:
            out[fl] = "DUPLICATE"
    c.commit()
    c.close()
    accepted = sum(1 for v in out.values() if v == "ACCEPTED")
    return jsonify(accepted=accepted, results=out)


def compute():
    c = db()
    teams = [r["team"] for r in c.execute(
        "SELECT DISTINCT team FROM flags WHERE team != 'attacker_bot'").fetchall()]
    scores = {}
    for t in teams:
        attack = c.execute("SELECT COUNT(*) n FROM subs WHERE attacker=?", (t,)).fetchone()["n"]
        lost = c.execute("SELECT COUNT(DISTINCT flag) n FROM subs WHERE victim=?", (t,)).fetchone()["n"]
        up = c.execute("SELECT COUNT(*) n FROM results WHERE team=? AND status='UP'", (t,)).fetchone()["n"]
        tot = c.execute("SELECT COUNT(*) n FROM results WHERE team=?", (t,)).fetchone()["n"]
        sla = round(100.0 * up / tot, 1) if tot else 0.0
        scores[t] = {"attack": attack, "lost": lost, "sla": sla,
                     "score": attack - lost + round(sla / 10)}
    # атакующий бот показываем отдельно (для ориентира)
    bot = c.execute("SELECT COUNT(*) n FROM subs WHERE attacker='attacker_bot'").fetchone()["n"]
    c.close()
    return scores, bot, cur_round()


@app.get("/api/scoreboard")
def api():
    scores, bot, rnd = compute()
    return jsonify(round=rnd, bot_attack=bot, teams=scores)


@app.get("/api/check")
def api_check():
    """Проверка флага для портала-тренажёра: валиден ли (свежий) и какого сервиса."""
    flag = (request.args.get("flag", "") or "").strip()
    c = db()
    row = c.execute("SELECT service, team, round FROM flags WHERE flag=?", (flag,)).fetchone()
    nowr = cur_round()
    c.close()
    if not row:
        return jsonify(valid=False, reason="unknown")
    if nowr - row["round"] >= TTL:
        return jsonify(valid=False, reason="expired", service=row["service"])
    return jsonify(valid=True, service=row["service"], team=row["team"])


PAGE = """<!doctype html><html lang=ru><head><meta charset=utf-8>
<meta http-equiv=refresh content=5><title>A/D Dojo — табло</title>
<style>
body{background:#0b0e14;color:#d7dce5;font:15px/1.5 ui-monospace,Consolas,monospace;margin:0;padding:24px}
h1{color:#7cf;font-size:20px;margin:0 0 4px}.sub{color:#5a6472;margin-bottom:18px}
table{border-collapse:collapse;width:100%;max-width:760px}
th,td{padding:8px 14px;text-align:left;border-bottom:1px solid #1c2330}
th{color:#8aa;text-transform:uppercase;font-size:12px;letter-spacing:.05em}
td.n{text-align:right;font-variant-numeric:tabular-nums}
.pos{color:#5bd68a}.neg{color:#e85d75}.sla{color:#f0b84b}
tr:first-child td{font-weight:700}.bot{color:#5a6472;margin-top:16px}
</style></head><body>
<h1>A/D Dojo — табло</h1><div class=sub>раунд {{rnd}} · обновление каждые 5с</div>
<table><tr><th>#</th><th>команда</th><th class=n>атака</th><th class=n>потеряно</th>
<th class=n>SLA</th><th class=n>очки</th></tr>{{rows}}</table>
<div class=bot>attacker_bot украл флагов: {{bot}} (ориентир: столько даёт «тупая» эталонная атака)</div>
</body></html>"""


@app.get("/")
def index():
    scores, bot, rnd = compute()
    ordered = sorted(scores.items(), key=lambda kv: kv[1]["score"], reverse=True)
    rows = ""
    for i, (t, s) in enumerate(ordered, 1):
        rows += (f"<tr><td>{i}</td><td>{t}</td>"
                 f"<td class='n pos'>{s['attack']}</td>"
                 f"<td class='n neg'>{s['lost']}</td>"
                 f"<td class='n sla'>{s['sla']}%</td>"
                 f"<td class='n'>{s['score']}</td></tr>")
    html = PAGE.replace("{{rnd}}", str(rnd)).replace("{{rows}}", rows).replace("{{bot}}", str(bot))
    return Response(html, mimetype="text/html")


init()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
