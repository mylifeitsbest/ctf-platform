"""Главный цикл чекера.

Каждый раунд для каждой (команда, сервис):
  1) генерит флаг, кладёт его в сервис (put_flag) и регистрирует в scoreboard;
  2) проверяет функциональность (check_sla);
  3) проверяет, что флаг прошлого раунда ещё достаётся (get_flag) — персистентность;
  4) шлёт статус UP/MUMBLE/DOWN в scoreboard.
"""
import json
import os
import random
import string
import sys
import time

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "checkers"))

ROUND_TIME = int(os.environ.get("ROUND_TIME", "30"))
SCOREBOARD = os.environ.get("SCOREBOARD", "http://scoreboard:8080")
PORT = 5000

with open(os.path.join(os.path.dirname(__file__), "game.json"), encoding="utf-8") as f:
    CFG = json.load(f)

TEAMS = [t["name"] for t in CFG["teams"]]
SERVICES = [s["name"] for s in CFG["services"]]
TTL = int(CFG.get("flag_ttl_rounds", 5))

CHECKERS = {}
for s in CFG["services"]:
    mod = __import__(s["checker"][:-3])  # notes_checker.py -> notes_checker
    CHECKERS[s["name"]] = mod


def gen_flag():
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=31)) + "="


# state[(service, team)] = { round: (flag, flag_id) }
STATE = {(s, t): {} for s in SERVICES for t in TEAMS}


def sb_post(path, payload):
    try:
        requests.post(SCOREBOARD + path, json=payload, timeout=5)
    except Exception as e:
        print(f"[sb] ошибка {path}: {e}", flush=True)


def tick(rnd):
    for team in TEAMS:
        for svc in SERVICES:
            mod = CHECKERS[svc]
            host = f"{svc}_{team}"
            status = "UP"
            flag = gen_flag()
            # 1) put flag
            try:
                fid = mod.put_flag(host, PORT, flag)
                STATE[(svc, team)][rnd] = (flag, fid)
                sb_post("/flags", {"flag": flag, "service": svc, "team": team, "round": rnd})
            except Exception as e:
                status = "DOWN"
                print(f"[{svc}/{team}] put_flag: {e}", flush=True)
            # 2) functional SLA
            if status == "UP":
                try:
                    if not mod.check_sla(host, PORT):
                        status = "MUMBLE"
                except Exception as e:
                    status = "DOWN"
                    print(f"[{svc}/{team}] check_sla: {e}", flush=True)
            # 3) persistence прошлого флага
            if status == "UP":
                prev = STATE[(svc, team)].get(rnd - 1)
                if prev:
                    try:
                        if not mod.get_flag(host, PORT, prev[1], prev[0]):
                            status = "MUMBLE"
                    except Exception:
                        status = "MUMBLE"
            sb_post("/result", {"service": svc, "team": team, "round": rnd, "status": status})
            print(f"[r{rnd}] {svc}/{team}: {status}", flush=True)
            # чистка старше TTL
            for old in [r for r in STATE[(svc, team)] if r <= rnd - TTL]:
                STATE[(svc, team)].pop(old, None)


def main():
    print(f"checker: {len(TEAMS)} команд × {len(SERVICES)} сервисов, "
          f"раунд {ROUND_TIME}с, scoreboard={SCOREBOARD}", flush=True)
    time.sleep(8)  # дать сервисам и scoreboard подняться
    rnd = 0
    while True:
        rnd += 1
        t0 = time.time()
        tick(rnd)
        dt = time.time() - t0
        time.sleep(max(1, ROUND_TIME - dt))


if __name__ == "__main__":
    main()
