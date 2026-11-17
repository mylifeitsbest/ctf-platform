"""attacker_bot — автоматический противник.

Гоняет эталонные атаки по ВСЕМ командам (включая вашу team1!) и сабмитит флаги
как 'attacker_bot'. Пока вы не запатчите свои сервисы — он крадёт и ваши флаги
(в табло это столбец «потеряно»). Запатчили — его добыча с вашей команды падает.
Это и есть смысл защиты: сделать так, чтобы бот (и живые соперники) ничего не брали.
"""
import glob
import importlib.util
import json
import os
import re
import time

import requests

FLAG = re.compile(os.environ.get("FLAG_REGEX", r"[A-Z0-9]{31}="))
SCOREBOARD = os.environ.get("SCOREBOARD", "http://scoreboard:8080")
ROUND_TIME = int(os.environ.get("ROUND_TIME", "30"))
PORT = 5000

with open(os.path.join(os.path.dirname(__file__), "game.json"), encoding="utf-8") as f:
    CFG = json.load(f)
TEAMS = [t["name"] for t in CFG["teams"]]
SERVICES = [s["name"] for s in CFG["services"]]


# эталонные атаки грузятся из sploits/ (единый источник, кладёт gen_compose) —
# те же сплойты, что у портала. Бот атакует ЛЮБОЙ сервис, у которого есть сплойт.
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
            print(f"[bot] сплойт {name} не загрузился: {e}", flush=True)
            continue
        svc = getattr(mod, "SERVICE", None)
        fn = getattr(mod, "exploit", None)
        if svc and callable(fn):
            out[svc] = fn
    return out


ATTACKS = _load_attacks()


def main():
    print(f"attacker_bot: цели {TEAMS}, сервисы {SERVICES}", flush=True)
    time.sleep(12)
    while True:
        t0 = time.time()
        flags = set()
        for team in TEAMS:
            for svc in SERVICES:
                fn = ATTACKS.get(svc)
                if not fn:
                    continue
                try:
                    flags |= set(fn(f"{svc}_{team}", PORT))
                except Exception as e:
                    print(f"[bot] {svc}/{team}: {e}", flush=True)
        if flags:
            try:
                r = requests.post(SCOREBOARD + "/submit", data="\n".join(flags),
                                  headers={"X-Team": "attacker_bot"}, timeout=10)
                print(f"[bot] сабмит: {r.json().get('accepted')} из {len(flags)}", flush=True)
            except requests.RequestException as e:
                print(f"[bot] сабмит не прошёл: {e}", flush=True)
        time.sleep(max(1, ROUND_TIME - (time.time() - t0)))


if __name__ == "__main__":
    main()
