"""farm — ферма эксплойтов (запускается на машине игрока).

Что делает каждый раунд:
  - по каждой команде-цели (кроме своей) запускает подходящий сплойт из sploits/;
  - собирает флаги, кидает их в scoreboard одним сабмитом (заголовок X-Team).

Свои сплойты кладите в farm/sploits/<сервис>_sploit.py:
    SERVICE = "notes"
    def exploit(host, port) -> list[str]:  # вернуть найденные флаги
Эталонные решения — в exploits_reference/ (сначала попробуйте сами!).

Запуск:
    pip install -r requirements.txt
    python farm.py                 # цикл
    python farm.py --once          # один проход
    python farm.py --team team1    # кем представиться (по умолчанию из FARM_TEAM или team1)
"""
import argparse
import importlib.util
import json
import os
import re
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))


def load_targets():
    with open(os.path.join(HERE, "targets.json"), encoding="utf-8") as f:
        return json.load(f)


def load_sploits():
    """Импортирует все *_sploit.py из sploits/, возвращает {service: exploit_fn}."""
    out = {}
    sdir = os.path.join(HERE, "sploits")
    for fn in sorted(os.listdir(sdir)):
        if not fn.endswith("_sploit.py"):
            continue
        path = os.path.join(sdir, fn)
        spec = importlib.util.spec_from_file_location(fn[:-3], path)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as e:
            print(f"[farm] сплойт {fn} не загрузился: {e}")
            continue
        svc = getattr(mod, "SERVICE", None)
        fn_exploit = getattr(mod, "exploit", None)
        if svc and callable(fn_exploit):
            out[svc] = fn_exploit
            print(f"[farm] загружен сплойт для сервиса '{svc}' из {fn}")
    return out


def submit(scoreboard, team, flags):
    if not flags:
        return {}
    r = requests.post(scoreboard + "/submit", data="\n".join(flags),
                      headers={"X-Team": team}, timeout=10)
    return r.json()


def one_pass(cfg, sploits, my_team, flag_re):
    scoreboard = cfg["scoreboard"]
    all_flags = set()
    for tgt in cfg["teams"]:
        if tgt["team"] == my_team:
            continue
        for svc, loc in tgt["services"].items():
            if svc not in sploits:
                continue
            try:
                found = sploits[svc](loc["host"], loc["port"]) or []
                good = [f for f in found if flag_re.fullmatch(f)]
                if good:
                    print(f"  [{svc} @ {tgt['team']}] +{len(good)} флагов")
                all_flags |= set(good)
            except Exception as e:
                print(f"  [{svc} @ {tgt['team']}] ошибка: {e}")
    res = submit(scoreboard, my_team, list(all_flags))
    if res:
        acc = res.get("accepted", 0)
        print(f"==> сабмит: {acc} ACCEPTED из {len(all_flags)} (как '{my_team}')")
    return all_flags


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--team", default=os.environ.get("FARM_TEAM", "team1"))
    args = ap.parse_args()

    cfg = load_targets()
    flag_re = re.compile(cfg["flag_regex"])
    sploits = load_sploits()
    if not sploits:
        print("[farm] НЕТ рабочих сплойтов в farm/sploits/. "
              "Напиши свой или скопируй из exploits_reference/ "
              "(scripts/load_reference_sploits.ps1).")
    interval = cfg.get("round_time", 30)
    print(f"[farm] представляюсь как '{args.team}', цель-раунд ~{interval}с\n")
    while True:
        t0 = time.time()
        one_pass(cfg, sploits, args.team, flag_re)
        if args.once:
            break
        time.sleep(max(1, interval - (time.time() - t0)))


if __name__ == "__main__":
    sys.exit(main())
