# -*- coding: utf-8 -*-
"""Нативная проверка ForcAD-чекеров без Docker/ForcAD.

Поднимаем каждый уязвимый сервис в потоке (werkzeug) и гоняем его checker.py
ровно так, как это делает ForcAD (pfr): check -> put -> get(private flag_id).
Проверяем коды выхода Hackerdom: OK=101, CORRUPT=102, MUMBLE=103, DOWN=104, ERROR=110.
"""
import importlib.util
import os
import random
import string
import subprocess
import sys
import tempfile
import threading
import time

import requests
from werkzeug.serving import make_server

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # корень репозитория
VENV_PY = sys.executable
OK, CORRUPT, MUMBLE, DOWN, ERROR = 101, 102, 103, 104, 110

# pingtool читает DATA_DIR при импорте — задаём ДО загрузки модулей
TMP = tempfile.mkdtemp(prefix="pingdata_")
os.environ["DATA_DIR"] = TMP


def load(mod, path):
    spec = importlib.util.spec_from_file_location(mod, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[mod] = m
    spec.loader.exec_module(m)
    return m


def serve(app, port):
    s = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=s.serve_forever, daemon=True).start()


def wait(port):
    for _ in range(80):
        try:
            requests.get(f"http://127.0.0.1:{port}/health", timeout=1)
            return True
        except Exception:
            time.sleep(0.05)
    return False


def gen_flag():
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=31)) + "="


def run_checker(svc, action, host, *args, port):
    env = os.environ.copy()
    env["CHECKER_PORT"] = str(port)
    path = os.path.join(REPO, "forcad", "checkers", svc, "checker.py")
    cp = subprocess.run([VENV_PY, path, action, host, *args],
                        capture_output=True, text=True, env=env, timeout=40)
    private = ""
    errlines = [ln for ln in cp.stderr.splitlines() if ln.strip()]
    if errlines:
        private = errlines[-1].strip()
    return cp.returncode, cp.stdout.strip(), private, cp.stderr


results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"   [{detail}]" if detail and not cond else ""))


# --- поднимаем сервисы ---
notes = load("notes_app", os.path.join(REPO, "services", "notes", "app.py"))
pingtool = load("pingtool_app", os.path.join(REPO, "services", "pingtool", "app.py"))
vault = load("vault_app", os.path.join(REPO, "services", "vault", "app.py"))

PORTS = {"notes": 5001, "pingtool": 5002, "vault": 5003}
serve(notes.app, PORTS["notes"])
serve(pingtool.app, PORTS["pingtool"])
serve(vault.app, PORTS["vault"])
for svc, port in PORTS.items():
    assert wait(port), f"{svc} did not come up on {port}"

print("=== сервисы подняты, гоняем чекеры как ForcAD (pfr) ===\n")

for svc in ("notes", "pingtool", "vault"):
    port = PORTS[svc]
    print(f"----- {svc} -----")
    flag = gen_flag()

    rc, _, _, err = run_checker(svc, "check", "127.0.0.1", port=port)
    check(f"{svc}: check -> OK", rc == OK, f"rc={rc} err={err[-200:]}")

    rc, public, private, err = run_checker(svc, "put", "127.0.0.1", "nonce123", flag, "0", port=port)
    check(f"{svc}: put -> OK", rc == OK, f"rc={rc} err={err[-200:]}")
    check(f"{svc}: put вернул public (attack_data)", bool(public), f"public={public!r}")
    check(f"{svc}: put вернул private flag_id", bool(private) and ":" in private, f"private={private!r}")

    rc, _, _, err = run_checker(svc, "get", "127.0.0.1", private, flag, "0", port=port)
    check(f"{svc}: get(правильный флаг) -> OK", rc == OK, f"rc={rc} err={err[-200:]}")

    rc, _, _, err = run_checker(svc, "get", "127.0.0.1", private, gen_flag(), "0", port=port)
    check(f"{svc}: get(ЧУЖОЙ флаг) -> CORRUPT", rc == CORRUPT, f"rc={rc} err={err[-200:]}")

    # сервис недоступен -> DOWN
    rc, _, _, err = run_checker(svc, "check", "127.0.0.1", port=5999)
    check(f"{svc}: мёртвый порт -> DOWN", rc == DOWN, f"rc={rc}")
    print()

ok = sum(results)
print(f"=== {ok}/{len(results)} PASS ===")
sys.exit(0 if ok == len(results) else 1)
