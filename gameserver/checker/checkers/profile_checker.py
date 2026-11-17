"""Чекер profile. SLA: register -> save bio -> GET /card возвращает этот текст.

Флаг кладётся как приватный секрет (/secret) и читается владельцем через GET /secret.
"""
import json
import checker_lib as L

SERVICE = "profile"


def put_flag(host, port, flag):
    u, p, tok = L.register(host, port)
    r = L.post(host, port, "/secret", json={"secret": flag},
               headers={"Authorization": tok})
    r.raise_for_status()
    return json.dumps({"u": u, "p": p})


def get_flag(host, port, flag_id, flag):
    d = json.loads(flag_id)
    r = L.post(host, port, "/login", json={"username": d["u"], "password": d["p"]})
    if r.status_code != 200:
        return False
    tok = r.json()["token"]
    # владелец читает свой секрет с токеном
    r = L.get(host, port, "/secret", headers={"Authorization": tok})
    return r.status_code == 200 and r.json().get("secret") == flag


def check_sla(host, port):
    if L.get(host, port, "/health").json().get("status") != "ok":
        return False
    u, p, tok = L.register(host, port)
    bio = L.rnd(20)
    rb = L.post(host, port, "/bio", json={"bio": bio}, headers={"Authorization": tok})
    if rb.status_code != 200:
        return False
    r = L.get(host, port, "/card", headers={"Authorization": tok})
    return r.status_code == 200 and bio in (r.json().get("card") or "")
