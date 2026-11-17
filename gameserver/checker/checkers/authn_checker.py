"""Чекер authn. SLA: register -> login -> /stash set -> /stash get (своё)."""
import json
import checker_lib as L

SERVICE = "authn"


def put_flag(host, port, flag):
    u, p, tok = L.register(host, port)
    r = L.post(host, port, "/stash", json={"secret": flag}, headers={"Authorization": tok})
    r.raise_for_status()
    return json.dumps({"u": u, "p": p})


def get_flag(host, port, flag_id, flag):
    d = json.loads(flag_id)
    r = L.post(host, port, "/login", json={"username": d["u"], "password": d["p"]})
    if r.status_code != 200:
        return False
    tok = r.json()["token"]
    r = L.get(host, port, "/stash", headers={"Authorization": tok})
    return r.status_code == 200 and r.json().get("secret") == flag


def check_sla(host, port):
    if L.get(host, port, "/health").json().get("status") != "ok":
        return False
    u, p, tok = L.register(host, port)
    secret = L.rnd(24)
    r = L.post(host, port, "/stash", json={"secret": secret}, headers={"Authorization": tok})
    if r.status_code != 200:
        return False
    r = L.get(host, port, "/stash", headers={"Authorization": tok})
    return r.status_code == 200 and r.json().get("secret") == secret
