"""Чекер vault. SLA: register -> seal -> reveal (round-trip)."""
import json
import checker_lib as L

SERVICE = "vault"


def put_flag(host, port, flag):
    u, p, tok = L.register(host, port)
    r = L.post(host, port, "/seal", json={"secret": flag}, headers={"Authorization": tok})
    r.raise_for_status()
    return json.dumps({"u": u, "p": p, "tok": tok, "id": r.json()["id"]})


def get_flag(host, port, flag_id, flag):
    d = json.loads(flag_id)
    r = L.get(host, port, f"/reveal/{d['id']}", headers={"Authorization": d["tok"]})
    return r.status_code == 200 and r.json().get("secret") == flag


def check_sla(host, port):
    if L.get(host, port, "/health").json().get("status") != "ok":
        return False
    u, p, tok = L.register(host, port)
    secret = L.rnd(24)
    sid = L.post(host, port, "/seal", json={"secret": secret},
                 headers={"Authorization": tok}).json()["id"]
    r = L.get(host, port, f"/reveal/{sid}", headers={"Authorization": tok})
    return r.status_code == 200 and r.json().get("secret") == secret
