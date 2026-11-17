"""Чекер notes. SLA: register -> create note -> read back (авторизованно) -> list."""
import json
import checker_lib as L

SERVICE = "notes"


def put_flag(host, port, flag):
    u, p, tok = L.register(host, port)
    r = L.post(host, port, "/notes", json={"title": L.rnd(6), "body": flag},
               headers={"Authorization": tok})
    r.raise_for_status()
    nid = r.json()["id"]
    return json.dumps({"u": u, "p": p, "tok": tok, "id": nid})


def get_flag(host, port, flag_id, flag):
    d = json.loads(flag_id)
    r = L.post(host, port, "/login", json={"username": d["u"], "password": d["p"]})
    if r.status_code != 200:
        return False
    tok = r.json()["token"]
    # авторизованное чтение собственной заметки
    mine = L.get(host, port, "/notes", headers={"Authorization": tok}).json().get("notes", [])
    if not any(n["id"] == d["id"] for n in mine):
        return False
    r = L.get(host, port, f"/note/{d['id']}", headers={"Authorization": tok})
    return r.status_code == 200 and r.json().get("body") == flag


def check_sla(host, port):
    if L.get(host, port, "/health").json().get("status") != "ok":
        return False
    u, p, tok = L.register(host, port)
    body = L.rnd(20)
    nid = L.post(host, port, "/notes", json={"title": "t", "body": body},
                 headers={"Authorization": tok}).json()["id"]
    r = L.get(host, port, f"/note/{nid}", headers={"Authorization": tok})
    return r.status_code == 200 and r.json().get("body") == body
