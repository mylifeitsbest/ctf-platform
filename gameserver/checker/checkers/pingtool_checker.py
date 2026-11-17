"""Чекер pingtool. SLA: register -> save -> get (round-trip)."""
import json
import checker_lib as L

SERVICE = "pingtool"


def put_flag(host, port, flag):
    u, p, tok = L.register(host, port)
    name = "diag_" + L.rnd(6) + ".txt"
    r = L.post(host, port, "/save", json={"name": name, "content": flag},
               headers={"Authorization": tok})
    r.raise_for_status()
    return json.dumps({"u": u, "p": p, "tok": tok, "name": name})


def get_flag(host, port, flag_id, flag):
    d = json.loads(flag_id)
    r = L.get(host, port, f"/get/{d['name']}", headers={"Authorization": d["tok"]})
    return r.status_code == 200 and r.json().get("content") == flag


def check_sla(host, port):
    if L.get(host, port, "/health").json().get("status") != "ok":
        return False
    u, p, tok = L.register(host, port)
    name, content = "t_" + L.rnd(5), L.rnd(20)
    L.post(host, port, "/save", json={"name": name, "content": content},
           headers={"Authorization": tok})
    r = L.get(host, port, f"/get/{name}", headers={"Authorization": tok})
    return r.status_code == 200 and r.json().get("content") == content
