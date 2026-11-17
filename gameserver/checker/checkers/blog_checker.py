"""Чекер blog. SLA: register -> login -> create private post -> read back (авторизованно)."""
import json
import checker_lib as L

SERVICE = "blog"


def put_flag(host, port, flag):
    u, p, tok = L.register(host, port)
    r = L.post(host, port, "/posts", json={"title": L.rnd(6), "body": flag, "private": 1},
               headers={"Authorization": tok})
    r.raise_for_status()
    pid = r.json()["id"]
    return json.dumps({"u": u, "p": p, "id": pid})


def get_flag(host, port, flag_id, flag):
    d = json.loads(flag_id)
    r = L.post(host, port, "/login", json={"username": d["u"], "password": d["p"]})
    if r.status_code != 200:
        return False
    tok = r.json()["token"]
    # авторизованное чтение собственного приватного поста
    r = L.get(host, port, f"/post/{d['id']}", headers={"Authorization": tok})
    return r.status_code == 200 and r.json().get("body") == flag


def check_sla(host, port):
    if L.get(host, port, "/health").json().get("status") != "ok":
        return False
    u, p, tok = L.register(host, port)
    body = L.rnd(20)
    pid = L.post(host, port, "/posts", json={"title": "t", "body": body, "private": 1},
                 headers={"Authorization": tok}).json()["id"]
    r = L.get(host, port, f"/post/{pid}", headers={"Authorization": tok})
    return r.status_code == 200 and r.json().get("body") == body
