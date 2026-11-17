"""Чекер gallery. SLA: register -> login -> upload -> get (round-trip).

Флаг чекер кладёт как загруженный файл (/upload) и читает владельцем через
безопасный GET /get/<name>. Уязвимость искать в /recent + /download.
"""
import json
import checker_lib as L

SERVICE = "gallery"


def put_flag(host, port, flag):
    u, p, tok = L.register(host, port)
    name = "f_" + L.rnd(6)
    r = L.post(host, port, "/upload", json={"name": name, "content": flag},
               headers={"Authorization": tok})
    r.raise_for_status()
    return json.dumps({"u": u, "p": p, "name": name})


def get_flag(host, port, flag_id, flag):
    d = json.loads(flag_id)
    r = L.post(host, port, "/login", json={"username": d["u"], "password": d["p"]})
    if r.status_code != 200:
        return False
    tok = r.json().get("token")
    r = L.get(host, port, f"/get/{d['name']}", headers={"Authorization": tok})
    return r.status_code == 200 and r.json().get("content") == flag


def check_sla(host, port):
    if L.get(host, port, "/health").json().get("status") != "ok":
        return False
    u, p, tok = L.register(host, port)
    # заодно проверяем /login (SLA-путь: register -> login -> upload -> get)
    tok = L.post(host, port, "/login", json={"username": u, "password": p}).json().get("token")
    name, content = "t_" + L.rnd(5), L.rnd(20)
    L.post(host, port, "/upload", json={"name": name, "content": content},
           headers={"Authorization": tok})
    r = L.get(host, port, f"/get/{name}", headers={"Authorization": tok})
    return r.status_code == 200 and r.json().get("content") == content
