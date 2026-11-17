#!/usr/bin/env python3
"""ForcAD-совместимый чекер сервиса gallery (checker_type: pfr).

Контракт (checklib / ForcAD):
  checker.py check <host>
  checker.py put   <host> <flag_id> <flag> <vuln>   -> stdout=public(attack_data), stderr=private(flag_id для get)
  checker.py get   <host> <flag_id> <flag> <vuln>   <flag_id> == private из put

SLA-путь (должен работать и ПОСЛЕ правильного патча):
  register -> login -> upload(файл с флагом) -> GET /get/<name> с токеном владельца.
Эксплойт (то, что чинят): path traversal / broken access control — /recent (без
авторизации) раскрывает пути "<token16>/<name>", а /download?path=... (тоже без
авторизации) читает os.path.join(DATA, path) без ограничения каталогом.
Правильный патч ограничивает /download каталогом владельца и требует авторизацию
(или убирает /download), SLA через /get остаётся зелёным.
У сервиса ЕСТЬ /login, поэтому в get() логинимся по u:p из private flag_id.
"""
import os
import sys

import requests
from checklib import *  # noqa: F401,F403  (BaseChecker, Status, cquit, rnd_*, get_initialized_session)

# ВАЖНО: ForcAD НЕ прокидывает кастомные env в чекер (run_generic_command меняет
# только $PATH). Поэтому порт сервиса на вулнбоксе зашит дефолтом ниже и должен
# совпадать с forcad/vulnbox (notes:5001, pingtool:5002, vault:5003, gallery:5005).
# CHECKER_PORT оставлен как override для локального теста без Docker.
PORT = int(os.environ.get("CHECKER_PORT", "5005"))  # gallery на вулнбоксе


class Checker(BaseChecker):
    vulns: int = 1
    timeout: int = 10
    uses_attack_data: bool = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.url = f"http://{self.host}:{PORT}"

    # сетевые сбои -> DOWN
    def action(self, action, *args, **kwargs):
        try:
            super().action(action, *args, **kwargs)
        except requests.exceptions.ConnectionError:
            self.cquit(Status.DOWN, "Service unreachable", "requests ConnectionError")
        except requests.exceptions.Timeout:
            self.cquit(Status.DOWN, "Service timeout", "requests Timeout")

    # ---- helpers ----
    def _req(self, s, method, path, **kw):
        kw.setdefault("timeout", self.timeout)
        return s.request(method, self.url + path, **kw)

    def _json(self, r, status=Status.MUMBLE):
        try:
            return r.json()
        except Exception:
            self.cquit(status, "Service returned invalid JSON", f"{r.request.method} {r.url} -> {r.text[:200]!r}")

    def _register(self, s, u, p, status=Status.MUMBLE):
        r = self._req(s, "POST", "/register", json={"username": u, "password": p})
        self.assert_eq(r.status_code, 200, "register failed", status=status)
        tok = self._json(r, status).get("token")
        self.assert_(bool(tok), "register returned no token", status=status)
        return tok

    def _login(self, s, u, p, status=Status.MUMBLE):
        r = self._req(s, "POST", "/login", json={"username": u, "password": p})
        self.assert_eq(r.status_code, 200, "login failed", status=status)
        tok = self._json(r, status).get("token")
        self.assert_(bool(tok), "login returned no token", status=status)
        return tok

    def _upload(self, s, tok, name, content, status=Status.MUMBLE):
        r = self._req(s, "POST", "/upload", json={"name": name, "content": content},
                      headers={"Authorization": tok})
        self.assert_eq(r.status_code, 200, "upload failed", status=status)
        return self._json(r, status)

    def _get(self, s, tok, name, status=Status.MUMBLE):
        r = self._req(s, "GET", f"/get/{name}", headers={"Authorization": tok})
        self.assert_eq(r.status_code, 200, "get failed", status=status)
        return self._json(r, status)

    # ---- actions ----
    def check(self):
        s = get_initialized_session()
        r = self._req(s, "GET", "/health")
        self.assert_eq(r.status_code, 200, "health is down", status=Status.DOWN)
        self.assert_eq(self._json(r).get("service"), "gallery", "wrong service on /health")

        u, p = rnd_username(), rnd_password()
        tok = self._register(s, u, p)
        tok2 = self._login(s, u, p)
        self.assert_eq(tok, tok2, "login token != register token")

        # загрузка обязана требовать авторизацию
        r = self._req(s, "POST", "/upload", json={"name": "x", "content": "y"})
        self.assert_eq(r.status_code, 401, "upload must require auth", status=Status.MUMBLE)

        # чтение своего файла обязано требовать авторизацию
        r = self._req(s, "GET", "/get/x")
        self.assert_eq(r.status_code, 401, "get must require auth", status=Status.MUMBLE)

        # SLA: сохранённый файл читается владельцем обратно без изменений
        name, content = "d_" + rnd_string(8), rnd_string(24)
        self._upload(s, tok, name, content)
        got = self._get(s, tok, name)
        self.assert_eq(str(got.get("content")), content, "saved content mismatch", status=Status.MUMBLE)
        self.cquit(Status.OK)

    def put(self, flag_id, flag, vuln):
        s = get_initialized_session()
        u, p = rnd_username(), rnd_password()
        tok = self._register(s, u, p)
        name = "f_" + rnd_string(10)
        self._upload(s, tok, name, flag)
        # public = attack_data (путь из публичной ленты /recent); private = то, что получит get
        self.cquit(Status.OK, f"{tok[:16]}/{name}", f"{u}:{p}:{name}")

    def get(self, flag_id, flag, vuln):
        try:
            u, p, name = flag_id.split(":", 2)
        except ValueError:
            self.cquit(Status.ERROR, "bad flag_id", f"flag_id={flag_id!r}")
        s = get_initialized_session()
        # легитимный путь: владелец логинится и читает свой файл с токеном
        tok = self._login(s, u, p, status=Status.CORRUPT)
        got = self._get(s, tok, name, status=Status.CORRUPT)
        self.assert_eq(str(got.get("content")), flag, "flag not found in uploaded file", status=Status.CORRUPT)
        self.cquit(Status.OK)


if __name__ == "__main__":
    c = Checker(sys.argv[2])
    try:
        c.action(sys.argv[1], *sys.argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)
