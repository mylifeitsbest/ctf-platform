#!/usr/bin/env python3
"""ForcAD-совместимый чекер сервиса pingtool (checker_type: pfr).

SLA-путь: register -> save(файл с флагом) -> get(файл) с токеном владельца.
Эксплойт (то, что чинят): command injection в /diag (host подставляется в shell).
Патч /diag не трогает save/get, поэтому SLA остаётся зелёным.
У сервиса НЕТ /login, поэтому токен владельца переносим в private flag_id.
"""
import os
import sys

import requests
from checklib import *  # noqa: F401,F403

# ВАЖНО: ForcAD НЕ прокидывает кастомные env в чекер (run_generic_command меняет
# только $PATH). Поэтому порт сервиса на вулнбоксе зашит дефолтом ниже и должен
# совпадать с forcad/vulnbox (notes:5001, pingtool:5002, vault:5003).
# CHECKER_PORT оставлен как override для локального теста без Docker.
PORT = int(os.environ.get("CHECKER_PORT", "5002"))  # pingtool на вулнбоксе


class Checker(BaseChecker):
    vulns: int = 1
    timeout: int = 10
    uses_attack_data: bool = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.url = f"http://{self.host}:{PORT}"

    def action(self, action, *args, **kwargs):
        try:
            super().action(action, *args, **kwargs)
        except requests.exceptions.ConnectionError:
            self.cquit(Status.DOWN, "Service unreachable", "requests ConnectionError")
        except requests.exceptions.Timeout:
            self.cquit(Status.DOWN, "Service timeout", "requests Timeout")

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

    def _save(self, s, tok, name, content, status=Status.MUMBLE):
        r = self._req(s, "POST", "/save", json={"name": name, "content": content},
                      headers={"Authorization": tok})
        self.assert_eq(r.status_code, 200, "save failed", status=status)
        return self._json(r, status)

    def _get(self, s, tok, name, status=Status.MUMBLE):
        r = self._req(s, "GET", f"/get/{name}", headers={"Authorization": tok})
        self.assert_eq(r.status_code, 200, "get failed", status=status)
        return self._json(r, status)

    def check(self):
        s = get_initialized_session()
        r = self._req(s, "GET", "/health")
        self.assert_eq(r.status_code, 200, "health is down", status=Status.DOWN)
        self.assert_eq(self._json(r).get("service"), "pingtool", "wrong service on /health")

        u, p = rnd_username(), rnd_password()
        tok = self._register(s, u, p)

        # сохранение обязано требовать авторизацию
        r = self._req(s, "POST", "/save", json={"name": "x", "content": "y"})
        self.assert_eq(r.status_code, 401, "save must require auth", status=Status.MUMBLE)

        name, content = "d_" + rnd_string(8), rnd_string(24)
        self._save(s, tok, name, content)
        got = self._get(s, tok, name)
        self.assert_eq(str(got.get("content")), content, "saved content mismatch", status=Status.MUMBLE)
        self.cquit(Status.OK)

    def put(self, flag_id, flag, vuln):
        s = get_initialized_session()
        u, p = rnd_username(), rnd_password()
        tok = self._register(s, u, p)
        name = "f_" + rnd_string(10)
        self._save(s, tok, name, flag)
        self.cquit(Status.OK, name, f"{tok}:{name}")

    def get(self, flag_id, flag, vuln):
        try:
            tok, name = flag_id.split(":", 1)
        except ValueError:
            self.cquit(Status.ERROR, "bad flag_id", f"flag_id={flag_id!r}")
        s = get_initialized_session()
        got = self._get(s, tok, name, status=Status.CORRUPT)
        self.assert_eq(str(got.get("content")), flag, "flag not found in saved file", status=Status.CORRUPT)
        self.cquit(Status.OK)


if __name__ == "__main__":
    c = Checker(sys.argv[2])
    try:
        c.action(sys.argv[1], *sys.argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)
