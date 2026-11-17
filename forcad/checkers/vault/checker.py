#!/usr/bin/env python3
"""ForcAD-совместимый чекер сервиса vault (checker_type: pfr).

SLA-путь: register -> seal(секрет=флаг) -> reveal(id) с токеном владельца.
Эксплойт (то, что чинят): /blob/<id> отдаёт шифртекст без авторизации, а ключ AES-ECB
зашит в исходники (одинаков у всех) -> флаг расшифровывается оффлайн.
Правильный патч (убрать неавторизованный /blob и/или сделать ключ уникальным) не ломает reveal.
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
PORT = int(os.environ.get("CHECKER_PORT", "5003"))  # vault на вулнбоксе


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

    def _seal(self, s, tok, secret, status=Status.MUMBLE):
        r = self._req(s, "POST", "/seal", json={"secret": secret}, headers={"Authorization": tok})
        self.assert_eq(r.status_code, 200, "seal failed", status=status)
        sid = self._json(r, status).get("id")
        self.assert_(sid is not None, "seal returned no id", status=status)
        return sid

    def _reveal(self, s, tok, sid, status=Status.MUMBLE):
        r = self._req(s, "GET", f"/reveal/{sid}", headers={"Authorization": tok})
        self.assert_eq(r.status_code, 200, "reveal failed", status=status)
        return self._json(r, status)

    def check(self):
        s = get_initialized_session()
        r = self._req(s, "GET", "/health")
        self.assert_eq(r.status_code, 200, "health is down", status=Status.DOWN)
        self.assert_eq(self._json(r).get("service"), "vault", "wrong service on /health")

        u, p = rnd_username(), rnd_password()
        tok = self._register(s, u, p)

        # reveal обязан требовать авторизацию
        secret = rnd_string(24)
        sid = self._seal(s, tok, secret)
        r = self._req(s, "GET", f"/reveal/{sid}")
        self.assert_eq(r.status_code, 401, "reveal must require auth", status=Status.MUMBLE)

        got = self._reveal(s, tok, sid)
        self.assert_eq(str(got.get("secret")), secret, "revealed secret mismatch", status=Status.MUMBLE)
        self.cquit(Status.OK)

    def put(self, flag_id, flag, vuln):
        s = get_initialized_session()
        u, p = rnd_username(), rnd_password()
        tok = self._register(s, u, p)
        sid = self._seal(s, tok, flag)
        self.cquit(Status.OK, str(sid), f"{tok}:{sid}")

    def get(self, flag_id, flag, vuln):
        try:
            tok, sid = flag_id.split(":")
        except ValueError:
            self.cquit(Status.ERROR, "bad flag_id", f"flag_id={flag_id!r}")
        s = get_initialized_session()
        got = self._reveal(s, tok, sid, status=Status.CORRUPT)
        self.assert_eq(str(got.get("secret")), flag, "flag not found in vault", status=Status.CORRUPT)
        self.cquit(Status.OK)


if __name__ == "__main__":
    c = Checker(sys.argv[2])
    try:
        c.action(sys.argv[1], *sys.argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)
