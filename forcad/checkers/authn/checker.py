#!/usr/bin/env python3
"""ForcAD-совместимый чекер сервиса authn (checker_type: pfr).

SLA-путь: register -> login -> /stash set(секрет=флаг) -> /stash get своим токеном.
Эксплойт (то, что чинят): токен — это JWT, но сервис декодирует его со слабым
секретом "secret" и с принятием alg:none (подпись фактически не проверяется) ->
можно подделать admin-токен и выгрести все флаги через GET /admin/dump.
Правильный патч (сильный случайный секрет при старте, запрет alg:none, реальная
проверка admin) не ломает SLA: register/login/stash ходят по токену владельца.
"""
import os
import sys

import requests
from checklib import *  # noqa: F401,F403

# ВАЖНО: ForcAD НЕ прокидывает кастомные env в чекер (run_generic_command меняет
# только $PATH). Поэтому порт сервиса на вулнбоксе зашит дефолтом ниже и должен
# совпадать с forcad/vulnbox (notes:5001, pingtool:5002, vault:5003, authn:5007).
# CHECKER_PORT оставлен как override для локального теста без Docker.
PORT = int(os.environ.get("CHECKER_PORT", "5007"))  # authn на вулнбоксе


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

    def _login(self, s, u, p, status=Status.MUMBLE):
        r = self._req(s, "POST", "/login", json={"username": u, "password": p})
        self.assert_eq(r.status_code, 200, "login failed", status=status)
        tok = self._json(r, status).get("token")
        self.assert_(bool(tok), "login returned no token", status=status)
        return tok

    def _stash_set(self, s, tok, secret, status=Status.MUMBLE):
        r = self._req(s, "POST", "/stash", json={"secret": secret}, headers={"Authorization": tok})
        self.assert_eq(r.status_code, 200, "stash set failed", status=status)
        return self._json(r, status)

    def _stash_get(self, s, tok, status=Status.MUMBLE):
        r = self._req(s, "GET", "/stash", headers={"Authorization": tok})
        self.assert_eq(r.status_code, 200, "stash get failed", status=status)
        return self._json(r, status)

    def check(self):
        s = get_initialized_session()
        r = self._req(s, "GET", "/health")
        self.assert_eq(r.status_code, 200, "health is down", status=Status.DOWN)
        self.assert_eq(self._json(r).get("service"), "authn", "wrong service on /health")

        u, p = rnd_username(), rnd_password()
        self._register(s, u, p)
        tok = self._login(s, u, p)

        # /stash обязан требовать авторизацию
        r = self._req(s, "GET", "/stash")
        self.assert_eq(r.status_code, 401, "stash must require auth", status=Status.MUMBLE)

        secret = rnd_string(24)
        self._stash_set(s, tok, secret)
        got = self._stash_get(s, tok)
        self.assert_eq(str(got.get("secret")), secret, "stashed secret mismatch", status=Status.MUMBLE)
        self.cquit(Status.OK)

    def put(self, flag_id, flag, vuln):
        s = get_initialized_session()
        u, p = rnd_username(), rnd_password()
        tok = self._register(s, u, p)
        self._stash_set(s, tok, flag)
        # public = attack_data (имя пользователя); private = u:p для последующего get
        self.cquit(Status.OK, str(u), f"{u}:{p}")

    def get(self, flag_id, flag, vuln):
        try:
            u, p = flag_id.split(":", 1)
        except ValueError:
            self.cquit(Status.ERROR, "bad flag_id", f"flag_id={flag_id!r}")
        s = get_initialized_session()
        tok = self._login(s, u, p, status=Status.CORRUPT)
        got = self._stash_get(s, tok, status=Status.CORRUPT)
        self.assert_eq(str(got.get("secret")), flag, "flag not found in stash", status=Status.CORRUPT)
        self.cquit(Status.OK)


if __name__ == "__main__":
    c = Checker(sys.argv[2])
    try:
        c.action(sys.argv[1], *sys.argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)
