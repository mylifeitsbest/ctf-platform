#!/usr/bin/env python3
"""ForcAD-совместимый чекер сервиса profile (checker_type: pfr).

Контракт (checklib / ForcAD):
  checker.py check <host>
  checker.py put   <host> <flag_id> <flag> <vuln>   -> stdout=public(attack_data), stderr=private(flag_id для get)
  checker.py get   <host> <flag_id> <flag> <vuln>   <flag_id> == private из put

SLA-путь (должен работать и ПОСЛЕ правильного патча SSTI):
  register -> login -> сохранить bio -> GET /card возвращает этот же текст.
Эксплойт (то, что чинят): bio рендерится как Jinja2-шаблон с контекстом, где есть
secrets=SECRETS, поэтому bio вида {{ secrets.values()|list }} в /card выдаёт чужие флаги.
Правильный патч рендерит bio как ПЛЕЙН-ТЕКСТ (без шаблонизатора), SLA остаётся зелёным.
"""
import os
import sys

import requests
from checklib import *  # noqa: F401,F403  (BaseChecker, Status, cquit, rnd_*, get_initialized_session)

# ВАЖНО: ForcAD НЕ прокидывает кастомные env в чекер (run_generic_command меняет
# только $PATH). Поэтому порт сервиса на вулнбоксе зашит дефолтом ниже и должен
# совпадать с forcad/vulnbox (notes:5001, pingtool:5002, vault:5003, profile:5006).
# CHECKER_PORT оставлен как override для локального теста без Docker.
PORT = int(os.environ.get("CHECKER_PORT", "5006"))  # profile на вулнбоксе


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

    def _set_bio(self, s, tok, bio, status=Status.MUMBLE):
        r = self._req(s, "POST", "/bio", json={"bio": bio}, headers={"Authorization": tok})
        self.assert_eq(r.status_code, 200, "setting bio failed", status=status)

    # ---- actions ----
    def check(self):
        s = get_initialized_session()
        r = self._req(s, "GET", "/health")
        self.assert_eq(r.status_code, 200, "health is down", status=Status.DOWN)
        self.assert_eq(self._json(r).get("service"), "profile", "wrong service on /health")

        u, p = rnd_username(), rnd_password()
        tok = self._register(s, u, p)
        tok2 = self._login(s, u, p)
        self.assert_eq(tok, tok2, "login token != register token")

        # карточка должна требовать авторизацию
        r = self._req(s, "GET", "/card")
        self.assert_eq(r.status_code, 401, "card must require auth", status=Status.MUMBLE)

        # SLA: сохранённое bio целиком отображается в карточке
        bio = rnd_string(24)
        self._set_bio(s, tok, bio)
        r = self._req(s, "GET", "/card", headers={"Authorization": tok})
        self.assert_eq(r.status_code, 200, "owner cannot read own card", status=Status.MUMBLE)
        self.assert_(bio in str(self._json(r).get("card")), "bio text not shown in card", status=Status.MUMBLE)
        self.cquit(Status.OK)

    def put(self, flag_id, flag, vuln):
        s = get_initialized_session()
        u, p = rnd_username(), rnd_password()
        tok = self._register(s, u, p)
        r = self._req(s, "POST", "/secret", json={"secret": flag}, headers={"Authorization": tok})
        self.assert_eq(r.status_code, 200, "storing secret failed", status=Status.MUMBLE)
        # public = attack_data (имя пользователя-жертвы); private = то, что получит get
        self.cquit(Status.OK, u, f"{u}:{p}")

    def get(self, flag_id, flag, vuln):
        try:
            u, p = flag_id.split(":")
        except ValueError:
            self.cquit(Status.ERROR, "bad flag_id", f"flag_id={flag_id!r}")
        s = get_initialized_session()
        # легитимный путь: владелец логинится и читает свой секрет
        tok = self._login(s, u, p, status=Status.CORRUPT)
        r = self._req(s, "GET", "/secret", headers={"Authorization": tok})
        self.assert_eq(r.status_code, 200, "owner cannot read own secret", status=Status.CORRUPT)
        self.assert_eq(str(self._json(r, Status.CORRUPT).get("secret")), flag,
                       "flag not found in secret", status=Status.CORRUPT)
        self.cquit(Status.OK)


if __name__ == "__main__":
    c = Checker(sys.argv[2])
    try:
        c.action(sys.argv[1], *sys.argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)
