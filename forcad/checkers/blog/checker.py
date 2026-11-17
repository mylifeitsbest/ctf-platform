#!/usr/bin/env python3
"""ForcAD-совместимый чекер сервиса blog (checker_type: pfr).

Контракт (checklib / ForcAD):
  checker.py check <host>
  checker.py put   <host> <flag_id> <flag> <vuln>   -> stdout=public(attack_data), stderr=private(flag_id для get)
  checker.py get   <host> <flag_id> <flag> <vuln>   <flag_id> == private из put

SLA-путь (должен работать и ПОСЛЕ правильного патча SQLi):
  register -> login -> создать приватный пост -> прочитать СВОЙ пост с токеном владельца.
Эксплойт (то, что чинят): GET /search?q= строит SQL конкатенацией строк -> SQL-инъекция;
UNION-пейлоадом из публичного поиска вытягиваются чужие приватные посты (в т.ч. посты чекера с флагами).
Правильный патч — параметризованный запрос в /search; /search не участвует в SLA, поэтому SLA остаётся зелёным.
"""
import os
import sys

import requests
from checklib import *  # noqa: F401,F403  (BaseChecker, Status, cquit, rnd_*, get_initialized_session)

# ВАЖНО: ForcAD НЕ прокидывает кастомные env в чекер (run_generic_command меняет
# только $PATH). Поэтому порт сервиса на вулнбоксе зашит дефолтом ниже и должен
# совпадать с forcad/vulnbox (notes:5001, pingtool:5002, vault:5003, blog:5004).
# CHECKER_PORT оставлен как override для локального теста без Docker.
PORT = int(os.environ.get("CHECKER_PORT", "5004"))  # blog на вулнбоксе


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

    def _create(self, s, tok, title, body, private, status=Status.MUMBLE):
        r = self._req(s, "POST", "/posts", json={"title": title, "body": body, "private": private},
                      headers={"Authorization": tok})
        self.assert_eq(r.status_code, 200, "post creation failed", status=status)
        pid = self._json(r, status).get("id")
        self.assert_(pid is not None, "post creation returned no id", status=status)
        return pid

    # ---- actions ----
    def check(self):
        s = get_initialized_session()
        r = self._req(s, "GET", "/health")
        self.assert_eq(r.status_code, 200, "health is down", status=Status.DOWN)
        self.assert_eq(self._json(r).get("service"), "blog", "wrong service on /health")

        u, p = rnd_username(), rnd_password()
        tok = self._register(s, u, p)
        tok2 = self._login(s, u, p)
        self.assert_eq(tok, tok2, "login token != register token")

        title, body = rnd_string(8), rnd_string(24)
        pid = self._create(s, tok, title, body, 1)

        # приватный листинг обязан требовать авторизацию
        r = self._req(s, "GET", "/posts")
        self.assert_eq(r.status_code, 401, "post listing must require auth", status=Status.MUMBLE)

        # владелец читает свой пост с токеном
        r = self._req(s, "GET", f"/post/{pid}", headers={"Authorization": tok})
        self.assert_eq(r.status_code, 200, "owner cannot read own post", status=Status.MUMBLE)
        self.assert_eq(str(self._json(r).get("body")), body, "post body mismatch", status=Status.MUMBLE)
        self.cquit(Status.OK)

    def put(self, flag_id, flag, vuln):
        s = get_initialized_session()
        u, p = rnd_username(), rnd_password()
        tok = self._register(s, u, p)
        pid = self._create(s, tok, rnd_string(10), flag, 1)
        # public = attack_data (id приватного поста); private = то, что получит get:
        # у blog есть /login, поэтому кладём u:p:id и в get() логинимся заново.
        self.cquit(Status.OK, str(pid), f"{u}:{p}:{pid}")

    def get(self, flag_id, flag, vuln):
        try:
            u, p, pid = flag_id.split(":")
        except ValueError:
            self.cquit(Status.ERROR, "bad flag_id", f"flag_id={flag_id!r}")
        s = get_initialized_session()
        # легитимный путь: логинимся и читаем свой пост с токеном владельца
        tok = self._login(s, u, p, status=Status.CORRUPT)
        r = self._req(s, "GET", f"/post/{pid}", headers={"Authorization": tok})
        self.assert_eq(r.status_code, 200, "owner cannot read own post", status=Status.CORRUPT)
        self.assert_eq(str(self._json(r, Status.CORRUPT).get("body")), flag,
                       "flag not found in post", status=Status.CORRUPT)
        self.cquit(Status.OK)


if __name__ == "__main__":
    c = Checker(sys.argv[2])
    try:
        c.action(sys.argv[1], *sys.argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)
