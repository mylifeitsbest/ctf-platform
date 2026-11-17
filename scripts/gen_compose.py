#!/usr/bin/env python3
"""Генерирует docker-compose.yml и farm/targets.json из config/game.json.

Запускается автоматически из scripts/up.ps1 / up.sh. Можно и вручную:
    python scripts/gen_compose.py
"""
import glob
import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "config", "game.json")


def load_config():
    with open(CONFIG, "r", encoding="utf-8") as f:
        return json.load(f)


def gen_compose(cfg):
    lines = []
    lines.append("# АВТОГЕНЕРАЦИЯ из config/game.json — правьте конфиг, а не этот файл.")
    lines.append("# Пересоздать: python scripts/gen_compose.py")
    lines.append("services:")

    # --- Уязвимые сервисы: по контейнеру на (сервис, команда) ---
    for team in cfg["teams"]:
        for si, svc in enumerate(cfg["services"]):
            name = f"{svc['name']}_{team['name']}"
            host_port = team["host_port_base"] + si
            lines += [
                f"  {name}:",
                f"    build: ./services/{svc['name']}",
                f"    container_name: {name}",
                f"    hostname: {name}",
                "    environment:",
                f"      - SERVICE={svc['name']}",
                f"      - TEAM={team['name']}",
                "    ports:",
                f"      - \"{host_port}:{svc['internal_port']}\"",
                "    networks: [adnet]",
                "    restart: unless-stopped",
            ]

    # --- Scoreboard ---
    sb_port = cfg["scoreboard_port"]
    lines += [
        "  scoreboard:",
        "    build: ./gameserver/scoreboard",
        "    container_name: scoreboard",
        "    hostname: scoreboard",
        "    environment:",
        f"      - FLAG_REGEX={cfg['flag_regex']}",
        f"      - FLAG_TTL_ROUNDS={cfg['flag_ttl_rounds']}",
        "    ports:",
        f"      - \"{sb_port}:8080\"",
        "    networks: [adnet]",
        "    restart: unless-stopped",
    ]

    # --- Checker (кладёт флаги + проверяет SLA каждый раунд) ---
    checker_env = [
        f"      - ROUND_TIME={cfg['round_time']}",
        f"      - FLAG_REGEX={cfg['flag_regex']}",
        "      - SCOREBOARD=http://scoreboard:8080",
    ]
    depends = [f"{svc['name']}_{t['name']}" for t in cfg["teams"] for svc in cfg["services"]]
    lines += [
        "  checker:",
        "    build: ./gameserver/checker",
        "    container_name: checker",
        "    environment:",
        *checker_env,
        "    depends_on: [scoreboard]",
        "    networks: [adnet]",
        "    restart: unless-stopped",
    ]

    # --- Portal (тренировочный полигон: вход, задания, реальная проверка) ---
    pub = os.environ.get("PUBLIC_HOST") or cfg.get("public_host") or "localhost"
    lines += [
        "  portal:",
        "    build: ./portal",
        "    container_name: portal",
        "    environment:",
        "      - SCOREBOARD=http://scoreboard:8080",
        f"      - PUBLIC_HOST={pub}",
        "      - SECRET=dojo-portal-secret",
        "    ports:",
        f"      - \"{cfg.get('portal_port', 9000)}:9000\"",
        "    depends_on: [scoreboard]",
        "    networks: [adnet]",
        "    restart: unless-stopped",
    ]

    # --- Опциональный бот-атакующий (гоняет эталонные эксплойты по всем) ---
    if cfg.get("attacker_bot"):
        lines += [
            "  attacker_bot:",
            "    build: ./gameserver/attacker_bot",
            "    container_name: attacker_bot",
            "    environment:",
            f"      - ROUND_TIME={cfg['round_time']}",
            f"      - FLAG_REGEX={cfg['flag_regex']}",
            "      - SCOREBOARD=http://scoreboard:8080",
            "      - TEAM=attacker_bot",
            "    depends_on: [scoreboard]",
            "    networks: [adnet]",
            "    restart: unless-stopped",
        ]

    lines += ["networks:", "  adnet:", "    driver: bridge", ""]
    return "\n".join(lines)


def gen_targets(cfg):
    """Список целей для фермы, которую игроки запускают на своей машине (по опубликованным портам).

    Хост берётся из PUBLIC_HOST (env) -> public_host (game.json) -> 127.0.0.1.
    На ВДС выставьте публичный IP, чтобы ферма с ноутбуков била по нему.
    """
    host = os.environ.get("PUBLIC_HOST") or cfg.get("public_host") or "127.0.0.1"
    targets = []
    for team in cfg["teams"]:
        entry = {"team": team["name"], "owner": team.get("owner", ""), "services": {}}
        for si, svc in enumerate(cfg["services"]):
            entry["services"][svc["name"]] = {
                "host": host,
                "port": team["host_port_base"] + si,
            }
        targets.append(entry)
    return {
        "scoreboard": f"http://127.0.0.1:{cfg['scoreboard_port']}",
        "flag_regex": cfg["flag_regex"],
        "round_time": cfg["round_time"],
        "teams": targets,
    }


def main():
    cfg = load_config()
    compose = gen_compose(cfg)
    with open(os.path.join(ROOT, "docker-compose.yml"), "w", encoding="utf-8") as f:
        f.write(compose)
    with open(os.path.join(ROOT, "farm", "targets.json"), "w", encoding="utf-8") as f:
        json.dump(gen_targets(cfg), f, ensure_ascii=False, indent=2)
    # копия конфига в образы, которым он нужен на борту (build-контекст не видит ../..)
    for sub in ("gameserver/checker", "gameserver/attacker_bot", "portal"):
        dst = os.path.join(ROOT, sub, "game.json")
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)

    # единый источник эксплойтов: кладём exploits_reference/*_sploit.py в образы
    # портала (автопроверка патча) и бота-противника (атакует все сервисы).
    sploit_src = sorted(glob.glob(os.path.join(ROOT, "exploits_reference", "*_sploit.py")))
    for sub in ("portal", os.path.join("gameserver", "attacker_bot")):
        sdst = os.path.join(ROOT, sub, "sploits")
        os.makedirs(sdst, exist_ok=True)
        for old in glob.glob(os.path.join(sdst, "*_sploit.py")):
            os.remove(old)
        for src in sploit_src:
            shutil.copy(src, sdst)
    print(f"[ok] сплойтов разнесено в portal/ и attacker_bot/: {len(sploit_src)}")
    n_svc = len(cfg["services"]) * len(cfg["teams"])
    print(f"[ok] docker-compose.yml: {n_svc} сервис-контейнеров, "
          f"{len(cfg['teams'])} команд, scoreboard + checker"
          + (" + attacker_bot" if cfg.get("attacker_bot") else ""))
    print("[ok] farm/targets.json обновлён")


if __name__ == "__main__":
    sys.exit(main())
