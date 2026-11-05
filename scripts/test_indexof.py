#!/usr/bin/env python3
"""Тесты режима «Index of»: детектор листингов, парсер, обходчик, run_global.

Локальный HTTP-сервер раздаёт фейковое дерево открытого каталога:
  /wallets/           листинг: ../, keys_backup.txt, notes.txt, logo.png, old/, внешняя ссылка
  /wallets/old/       листинг: ../, keys.txt
Файлы содержат валидные WIF — проверяем, что они доезжают до files/.
"""
import base64
import io
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "mini-services" / "scanner-service"
sys.path.insert(0, str(ROOT))

from engine.globalsearch import (  # noqa: E402
    _is_index_listing,
    _parse_index_entries,
    run_global,
    walk_index_of,
)
from engine.globalsearch import _is_fetchable_url as _real_fetchable  # noqa: E402
from engine.detectors import analyze_text, get_bip39  # noqa: E402

WIF1 = "L51Uc2DVUmVXTftYY3oqzbf5UkTnHgNk4LKsrKJadp9NAyzHqUP1"
WIF2 = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
# 200x200 PNG (мельче 120px _save_image не принимает — минимум для QR-декодера)
from PIL import Image  # noqa: E402
_buf = io.BytesIO()
Image.new("RGB", (200, 200), (30, 30, 34)).save(_buf, "PNG")
PNG = _buf.getvalue()

APACHE_LISTING = """<!DOCTYPE HTML><html><head><title>Index of /wallets</title></head><body>
<h1>Index of /wallets</h1><pre><img src="/icons/blank.gif"> <a href="?C=N;O=D">Name</a>
<hr><img src="/icons/parent.gif"><a href="../">Parent Directory</a>
<img src="/icons/text.gif"><a href="keys_backup.txt">keys_backup.txt</a>   2024-01-01 10:00  120
<img src="/icons/text.gif"><a href="notes.txt">notes.txt</a>               2024-01-02 10:00   88
<img src="/icons/image2.gif"><a href="logo.png">logo.png</a>               2024-01-03 10:00   95
<img src="/icons/folder.gif"><a href="old/">old/</a>                       2024-01-04 10:00    -
<img src="/icons/unknown.gif"><a href="http://evil.example.org/steal.txt">steal.txt</a>
<hr></pre></body></html>"""

OLD_LISTING = """<html><head><title>Index of /wallets/old</title></head><body>
<h1>Index of /wallets/old</h1>
<a href="../">Parent Directory</a><br>
<a href="keys.txt">keys.txt</a><br>
<a href="%D1%84%D0%B0%D0%B9%D0%BB%20%D1%81%20%D0%BA%D0%BB%D1%8E%D1%87%D0%B0%D0%BC%D0%B8.txt">файл с ключами.txt</a><br>
</body></html>"""

PLAIN_PAGE = """<html><head><title>My blog</title></head><body><p>hello</p>
<a href="/about">about</a><a href="/posts">posts</a><a href="/links">links</a></body></html>"""

NGINX_LISTING = """<html><head></head><body>
<h1>Directory listing for /backup/</h1>
<hr><a href="../">../</a><br>
<a href="seed.txt">seed.txt</a><br>
<a href="wallet.dat">wallet.dat</a><br>
<a href="dump.sql">dump.sql</a><br>
</body></html>"""

FILES = {
    "/wallets/": ("text/html", APACHE_LISTING.encode()),
    "/wallets/keys_backup.txt": ("text/plain", f"backup keys:\n{WIF1}\n".encode()),
    "/wallets/notes.txt": ("text/plain", b"nothing here, just notes\n"),
    "/wallets/logo.png": ("image/png", PNG),
    "/wallets/old/": ("text/html", OLD_LISTING.encode()),
    "/wallets/old/keys.txt": ("text/plain", f"key: {WIF2}\n".encode()),
    "/wallets/old/файл с ключами.txt": ("text/plain", f"WIF {WIF1} again\n".encode()),
    "/plain.html": ("text/html", PLAIN_PAGE.encode()),
}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import unquote
        p = unquote(self.path.split("?")[0])   # приходят %-кодированные пути
        key = p if p in FILES else (p.rstrip("/") + "/" if p + "/" in FILES else None)
        if key and key in FILES:
            ct, body = FILES[key]
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):  # тише
        pass


fails = []


def check(name, cond, extra=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{(' — ' + extra) if extra else ''}")
    if not cond:
        fails.append(name)


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{port}"

print("1) детектор листингов:")
check("Apache (title Index of)", _is_index_listing(APACHE_LISTING))
check("nginx (Directory listing for)", _is_index_listing(NGINX_LISTING))
check("обычная страница — не листинг", not _is_index_listing(PLAIN_PAGE))
check("SSRF-фильтр жив: 127.0.0.1 отклоняется", not _real_fetchable(f"http://127.0.0.1:1/x"))

# тестовый сервер — на 127.0.0.1, который SSRF-фильтр по дизайну блокирует.
# Функциональные прогоны идут через allow_private=True (прямые ссылки пользователя
# доверенные); поведение фильтра проверено выше и отдельно в п.2
import engine.globalsearch as _gs  # noqa: E402

print("2) парсер записей:")
dirs, files = _gs._parse_index_entries(APACHE_LISTING, f"{BASE}/wallets/", allow_private=True)
check("подкаталог найден", dirs == [f"{BASE}/wallets/old/"], str(dirs))
check("файлы собраны (3, внешняя отброшена)",
      sorted(files) == sorted([f"{BASE}/wallets/keys_backup.txt",
                               f"{BASE}/wallets/notes.txt",
                               f"{BASE}/wallets/logo.png"]), str(files))
check("parent ../ не попал никуда", f"{BASE}/" not in dirs and f"{BASE}/" not in files)
check("юникод-имя перекодировано и доступно",
      any("%D1%84%D0%B0%D0%B9%D0%BB" in u
          for u in _gs._parse_index_entries(OLD_LISTING, f"{BASE}/wallets/old/", allow_private=True)[1]))
priv_dirs, priv_files = _gs._parse_index_entries(APACHE_LISTING, f"{BASE}/wallets/", allow_private=False)
check("без allow_private приватный хост отсеян", not priv_dirs and not priv_files)

print("3) обходчик walk_index_of:")
with tempfile.TemporaryDirectory() as td:
    store = _gs._Store(Path(td), "t", set())
    st = _gs.walk_index_of(f"{BASE}/wallets/", store, depth=2, max_items=200, allow_private=True)
    check("листингов пройдено 2", st["listings"] == 2, str({k: st[k] for k in ('listings', 'dirs', 'files')}))
    check("подкаталог раскрыт", st["dirs"] >= 1)
    check("файлов скачано 5 (4 док + png)", st["files"] == 5, str(st["files"]))
    check("docs в store = 4", store.counters["docs"] == 4, str(store.counters))
    check("images в store = 1", store.counters["images"] == 1)
    saved = {p.name for p in (Path(td) / "files").iterdir()}
    check("keys.txt из подкаталога сохранён", any("keys" in n for n in saved), str(saved))
    # WIF доезжает до детекторов
    blob = "\n".join(p.read_text(encoding="utf-8") for p in (Path(td) / "files").iterdir())
    hits = analyze_text(blob, {"detect_wif": True}, get_bip39())
    vals = {h["value"] for h in hits}
    check("WIF1 найден детектором", WIF1 in vals)
    check("WIF2 найден детектором", WIF2 in vals)

print("4) бюджет max_items:")
with tempfile.TemporaryDirectory() as td:
    store = _gs._Store(Path(td), "t2", set())
    st = _gs.walk_index_of(f"{BASE}/wallets/", store, depth=2, max_items=1, allow_private=True)
    check("загрузок не больше бюджета", st["fetched"] <= 1, str(st["fetched"]))

print("5) run_global(mode=indexof) целиком:")
with tempfile.TemporaryDirectory() as td:
    res = run_global(Path(td), {
        "mode": "indexof",
        "urls": [f"{BASE}/wallets/"],
        "keywords": [],
        "engines": ["bing"],
        "depth": 2,
        "max_urls": 15,
        "max_files": 40,
    })
    src = res["sources"]["indexof"]
    check("источник indexof в отчёте", src["listings_found"] == 1)
    check("файлы скачаны режимом", res["docs"] == 4 and res["images"] == 1,
          f"docs={res['docs']} images={res['images']}")
    check("статистика обхода заполнена",
          any(w["listings"] == 2 for w in src["walked"].values()), str(src["walked"]))

srv.shutdown()
print()
if fails:
    print(f"ПРОВАЛЕНО: {len(fails)} -> {fails}")
    sys.exit(1)
print("ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ")
