#!/usr/bin/env python3
"""Юнит-регрессия: перебор скрытых папок (режим hidden глобального поиска).

Фейк-сайт отдаёт: .git-репозиторий, .env с WIF, .htaccess, .DS_Store с именами
(ASCII + UTF-16BE), каталог /backup/ с листингом и подкаталогом /old/, путь
/admin/ с 403. Всё остальное — «мягкая 404» (html-заглушка с кодом 200).

Проверяется: находки помечены верно, мягкие 404 не считаются попаданиями,
.git добирается до extras, имена из .DS_Store пробуются, листинги обходятся
(файлы wallet.txt/keys.txt сохранены), 403 помечен «закрыт».
"""
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "mini-services" / "scanner-service"))

from engine.globalsearch import (  # noqa: E402
    _Store,
    _ds_store_names,
    normalize_site_root,
    probe_hidden_paths,
)

WIF = "L51Uc2DVUmVXTftYY3oqzbf5UkTnHgNk4LKsrKJadp9NAyzHqUP1"  # валидный (см. test_wif_regression)

SOFT404 = b"<html><head><title>Welcome to CorpSite</title></head><body>Nothing here</body></html>"


def make_ds_store() -> bytes:
    blob = b"\x00\x00\x00\x01Bud1"
    blob += b"\x00\x01Iloc" + b"\x00" * 10               # служебный чанк — не имя
    blob += b"secret.txt"                                 # имя в ASCII
    blob += "wallet-backup.zip".encode("utf-16-be")       # имя в UTF-16BE (с дефисом)
    blob += b"noextname"                                  # без точки — фильтруется
    blob += b"._trash"                                    # AppleDouble — фильтруется
    return blob


FILES: dict[str, tuple[str, bytes]] = {
    "/.git/HEAD": ("text/plain", b"ref: refs/heads/master\n"),
    "/.git/config": ("text/plain", b"[core]\n\trepositoryformatversion = 0\n"),
    "/.git/logs/HEAD": ("text/plain", b"0000000000 a1b2c3d4e5 Ivan <ivan@corp> 1729000000 +0300\tcommit: init\n"),
    "/.env": ("application/octet-stream", f"DB_PASSWORD=hunter2\nWALLET_BACKUP={WIF}\n".encode()),
    "/.htaccess": ("text/plain", b"RewriteEngine On\n"),
    "/.DS_Store": ("application/octet-stream", make_ds_store()),
    "/secret.txt": ("text/plain", b"ftp creds: admin/admin\n"),
    "/wallet-backup.zip": ("application/zip", b"PK\x03\x04 fake zip payload"),
    "/backup/": ("text/html",
                 b"<html><head><title>Index of /backup</title></head><body>"
                 b'<a href="../">Parent Directory</a>'
                 b'<a href="wallet.txt">wallet.txt</a>'
                 b'<a href="old/">old/</a></body></html>'),
    "/backup/wallet.txt": ("text/plain", f"paper wallet backup\n{WIF}\n".encode()),
    "/backup/old/": ("text/html",
                     b"<html><head><title>Index of /backup/old</title></head><body>"
                     b'<a href="../">Parent Directory</a>'
                     b'<a href="keys.txt">keys.txt</a></body></html>'),
    "/backup/old/keys.txt": ("text/plain", b"old keys batch\n"),
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/keys/":   # существует, но закрыт (WAF/htaccess)
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"forbidden")
            return
        item = FILES.get(path)
        if item is None:
            # мягкая 404: заглушка с кодом 200 (типичная ошибка SPA/ CMS)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(SOFT404)
            return
        ct, data = item
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):  # тишина в логах
        pass


def check(cond: bool, msg: str) -> None:
    print(("  PASS  " if cond else "  FAIL  ") + msg)
    if not cond:
        globals()["FAILED"] = True


FAILED = False

# --- normalize_site_root -------------------------------------------------------------
print("== normalize_site_root ==")
check(normalize_site_root("example.com") == "https://example.com/", "домен без схемы -> https://")
check(normalize_site_root("http://127.0.0.1:8901") == "http://127.0.0.1:8901/", "IP с портом сохраняется")
check(normalize_site_root("localhost:3000") == "https://localhost:3000/", "localhost допускается")
check(normalize_site_root("https://site.io/sub/dir") == "https://site.io/sub/dir/", "путь сохраняется, хвост /")
check(normalize_site_root("not a url!!") == "", "мусор отбрасывается")
check(normalize_site_root("") == "", "пустая строка -> ''")

# --- _ds_store_names -----------------------------------------------------------------
print("== _ds_store_names ==")
names = _ds_store_names(make_ds_store())
check("secret.txt" in names, f"ASCII-имя извлечено: {names}")
check("wallet-backup.zip" in names, "UTF-16BE имя с дефисом извлечено")
check("noextname" not in names and "Iloc" not in names and "Bud1" not in names, "служебные токены отфильтрованы")
check(_ds_store_names(b"not a ds store") == [], "не-DS_Store -> []")

# --- probe_hidden_paths ---------------------------------------------------------------
print("== probe_hidden_paths ==")
srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

try:
    job_dir = Path(tempfile.mkdtemp(prefix="wcs_hidden_"))
    store = _Store(job_dir, "hid", set())
    stats = probe_hidden_paths(f"http://127.0.0.1:{port}/", store, depth=2, max_items=60)

    hits = stats["hits"]
    print("hits:", len(hits))
    for u in sorted(hits):
        print("   ", u.replace(f"http://127.0.0.1:{port}", ""), "->", hits[u])

    check(not stats.get("error"), f"без ошибок: {stats.get('error')}")
    check(hits.get(f"http://127.0.0.1:{port}/.git/HEAD") == "файл", ".git/HEAD найден")
    check(f"http://127.0.0.1:{port}/.git/config" in hits, ".git extras добраны (config)")
    check(f"http://127.0.0.1:{port}/.git/logs/HEAD" in hits, ".git extras добраны (logs/HEAD)")
    check(hits.get(f"http://127.0.0.1:{port}/.env") == "файл", ".env найден (octet-stream)")
    check(hits.get(f"http://127.0.0.1:{port}/.htaccess") == "файл", ".htaccess найден")
    check(hits.get(f"http://127.0.0.1:{port}/.DS_Store") == "файл", ".DS_Store найден")
    check(f"http://127.0.0.1:{port}/secret.txt" in hits, "имя из .DS_Store (ASCII) пробито")
    check(f"http://127.0.0.1:{port}/wallet-backup.zip" in hits, "имя из .DS_Store (UTF-16BE) пробито")
    check(hits.get(f"http://127.0.0.1:{port}/backup/") == "листинг", "/backup/ распознан как листинг")
    check(f"http://127.0.0.1:{port}/backup/old/" in hits, "подкаталог /backup/old/ найден (глубина 2)")
    check(hits.get(f"http://127.0.0.1:{port}/keys/") == "закрыт (403)", "403 помечен «закрыт»")
    # мягкие 404 не считаются попаданиями
    for absent in ("/tmp/", "/db/", "/wallet/", "/.git/", "/.svn/", "/data/", "/old/", "/private/"):
        check(f"http://127.0.0.1:{port}{absent}" not in hits, f"мягкая 404 {absent} — не попадание")
    # файлы листингов дошли до store
    saved = sorted(p.name for p in (job_dir / "files").iterdir())
    print("files/:", saved)
    docs = store.counters["docs"]
    check(docs >= 7, f"документов сохранено {docs} (ожидалось >=7)")
    wallet_saved = [n for n in saved if "wallet" in n and n.endswith(".txt")]
    check(bool(wallet_saved), "wallet.txt из листинга сохранён")
    check(any("keys" in n for n in saved), "keys.txt из /backup/old/ сохранён")
    env_saved = [n for n in saved if n.endswith(".env") or "env" in n]
    check(bool(env_saved), ".env сохранён в files/")
    check((job_dir / "files" / env_saved[0]).read_text().find(WIF) >= 0, "WIF внутри .env на месте")
    check(stats["listings"] >= 2, f"листингов {stats['listings']} (>=2)")
    check(stats["errors"] == 0, f"ошибок сети {stats['errors']}")
finally:
    srv.shutdown()

print()
print("РЕЗУЛЬТАТ:", "PASS" if not FAILED else "FAIL")
sys.exit(0 if not FAILED else 1)
