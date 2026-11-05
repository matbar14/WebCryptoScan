#!/usr/bin/env python3
"""Юнит-тест веб-фазы краулера (режим keywords в run_global).

Поднимает локальный HTTP-сервер со страницей-листингом (index of), файлом
seed.txt с валидным WIF-ключом и PNG-картинкой. SERP подменяется на локальные
URL. Проверяет: страницы -> pages/, файлы -> files/, картинки -> images/,
строковые детекторы находят WIF из файла.
"""

import io
import json
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "mini-services" / "scanner-service"))

from engine import globalsearch as gs  # noqa: E402
from engine.detectors import analyze_text, get_bip39  # noqa: E402

WIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
SEED_TXT = f"my wallet backup\nprivate key: {WIF}\n mnemomic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n".encode()
# 1x1 PNG
PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000d49444154789c626001000000ffff030000060005"
    "57bfabd40000000049454e44ae426082"
)

HTML_LISTING = """<!doctype html><html><head><title>Index of /backup</title></head>
<body><h1>Index of /backup</h1>
<ul>
<li><a href="../">..</a></li>
<li><a href="seed.txt">seed.txt</a></li>
<li><a href="wallet.png">wallet.png</a></li>
<li><a href="notes.html">notes.html</a></li>
</ul>
<p>misc text without secrets</p>
</body></html>"""

HTML_NOTES = "<html><body><p>recovery phrase paper backup page, no real keys here</p></body></html>"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # тишина в логах
        pass

    def do_GET(self):
        if self.path.endswith("seed.txt"):
            body, ct = SEED_TXT, "text/plain"
        elif self.path.endswith("wallet.png"):
            body, ct = PNG, "image/png"
        elif self.path.endswith("notes.html"):
            body, ct = HTML_NOTES.encode(), "text/html"
        elif self.path.endswith("/") or self.path.endswith("listing"):
            body, ct = HTML_LISTING.encode(), "text/html"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    # 127.0.0.1.nip.io резолвится в 127.0.0.1, но выглядит как публичный хост —
    # иначе _is_fetchable_url режет ссылки на файлы (SSRF-защита от localhost)
    base = f"http://127.0.0.1.nip.io:{port}"

    # подменяем bing: выдача — листинг + notes
    fake_urls = [f"{base}/backup/", f"{base}/notes.html"]
    gs.SERPS["bing"] = lambda kw, n=15: {"urls": list(fake_urls), "error": None}
    # marginalia не вызываем — не включаем в engines

    with tempfile.TemporaryDirectory() as td:
        job_dir = Path(td)
        stages: list[str] = []

        def prog(stage, done, total):
            stages.append(stage)

        res = gs.run_global(job_dir, {
            "mode": "keywords",
            "keywords": ["bitcoin seed phrase backup"],
            "engines": ["bing"],
            "max_pages": 5,
            "max_files": 10,
        }, progress=prog)

        ok = True

        def check(cond, msg):
            nonlocal ok
            print(("PASS" if cond else "FAIL"), "-", msg)
            if not cond:
                ok = False

        src = res["sources"].get("bing") or {}
        check(src.get("urls_found") == 2, f"bing: urls_found=2 (получено {src.get('urls_found')})")
        check(src.get("count", 0) >= 3, f"сохранено >=3 находок (получено {src.get('count')})")

        files = sorted((job_dir / "files").glob("*")) if (job_dir / "files").is_dir() else []
        check(any(f.name.endswith("seed.txt") for f in files),
              f"seed.txt в files/ ({[f.name for f in files]})")

        pages_manifest = job_dir / "pages" / "manifest.json"
        check(pages_manifest.is_file(), "pages/manifest.json создан")
        if pages_manifest.is_file():
            entries = json.loads(pages_manifest.read_text())
            check(len(entries) == 2, f"в манифесте 2 страницы (получено {len(entries)})")

        # строковые детекторы на скачанном файле — WIF находится
        seed_file = next((f for f in files if f.name.endswith("seed.txt")), None)
        if seed_file:
            findings = analyze_text(seed_file.read_text(errors="replace"),
                                    {"detect_wif": True, "detect_seed": True,
                                     "detect_mini": True, "detect_hex": True,
                                     "detect_seedqr": True, "detect_electrum": True},
                                    get_bip39())
            check(any(f["value"] == WIF for f in findings),
                  f"WIF найден детектором в seed.txt ({[f['type'] for f in findings]})")
        else:
            check(False, "seed.txt не скачан — детекторы не проверены")

        check(res["docs"] >= 1 and res["pages"] == 2,
              f"итоги: docs={res['docs']} pages={res['pages']} images={res['images']}")
        check(any("Веб-поиск" in s for s in stages), "прогресс содержит этапы веб-поиска")

    srv.shutdown()
    print("\nИТОГ:", "ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ" if ok else "ЕСТЬ ОШИБКИ")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
