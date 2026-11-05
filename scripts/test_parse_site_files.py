#!/usr/bin/env python3
"""Юнит-тест parse_site: страница отдаёт файловые ссылки — они должны попасть
в files/ (и pdf-текст — в pages/), а не только картинки."""

import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "mini-services" / "scanner-service"))

from engine.sitespider import parse_site  # noqa: E402

WIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
SEED_TXT = f"backup\n{WIF}\n".encode()
HTML = f"""<html><body>
<img src="/pic.jpg">
<a href="/files/seed.txt">seed.txt</a>
</body></html>""".encode()

import io  # noqa: E402
import random  # noqa: E402

from PIL import Image  # noqa: E402

# картинка с шумом: не сжимается до размеров ниже _MIN_BYTES (3 КБ)
_rng = random.Random(42)
_img = Image.new("RGB", (400, 400))
_img.putdata([(_rng.randrange(256), _rng.randrange(256), _rng.randrange(256))
              for _ in range(400 * 400)])
_buf = io.BytesIO()
_img.save(_buf, "JPEG", quality=90)
JPG_300 = _buf.getvalue()
assert len(JPG_300) > 4096, f"фикстура слишком мала: {len(JPG_300)}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/":
            body, ct = HTML, "text/html"
        elif self.path == "/files/seed.txt":
            body, ct = SEED_TXT, "text/plain"
        elif self.path == "/pic.jpg":
            body, ct = JPG_300, "image/jpeg"
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
    base = f"http://127.0.0.1.nip.io:{port}"

    ok = True

    def check(cond, msg):
        nonlocal ok
        print(("PASS" if cond else "FAIL"), "-", msg)
        if not cond:
            ok = False

    with tempfile.TemporaryDirectory() as td:
        res = parse_site(Path(td) / "images", base + "/", max_num=5, archive="no")
        info = ((res.get("keywords") or {}).get(base + "/") or {}).get("engines", {}).get("site", {})
        check(res.get("total", 0) >= 1, f"картинки скачаны (total={res.get('total')})")
        files = sorted((Path(td) / "files").glob("*")) if (Path(td) / "files").is_dir() else []
        check(any(f.name.endswith("seed.txt") for f in files),
              f"seed.txt со страницы в files/ ({[f.name for f in files]})")
        check(bool(res.get("page_text")), "page_text присутствует")
        check(not info.get("error"), f"без ошибок (info={info})")

    srv.shutdown()
    print("\nИТОГ:", "ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ" if ok else "ЕСТЬ ОШИБКИ")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
