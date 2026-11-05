#!/usr/bin/env python3
"""E2E: режим «Скрытые папки» через живой движок /api/scan/global.

Сам поднимает движок (python3 server.py :3031) и фейк-сайт (локальный порт)
с .env (внутри валидный WIF), .git/HEAD, keys.txt (hex-ключ), seeds.txt
(BIP39-фраза), листингом /backup/ и мягкой 404-заглушкой.
Джоба 1 (обычные опции): WIF + hex + сид находятся.
Джоба 2 (keys_hex_wif_only): мастер-ключи (сид) пропущены, hex и WIF — на месте.
"""
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENGINE_DIR = ROOT / "mini-services" / "scanner-service"
BASE = "http://127.0.0.1:3031"
WIF = "L51Uc2DVUmVXTftYY3oqzbf5UkTnHgNk4LKsrKJadp9NAyzHqUP1"
ADDR = "1CGXL3qxNPEJc38KeMcpLCGor9o3PMrzUB"
HEX = "e867ccd842e522c96049087218182dcee671d000c4e47f8d32fcc166f39b71bc"
PHRASE = "abandon amount liar amount expire adjust cage candy arch gather drum buyer"

SOFT404 = b"<html><head><title>Corp</title></head><body>Nothing here</body></html>"
FILES = {
    "/.git/HEAD": ("text/plain", b"ref: refs/heads/main\n"),
    "/.git/logs/HEAD": ("text/plain", b"000000 a1b2c3 root <r@c> 1729000000 +0000\tcommit: init\n"),
    "/.env": ("application/octet-stream", f"DB_PASSWORD=x\nWALLET_BACKUP={WIF}\n".encode()),
    "/keys.txt": ("text/plain", f"keys dump\n{HEX}\nchange to: {ADDR}\n".encode()),
    "/wifs.txt": ("text/plain", f"wif batch\n{WIF}\n".encode()),
    "/seeds.txt": ("text/plain", f"master key backup\n{PHRASE}\n".encode()),
    "/backup/": ("text/html",
                 b"<html><head><title>Index of /backup</title></head><body>"
                 b'<a href="../">Parent Directory</a>'
                 b'<a href="seed.txt">seed.txt</a></body></html>'),
    "/backup/seed.txt": ("text/plain", f"seed backup\n{WIF}\n".encode()),
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        item = FILES.get(self.path.split("?")[0])
        if item is None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(SOFT404)
            return
        ct, data = item
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def out(*a):
    print(*a, flush=True)


def api(path, data=None, method=None, timeout=30):
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


# сторож: как бы всё ни зависло, не дольше 300 секунд (две джобы)
signal.alarm(300)

engine = None
srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
out("фейк-сайт:", f"http://127.0.0.1:{port}/")

try:
    # движок: чистим порт и стартуем как дочерний процесс
    subprocess.run(["pkill", "-f", "scanner-service/server.py"], capture_output=True)
    time.sleep(0.5)
    logf = open("/tmp/eng_hidden.log", "wb")
    engine = subprocess.Popen(
        [sys.executable, "server.py"], cwd=str(ENGINE_DIR),
        stdout=logf, stderr=subprocess.STDOUT,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    for _ in range(40):
        try:
            api("/api/health", timeout=3)
            break
        except Exception:
            if engine.poll() is not None:
                out("движок упал при старте, лог:")
                out(Path("/tmp/eng_hidden.log").read_text(errors="replace")[-2000:])
                sys.exit(1)
            time.sleep(1)
    else:
        sys.exit("движок не ответил за 40с")
    out("движок жив")

    def run_job(options: dict) -> tuple[str, dict]:
        body = json.dumps({
            "mode": "hidden",
            "urls": [f"http://127.0.0.1:{port}/"],
            "depth": 2,
            "max_files": 40,
            "options": options,
        }).encode()
        job = api("/api/scan/global", data=body, timeout=60)
        jid = job["job_id"]
        out("job:", jid, "| label:", job.get("label"))
        st: dict = {}
        for _ in range(120):
            st = api(f"/api/jobs/{jid}", timeout=15)
            if st.get("status") in ("done", "error"):
                break
            time.sleep(1)
        return jid, st

    # --- джоба 1: обычные опции — WIF + hex + сид находятся -----------------------
    jid1, st1 = run_job({})

    # --- джоба 2: строгий режим — мастер-ключи пропускаем, ищем hex и WIF ---------
    jid2, st2 = run_job({"keys_hex_wif_only": True})
finally:
    srv.shutdown()
    if engine and engine.poll() is None:
        engine.terminate()
        try:
            engine.wait(timeout=5)
        except Exception:
            engine.kill()
    out("уборка выполнена")

for name, st in (("обычный", st1), ("строгий", st2)):
    out(f"— джоба ({name}) — status:", st.get("status"), "| error:", st.get("error"))
    hidden = ((st.get("crawl") or {}).get("sources") or {}).get("hidden") or {}
    out("hidden:", json.dumps({k: hidden.get(k) for k in ("roots", "probed", "hits", "fetched")},
                              ensure_ascii=False))
    for f in hidden.get("found") or []:
        out("   ", f)
    findings = [f for f in st.get("findings", []) if f.get("source") == "file"]
    out("file-находки:", sorted(f"{f.get('type')}:{(f.get('value') or '')[:20]}" for f in findings))

findings1 = [f for f in st1.get("findings", []) if f.get("source") == "file"]
types1 = {f.get("type") for f in findings1}
vals1 = {f.get("value") for f in findings1}

findings2 = [f for f in st2.get("findings", []) if f.get("source") == "file"]
types2 = {f.get("type") for f in findings2}
vals2 = {f.get("value") for f in findings2}

ok1 = st1.get("status") == "done" and WIF in vals1 and HEX in vals1 \
    and any(t.startswith("bip39") for t in types1)
out("джоба 1:", "PASS — WIF+hex+сид в находках" if ok1 else "FAIL")

ok2 = st2.get("status") == "done" and WIF in vals2 and HEX in vals2 \
    and not any(t.startswith(("bip39", "seedqr", "electrum")) for t in types2) \
    and not any(t.startswith("address_") for t in types2)
out("джоба 2:", "PASS — hex+WIF на месте, мастер-ключи пропущены" if ok2 else "FAIL")

out("РЕЗУЛЬТАТ:", "PASS" if ok1 and ok2 else "FAIL")
sys.exit(0 if ok1 and ok2 else 1)
