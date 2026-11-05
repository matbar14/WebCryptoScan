#!/usr/bin/env python3
"""E2E: POST /api/scan/global {mode: indexof, urls:[локальный каталог]} -> находки WIF."""
import io
import json
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# переиспользуем дерево каталога из юнит-теста
import test_indexof as tree  # noqa: E402

BASE = "http://127.0.0.1:3031"


def api(path, data=None):
    req = urllib.request.Request(BASE + path, data=data, method="POST")
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


srv = ThreadingHTTPServer(("127.0.0.1", 0), tree.H)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
root = f"http://127.0.0.1:{port}/wallets/"
print("каталог:", root)

for _ in range(40):
    try:
        urllib.request.urlopen(BASE + "/api/health", timeout=3)
        break
    except Exception:
        time.sleep(1)
else:
    sys.exit("движок не поднялся")

job = api("/api/scan/global", json.dumps({
    "mode": "indexof",
    "urls": [root],
    "keywords": [],
    "engines": ["bing"],
    "depth": 2,
    "max_urls": 5,
    "max_files": 40,
    "options": {},
}).encode())
jid = job["job_id"]
print("job:", jid, "|", job["label"])

for _ in range(60):
    st = api_get = urllib.request.urlopen(f"{BASE}/api/jobs/{jid}", timeout=10)
    j = json.loads(st.read().decode())
    if j.get("status") in ("done", "error"):
        break
    time.sleep(1)
print("status:", j.get("status"))
print("stats:", json.dumps(j.get("stats", {}), ensure_ascii=False))
print("crawl.indexof:", json.dumps((j.get("crawl") or {}).get("sources", {}).get("indexof", {}), ensure_ascii=False)[:400])
vals = [f["value"] for f in j.get("findings", [])]
print("находки:", vals)
ok = tree.WIF1 in vals and tree.WIF2 in vals
print("РЕЗУЛЬТАТ:", "PASS — оба WIF найдены через режим indexof" if ok else "FAIL")
sys.exit(0 if ok else 1)
