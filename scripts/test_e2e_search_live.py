#!/usr/bin/env python3
"""E2E на живом движке: github-режим без токена (Sourcegraph) + keywords через Arquivo."""
import sys, time, json, requests

BASE = "http://127.0.0.1:3031"

# 1) health
for _ in range(50):
    try:
        if requests.get(BASE + "/api/health", timeout=2).status_code == 200:
            print("engine: up")
            break
    except Exception:
        time.sleep(0.5)
else:
    sys.exit("engine did not come up")

# 2) github-режим БЕЗ токена
r = requests.post(BASE + "/api/scan/global", json={
    "mode": "github", "presets": ["known_seeds"], "max_files": 6,
}, timeout=30)
print("POST github:", r.status_code, r.json().get("label", ""))
job_a = r.json()["job_id"]

def poll(jid, limit=300):
    t0 = time.time()
    while time.time() - t0 < limit:
        j = requests.get(f"{BASE}/api/jobs/{jid}", timeout=10).json()
        st = j.get("status") or j.get("phase")
        stage = j.get("crawl_stage") or ""
        if st in ("done", "error"):
            return j
        time.sleep(3)
        print(f"  [{int(time.time()-t0)}s] {st} {stage}", flush=True)
    return None

ja = poll(job_a, 360)
if not ja:
    sys.exit("github job timed out")
print("\n== GITHUB JOB:", ja.get("status"), "| error:", ja.get("error"))
crawl = ja.get("crawl") or {}
print("sources:", json.dumps(crawl.get("sources"), ensure_ascii=False)[:600])
print("counters: images=%s docs=%s pages=%s blocked=%s" % (
    crawl.get("images"), crawl.get("docs"), crawl.get("pages"), crawl.get("blocked")))
findings = ja.get("findings") or []
vals = [f.get("value", "") for f in findings]
wif_hits = [v for v in vals if "5HpHag" in v]
seed_hits = [v for v in vals if v.lower().startswith("abandon")]
print("findings total:", len(vals))
print("WIF test-key hits:", wif_hits[:2])
print("abandon-seed hits:", [s[:60] for s in seed_hits[:2]])
types = {}
for f in findings:
    types[f.get("type", "?")] = types.get(f.get("type", "?"), 0) + 1
print("finding types:", types)

# 3) keywords-режим через Arquivo (прямой вызов run_global) — только если флаг kw
if "kw" not in sys.argv:
    sys.exit(0)
sys.path.insert(0, "/home/z/my-project/mini-services/scanner-service")
from pathlib import Path
from engine.globalsearch import run_global

kw_dir = Path("/tmp/kwjob")
import shutil
shutil.rmtree(kw_dir, ignore_errors=True)
t0 = time.time()
res = run_global(kw_dir, {
    "mode": "keywords",
    "keywords": ["bitcoin paper wallet backup", "wallet.dat backup"],
    "engines": ["arquivo"],
    "max_pages": 6, "max_files": 8,
}, progress=lambda s, d, t: None)
print(f"\n== KEYWORDS via Arquivo ({time.time()-t0:.0f}s)")
print("sources.arquivo:", json.dumps(res["sources"].get("arquivo"), ensure_ascii=False)[:400])
print("counters:", {k: res[k] for k in ("images", "docs", "pages", "blocked")})
pages_mf = kw_dir / "pages" / "manifest.json"
if pages_mf.is_file():
    entries = json.loads(pages_mf.read_text())
    print("sample pages:", [e.get("url", "")[:90] for e in entries[:4]])
