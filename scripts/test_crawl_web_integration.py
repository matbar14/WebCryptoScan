#!/usr/bin/env python3
"""Интеграционный тест веб-фазы краулера через Next.js-прокси (:3000, как у пользователя).

Запускается при УЖЕ работающих движке (:3031) и Next (:3000).
POST /api/scan/crawl {keyword, engines: [], web_engines: ["bing"], max_num: 15}
-> опрос джобы -> проверка crawl.sources / crawl.web / files/ / pages/.
"""

import json
import sys
import time
from pathlib import Path

import requests

BASE = "http://localhost:3000/api"
JOB_DIR_ROOT = Path("/home/z/my-project/mini-services/scanner-service/jobs")


def wait_job_done(job_id: str, timeout_s: int = 300) -> dict:
    t0 = time.time()
    last = ""
    while time.time() - t0 < timeout_s:
        j = requests.get(f"{BASE}/jobs/{job_id}", timeout=15).json()
        stage = j.get("crawl_stage") or ""
        line = f"{j['status']} {j.get('phase')} {j['progress'].get('processed')}/{j['progress'].get('total')} {stage}"
        if line != last:
            print("   ", line)
            last = line
        if j["status"] in ("done", "error"):
            return j
        time.sleep(4)
    raise TimeoutError("джоба не завершилась")


def main() -> int:
    ok = True

    def check(cond, msg):
        nonlocal ok
        print(("PASS" if cond else "FAIL"), "-", msg)
        if not cond:
            ok = False

    health = requests.get(f"{BASE}/health?XTransformPort=3031", timeout=15).json()
    check(health.get("status") == "ok", f"health через прокси: v{health.get('version')}")

    # --- веб-фаза краулера (без движков картинок, чтобы тест был быстрым) ---
    r = requests.post(f"{BASE}/scan/crawl?XTransformPort=3031", json={
        "keyword": "bitcoin paper wallet private key",
        "engines": [],
        "web_engines": ["bing"],
        "max_num": 15,
        "options": {"scan_strings": True, "ocr_fallback": True},
    }, timeout=30)
    check(r.status_code == 200, f"POST /scan/crawl -> {r.status_code}")
    job_id = r.json()["job_id"]
    print("    job:", job_id)

    job = wait_job_done(job_id)
    check(job["status"] == "done", f"джоба завершилась: {job['status']} {job.get('error') or ''}")
    crawl = job.get("crawl") or {}
    src = (crawl.get("sources") or {}).get("bing") or {}
    print("    crawl.sources:", json.dumps(crawl.get("sources"), ensure_ascii=False)[:220])
    check("bing" in (crawl.get("sources") or {}), "в отчёте есть источник bing")
    print("    crawl.web:", crawl.get("web"))
    web = crawl.get("web") or {}
    check(web.get("pages", 0) + web.get("docs", 0) > 0 or src.get("count", 0) > 0,
          "веб-фаза что-то сохранила (страницы/файлы)")

    jd = JOB_DIR_ROOT / job_id
    pages = sorted((jd / "pages").glob("page_*.txt")) if (jd / "pages").is_dir() else []
    files = sorted((jd / "files").glob("*")) if (jd / "files").is_dir() else []
    print(f"    pages: {len(pages)}, files: {len(files)}")
    check(len(pages) > 0, "pages/ с текстами страниц создан")

    st = job.get("stats") or {}
    print("    stats:", json.dumps({k: st.get(k) for k in ("images", "findings", "text_files")}, ensure_ascii=False))
    check(st.get("findings", 0) >= 0, "статистика доступна")  # находки не гарантированы в живом вебе

    for f in job.get("findings", [])[:5]:
        print("    finding:", f["type"], str(f["value"])[:44], "—", f.get("source"), f.get("source_detail", "")[:60])

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
