#!/usr/bin/env python3
"""E2E: движок + загрузка txt с обрезанным и полным WIF через /api/scan/upload.

Воспроизводит сценарий пользователя «тест с WIF … — не добавился»:
  file_trunc.txt — обрезанный ключ (44 симв.)  -> в отчёте его быть НЕ должно
  file_full.txt  — полный ключ (52 симв.)      -> должен добавиться как wif_compressed
"""
import io
import json
import sys
import time
import urllib.request
import uuid

TRUNC = "L51Uc2DVUmVXTftYY3oqzbf5UkTnHgNk4LKsrKJadp9N"
FULL = "L51Uc2DVUmVXTftYY3oqzbf5UkTnHgNk4LKsrKJadp9NAyzHqUP1"
BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:3031"


def multipart(files: list[tuple[str, bytes]]) -> tuple[bytes, str]:
    b = uuid.uuid4().hex
    body = io.BytesIO()
    for fname, data in files:
        body.write(f"--{b}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{fname}\"\r\n"
                   "Content-Type: text/plain\r\n\r\n".encode() + data + b"\r\n")
    body.write(f"--{b}--\r\n".encode())
    return body.getvalue(), f"multipart/form-data; boundary={b}"


def api(path: str, data=None, ctype=None, method=None):
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if ctype:
        req.add_header("Content-Type", ctype)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


# health
for _ in range(60):
    try:
        api("/api/health")
        break
    except Exception:
        time.sleep(1)
else:
    sys.exit("движок не ответил")

body, ctype = multipart([
    ("trunc.txt", f"wallet key: {TRUNC}\n".encode()),
    ("full.txt", f"wallet key: {FULL}\n".encode()),
])
job = api("/api/scan/upload", data=body, ctype=ctype)
jid = job["job_id"] if "job_id" in job else job.get("id")
print("job:", jid)

vals = []
for _ in range(60):
    st = api(f"/api/jobs/{jid}")
    if st.get("status") in ("done", "error"):
        print("status:", st["status"], "| stats:", json.dumps(st.get("stats", {}), ensure_ascii=False))
        vals = [f["value"] for f in st.get("findings", []) if f.get("source") == "file"]
        break
    time.sleep(1)
else:
    sys.exit("джоба не завершилась")

print("file-находки:", vals)
ok = (FULL in vals) and (TRUNC not in vals)
print("РЕЗУЛЬТАТ:", "PASS — полный добавлен, обрезок отклонён" if ok else "FAIL")
sys.exit(0 if ok else 1)
