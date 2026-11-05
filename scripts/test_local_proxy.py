#!/usr/bin/env python3
"""Проверка локального прокси Next -> Python (эмуляция машины пользователя, без Caddy).

Запуск: python3 scripts/test_local_proxy.py [base_url]   (по умолчанию http://localhost:3000)
Шлёт health, реальный multipart-скан (QR с WIF), ждёт джобу, тянет текстовый отчёт.
"""
import io
import json
import sys
import time
import urllib.request
import uuid

BASE = "http://localhost:3000/api/"
QP = "XTransformPort=3031"
WIF = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"


def url(path: str) -> str:
    sep = "&" if "?" in path else "?"
    return BASE + path + sep + QP


def get(path: str):
    with urllib.request.urlopen(url(path), timeout=60) as r:
        return r.status, json.loads(r.read().decode())


def post_multipart(path: str, files, fields):
    bound = "----wcs" + uuid.uuid4().hex
    body = io.BytesIO()
    for name, fname, data, ctype in files:
        body.write(f"--{bound}\r\n".encode())
        body.write(f'Content-Disposition: form-data; name="{name}"; filename="{fname}"\r\n'.encode())
        body.write(f"Content-Type: {ctype}\r\n\r\n".encode())
        body.write(data)
        body.write(b"\r\n")
    for k, v in fields.items():
        body.write(f"--{bound}\r\n".encode())
        body.write(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode())
        body.write(v.encode())
        body.write(b"\r\n")
    body.write(f"--{bound}--\r\n".encode())
    req = urllib.request.Request(
        url(path),
        data=body.getvalue(),
        headers={"Content-Type": f"multipart/form-data; boundary={bound}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.status, json.loads(r.read().decode())


def main() -> int:
    global BASE
    if len(sys.argv) > 1:
        BASE = sys.argv[1].rstrip("/") + "/api/"

    ok = True

    def check(name: str, cond: bool, extra="") -> None:
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name + (f" — {extra}" if extra else ""))
        ok = ok and cond

    st, health = get("health")
    check("health через прокси", st == 200 and health.get("status") == "ok", health.get("status"))

    import qrcode

    buf = io.BytesIO()
    qrcode.make(WIF).save(buf, format="PNG")
    opts = json.dumps(
        {
            "preprocess": True, "detect_wif": True, "detect_mini": True, "detect_hex": True,
            "detect_seed": True, "detect_seedqr": True, "detect_electrum": True,
            "detect_addresses": True, "ocr_fallback": False, "scan_strings": False,
        }
    )
    st, job = post_multipart(
        "scan/upload",
        [("files", "wif_qr.png", buf.getvalue(), "image/png")],
        {"options": opts, "label": "proxy-test"},
    )
    check("scan/upload (multipart)", st == 200 and bool(job.get("job_id")), job)
    jid = job.get("job_id", "")

    j = {}
    for _ in range(90):
        st, j = get(f"jobs/{jid}")
        if j.get("status") in ("done", "error"):
            break
        time.sleep(1)
    check("джоба завершилась", j.get("status") == "done", j.get("status"))
    types = [f.get("type") for f in j.get("findings", [])]
    check("находка WIF", any(str(t).startswith("wif") for t in types), types)

    with urllib.request.urlopen(url(f"jobs/{jid}/report?fmt=txt"), timeout=60) as r:
        txt = r.read().decode(errors="replace")
        code = r.status
    check("отчёт TXT (бинарный passthrough)", code == 200 and len(txt) > 20, f"{code}, {len(txt)} байт")

    print("ИТОГ:", "ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ" if ok else "ЕСТЬ СБОИ")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
