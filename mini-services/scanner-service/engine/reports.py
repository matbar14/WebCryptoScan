#!/usr/bin/env python3
"""
MrRobotQR 2.0 — отчёты по результатам сканирования.

  keylist.txt       — уникальные приватные ключи (WIF/mini/hex), формат оригинала
  seedlist.txt      — уникальные BIP39 сид-фразы
  scan_report.json  — полная машина-читаемая выгрузка (статистика + находки)
  scan_report.csv   — табличная выгрузка всех находок
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

KEY_TYPES = {"wif_compressed", "wif_uncompressed", "mini_private_key", "hex_private_key"}

# монета по типу находки-адреса и по ключу словаря addresses
COIN_BY_ADDR_TYPE = {
    "address_btc_p2pkh": "BTC", "address_btc_p2sh": "BTC", "address_btc_segwit": "BTC",
    "address_btc_taproot": "BTC", "address_ltc_p2pkh": "LTC", "address_ltc_p2sh": "LTC",
    "address_ltc_segwit": "LTC", "address_ltc_taproot": "LTC", "address_doge": "DOGE",
    "address_dash": "DASH", "address_dash_p2sh": "DASH", "address_eth": "ETH",
    "address_bch_cashaddr": "BCH", "address_xrp": "XRP", "address_trx": "TRX",
    "address_sol": "SOL",
}
COIN_BY_ADDR_KEY = {
    "btc_legacy": "BTC", "btc_legacy_uncompressed": "BTC", "btc_segwit": "BTC",
    "btc_taproot": "BTC", "ltc": "LTC", "ltc_segwit": "LTC", "ltc_taproot": "LTC",
    "doge": "DOGE", "dash": "DASH", "eth": "ETH",
}

CSV_FIELDS = [
    "id",
    "image",
    "source",
    "qr_index",
    "type",
    "value",
    "address",
    "address_uncompressed",
    "addresses",
    "valid_checksum",
    "word_count",
    "engine",
    "variant",
    "source_detail",
    "detail",
]


def _unique_by_value(findings: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for f in findings:
        if f["value"] not in seen:
            seen.add(f["value"])
            out.append(f)
    return out


def write_reports(job: dict, job_dir: Path) -> dict:
    findings = job.get("findings", [])

    # --- keylist.txt: только приватные ключи (как в оригинальном MrRobotQR) ---
    keys = _unique_by_value([f for f in findings if f.get("type") in KEY_TYPES])
    (job_dir / "keylist.txt").write_text("".join(f["value"] + "\n" for f in keys), encoding="utf-8")

    # --- seedlist.txt: уникальные сид-фразы (BIP39, SeedQR, Electrum) ---
    seeds = _unique_by_value(
        [f for f in findings if str(f.get("type", "")).startswith(("bip39", "seedqr", "electrum"))]
    )
    (job_dir / "seedlist.txt").write_text("".join(f["value"] + "\n" for f in seeds), encoding="utf-8")

    # --- addresses.txt: мультивалютные адреса (найденные + полученные из ключей/сидов) ---
    rows: list[tuple[str, str, str]] = []
    seen_addr: set[tuple[str, str]] = set()
    for f in findings:
        t = str(f.get("type", ""))
        fid = f.get("id", "?")
        if t.startswith("address_"):
            coin = COIN_BY_ADDR_TYPE.get(t, "?")
            key = (coin, f["value"])
            if key not in seen_addr:
                seen_addr.add(key)
                rows.append((coin, f["value"], f"находка #{fid} ({t})"))
        for k, v in (f.get("addresses") or {}).items():
            coin = COIN_BY_ADDR_KEY.get(k, k.upper())
            key = (coin, v)
            if key not in seen_addr:
                seen_addr.add(key)
                rows.append((coin, v, f"из находки #{fid} ({t})"))
    lines = [
        f"# Адреса — джоба {job.get('id', '?')} ({job.get('label', '')})",
        f"# всего: {len(rows)} (найденные в QR + выведенные из ключей/сидов)",
        "# coin\taddress\tисточник",
    ]
    lines += [f"{coin}\t{addr}\t{src}" for coin, addr, src in rows]
    (job_dir / "addresses.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # --- scan_report.json ---
    report = {
        "job_id": job["id"],
        "label": job.get("label", ""),
        "source_type": job.get("source_type", ""),
        "created_at": job.get("created_at"),
        "finished_at": job.get("finished_at"),
        "options": job.get("options", {}),
        "stats": job.get("stats", {}),
        "crawl": job.get("crawl"),
        "errors": job.get("errors", []),
        "findings": findings,
    }
    (job_dir / "scan_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # --- scan_report.csv ---
    with open(job_dir / "scan_report.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        for f in findings:
            row = {k: f.get(k, "") for k in CSV_FIELDS}
            for k in CSV_FIELDS:
                if isinstance(row[k], bool):
                    row[k] = "yes" if row[k] else "no"
            if isinstance(row.get("addresses"), dict):
                row["addresses"] = json.dumps(row["addresses"], ensure_ascii=False)
            w.writerow(row)

    return {"keys": len(keys), "seeds": len(seeds), "addresses": len(rows), "total": len(findings)}
