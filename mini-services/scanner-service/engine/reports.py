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

CSV_FIELDS = [
    "id",
    "image",
    "qr_index",
    "type",
    "value",
    "address",
    "address_uncompressed",
    "valid_checksum",
    "word_count",
    "engine",
    "variant",
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
            w.writerow(row)

    return {"keys": len(keys), "seeds": len(seeds), "total": len(findings)}
