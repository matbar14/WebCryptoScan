#!/usr/bin/env python3
"""
MrRobotQR 2.0 — веб-сервис сканера (mini service, порт 3031).

API:
  GET  /api/health                     — состояние сервиса и движков
  GET  /api/presets                    — пресеты ключевых слов краулера
  POST /api/scan/upload                — джоба: сканирование загруженных файлов (multipart)
  POST /api/scan/folder                — джоба: сканирование папки на сервере
  POST /api/scan/crawl                 — джоба: краулинг по ключевым словам + сканирование
  GET  /api/jobs                       — список джоб
  GET  /api/jobs/{id}                  — статус, прогресс, статистика, находки
  DELETE /api/jobs/{id}                — удалить джобу
  GET  /api/jobs/{id}/report?fmt=...   — отчёты: txt | csv | json | seeds
  GET  /api/jobs/{id}/images/{name}    — оригинал изображения
  GET  /api/jobs/{id}/annotated/{name} — превью с рамками найденных QR
"""

from __future__ import annotations

import json
import re
import shutil
import threading
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from engine.crawler import ENGINE_NAMES, IMAGE_EXTS, PRESETS, collect_image_paths, crawl_images
from engine.decoder import decode_image, open_image
from engine.detectors import analyze_text, get_bip39
from engine.reports import write_reports
from PIL import Image
import cv2
import numpy as np

BASE_DIR = Path(__file__).resolve().parent
JOBS_DIR = BASE_DIR / "jobs"
JOBS_DIR.mkdir(exist_ok=True)

VERSION = "2.0.0"

app = FastAPI(title="MrRobotQR 2.0 scanner service", version=VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

JOBS: dict[str, dict] = {}
LOCK = threading.Lock()

DEFAULT_OPTIONS = {
    "preprocess": True,
    "detect_wif": True,
    "detect_mini": True,
    "detect_hex": True,
    "detect_seed": True,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_name(name: str) -> str:
    base = Path(name).name
    base = re.sub(r"[^0-9A-Za-z._-]+", "_", base).strip("._")
    return base[:120] or "image"


def _new_stats() -> dict:
    return {
        "images": 0,
        "qr_codes": 0,
        "findings": 0,
        "by_type": {},
        "valid_seeds": 0,
        "invalid_seeds": 0,
    }


def _new_job(label: str, source_type: str, options: dict) -> dict:
    return {
        "id": uuid.uuid4().hex[:12],
        "label": label,
        "source_type": source_type,
        "status": "queued",  # queued | crawling | running | done | error
        "phase": "scan",     # crawl | scan | done
        "created_at": _now(),
        "finished_at": None,
        "progress": {"total": 0, "processed": 0},
        "stats": _new_stats(),
        "findings": [],
        "errors": [],
        "options": options,
        "crawl": None,
        "error": None,
    }


def _save_job(job: dict) -> None:
    d = JOBS_DIR / job["id"]
    d.mkdir(parents=True, exist_ok=True)
    (d / "job.json").write_text(json.dumps(job, ensure_ascii=False, indent=1), encoding="utf-8")


def _load_job_from_disk(job_id: str) -> dict | None:
    p = JOBS_DIR / job_id / "job.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _get_job(job_id: str) -> dict:
    with LOCK:
        job = JOBS.get(job_id)
    if job is None:
        job = _load_job_from_disk(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Джоба не найдена")
        with LOCK:
            JOBS[job_id] = job
    return job


def _job_dir(job_id: str) -> Path:
    d = JOBS_DIR / job_id
    if not d.is_dir():
        raise HTTPException(status_code=404, detail="Каталог джобы не найден")
    return d


def _safe_file(job_id: str, sub: str, name: str) -> Path:
    base = (JOBS_DIR / job_id / sub).resolve()
    p = (base / name).resolve()
    if p != base and base not in p.parents:
        raise HTTPException(status_code=404, detail="Некорректный путь")
    if not p.is_file():
        raise HTTPException(status_code=404, detail="Файл не найден")
    return p


# --- Рабочий поток джобы --------------------------------------------------------

def _annotate(job_id: str, image_path: Path, results: list) -> str:
    """Рисует рамки найденных QR на уменьшенной копии; возвращает имя файла превью."""
    img = cv2.imdecode(np.fromfile(str(image_path), dtype=np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        img = cv2.cvtColor(np.array(open_image(str(image_path))), cv2.COLOR_RGB2BGR)
    h, w = img.shape[:2]
    thick = max(2, min(h, w) // 300)
    for i, r in enumerate(results):
        x, y, bw, bh = r.bbox
        p1 = (max(0, x - 3), max(0, y - 3))
        p2 = (min(w - 1, x + bw + 3), min(h - 1, y + bh + 3))
        cv2.rectangle(img, p1, p2, (52, 211, 153), thick)  # emerald
        label = f"QR{i + 1}"
        ty = max(thick * 6, y - 6)
        cv2.putText(img, label, (p1[0], ty), cv2.FONT_HERSHEY_SIMPLEX, max(0.5, min(h, w) / 900), (52, 211, 153), thick)
    scale = min(1.0, 560.0 / max(1, w))
    if scale < 1.0:
        img = cv2.resize(img, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
    out = JOBS_DIR / job_id / "annotated"
    out.mkdir(exist_ok=True)
    name = image_path.stem + ".jpg"
    cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 82])[1].tofile(str(out / name))
    return name


def _process_image(job: dict, image_path: Path) -> None:
    options = job["options"]
    try:
        img = open_image(str(image_path))
    except Exception as e:  # noqa: BLE001
        job["errors"].append({"image": image_path.name, "error": f"не удалось открыть: {e}"})
        job["stats"]["images"] += 1
        return
    try:
        results = decode_image(img, use_preprocess=bool(options.get("preprocess", True)))
    except Exception as e:  # noqa: BLE001
        job["errors"].append({"image": image_path.name, "error": f"ошибка декодирования: {e}"})
        job["stats"]["images"] += 1
        return

    bip39 = get_bip39()
    findings = []
    for qi, r in enumerate(results):
        for f in analyze_text(r.data, options, bip39):
            f.update(
                image=image_path.name,
                qr_index=qi,
                engine=r.engine,
                variant=r.variant,
                bbox=r.bbox,
            )
            findings.append(f)

    if results:
        job["stats"]["qr_codes"] += len(results)
        qr_images = job["stats"].setdefault("qr_images", [])
        qr_images.append(image_path.name)
        try:
            _annotate(job["id"], image_path, results)
        except Exception:
            traceback.print_exc()

    for f in findings:
        t = f["type"]
        job["stats"]["by_type"][t] = job["stats"]["by_type"].get(t, 0) + 1
        if t.startswith("bip39"):
            if f.get("valid_checksum"):
                job["stats"]["valid_seeds"] += 1
            else:
                job["stats"]["invalid_seeds"] += 1
        fid = len(job["findings"]) + 1
        f["id"] = fid
        job["findings"].append(f)
    job["stats"]["findings"] += len(findings)
    job["stats"]["images"] += 1


def _worker(job_id: str, image_paths: list[Path], crawl_params: dict | None) -> None:
    with LOCK:
        job = JOBS.get(job_id)
    try:
        if crawl_params is not None:
            job["status"] = "crawling"
            job["phase"] = "crawl"
            _save_job(job)
            res = crawl_images(JOBS_DIR / job_id / "images", **crawl_params)
            job["crawl"] = res
            image_paths = collect_image_paths(JOBS_DIR / job_id / "images")

        job["status"] = "running"
        job["phase"] = "scan"
        job["progress"]["total"] = len(image_paths)
        job["progress"]["processed"] = 0
        _save_job(job)

        for i, p in enumerate(image_paths):
            _process_image(job, p)
            job["progress"]["processed"] = i + 1
            if i % 10 == 0 or i == len(image_paths) - 1:
                _save_job(job)

        job["phase"] = "done"
        job["status"] = "done"
        job["finished_at"] = _now()
        counts = write_reports(job, JOBS_DIR / job_id)
        job["report_counts"] = counts
        _save_job(job)
    except Exception as e:  # noqa: BLE001
        job["status"] = "error"
        job["error"] = f"{type(e).__name__}: {e}"
        job["finished_at"] = _now()
        traceback.print_exc()
        _save_job(job)


def _start_job(job: dict, image_paths: list[Path], crawl_params: dict | None = None) -> str:
    with LOCK:
        JOBS[job["id"]] = job
    _save_job(job)
    threading.Thread(target=_worker, args=(job["id"], image_paths, crawl_params), daemon=True).start()
    return job["id"]


# --- Эндпоинты -------------------------------------------------------------------

@app.get("/api/health")
def health():
    engines = {"pyzbar": True, "wechat": False, "opencv": True}
    try:
        from engine.decoder import _get_wechat

        _get_wechat()
        engines["wechat"] = True
    except Exception:
        pass
    words = 0
    try:
        words = len(get_bip39().words)
    except Exception:
        pass
    return {"status": "ok", "version": VERSION, "engines": engines, "bip39_words": words}


@app.get("/api/presets")
def presets():
    return PRESETS


def _parse_options(raw: str | None) -> dict:
    if not raw:
        return dict(DEFAULT_OPTIONS)
    try:
        given = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="options: некорректный JSON")
    opts = dict(DEFAULT_OPTIONS)
    for k in DEFAULT_OPTIONS:
        if k in given:
            opts[k] = bool(given[k])
    return opts


@app.post("/api/scan/upload")
async def scan_upload(
    files: list[UploadFile] = File(...),
    options: str = Form("{}"),
    label: str = Form("Загруженные файлы"),
):
    if not files:
        raise HTTPException(status_code=400, detail="Файлы не переданы")
    opts = _parse_options(options)
    job = _new_job(label=label or "Загруженные файлы", source_type="upload", options=opts)
    img_dir = JOBS_DIR / job["id"] / "images"
    img_dir.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []
    for f in files:
        data = await f.read()
        if not data:
            continue
        name = _safe_name(f.filename or "image")
        dst = img_dir / name
        k = 1
        while dst.exists():
            dst = img_dir / f"{Path(name).stem}_{k}{Path(name).suffix}"
            k += 1
        dst.write_bytes(data)
        saved.append(dst)
    if not saved:
        raise HTTPException(status_code=400, detail="Ни один файл не сохранён")
    return JSONResponse({"job_id": _start_job(job, saved)})


@app.post("/api/scan/folder")
def scan_folder(body: dict):
    path = str(body.get("path", "")).strip()
    if not path:
        raise HTTPException(status_code=400, detail="Не указан путь к папке")
    folder = Path(path).expanduser()
    if not folder.is_dir():
        raise HTTPException(status_code=400, detail=f"Папка не найдена: {path}")
    opts = _parse_options(json.dumps(body.get("options", {})))
    job = _new_job(label=str(folder), source_type="folder", options=opts)
    paths = collect_image_paths(folder)
    if not paths:
        raise HTTPException(status_code=400, detail="В папке нет изображений")
    _start_job(job, paths)
    return {"job_id": job["id"], "images": len(paths)}


@app.post("/api/scan/crawl")
def scan_crawl(body: dict):
    engines = body.get("engines") or ["baidu", "so360"]
    if not isinstance(engines, list):
        raise HTTPException(status_code=400, detail="engines: ожидался список")
    engines = [e for e in engines if e in ENGINE_NAMES]
    if not engines:
        raise HTTPException(status_code=400, detail="Не выбрана ни одна поисковая система")

    preset = str(body.get("preset", "") or "")
    keywords: list[str] = []
    if preset:
        if preset not in PRESETS:
            raise HTTPException(status_code=400, detail=f"Неизвестный пресет: {preset}")
        keywords = list(PRESETS[preset]["keywords"])
    custom = str(body.get("keyword", "") or "").strip()
    if custom:
        keywords = [custom]
    if not keywords:
        raise HTTPException(status_code=400, detail="Укажите ключевое слово или пресет")

    max_num = int(body.get("max_num", 30))
    max_num = max(5, min(200, max_num))
    opts = _parse_options(json.dumps(body.get("options", {})))
    label = f"Краулер: {custom or PRESETS.get(preset, {}).get('label', preset)}"
    job = _new_job(label=label, source_type="crawl", options=opts)
    job["progress"]["total"] = len(keywords)
    crawl_params = {"keyword_list": keywords, "engines": engines, "max_num": max_num}
    _start_job(job, [], crawl_params)
    return {"job_id": job["id"], "keywords": keywords, "max_num": max_num}


@app.get("/api/jobs")
def jobs_list():
    ids = {p.parent.name for p in JOBS_DIR.glob("*/job.json")}
    out = []
    for jid in sorted(ids, reverse=True):
        with LOCK:
            job = JOBS.get(jid)
        if job is None:
            job = _load_job_from_disk(jid)
        if job:
            out.append(
                {
                    "id": job["id"],
                    "label": job.get("label", ""),
                    "source_type": job.get("source_type", ""),
                    "status": job.get("status"),
                    "created_at": job.get("created_at"),
                    "stats": job.get("stats", {}),
                }
            )
    return out


@app.get("/api/jobs/{job_id}")
def job_detail(job_id: str):
    return _get_job(job_id)


@app.delete("/api/jobs/{job_id}")
def job_delete(job_id: str):
    with LOCK:
        JOBS.pop(job_id, None)
    d = JOBS_DIR / job_id
    if d.is_dir():
        shutil.rmtree(d, ignore_errors=True)
        return {"deleted": job_id}
    raise HTTPException(status_code=404, detail="Джоба не найдена")


@app.get("/api/jobs/{job_id}/report")
def job_report(job_id: str, fmt: str = "json"):
    job = _get_job(job_id)
    if job.get("status") != "done":
        raise HTTPException(status_code=409, detail="Сканирование ещё не завершено")
    names = {
        "txt": ("keylist.txt", "text/plain; charset=utf-8"),
        "seeds": ("seedlist.txt", "text/plain; charset=utf-8"),
        "json": ("scan_report.json", "application/json"),
        "csv": ("scan_report.csv", "text/csv; charset=utf-8"),
    }
    if fmt not in names:
        raise HTTPException(status_code=400, detail="fmt: txt | seeds | json | csv")
    fname, media = names[fmt]
    p = _safe_file(job_id, "", fname)
    return FileResponse(p, media_type=media, filename=fname)


@app.get("/api/jobs/{job_id}/images/{name}")
def job_image(job_id: str, name: str):
    return FileResponse(_safe_file(job_id, "images", name))


@app.get("/api/jobs/{job_id}/annotated/{name}")
def job_annotated(job_id: str, name: str):
    return FileResponse(_safe_file(job_id, "annotated", name))


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=3031, log_level="warning", access_log=False)
