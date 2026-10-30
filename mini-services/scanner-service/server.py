#!/usr/bin/env python3
"""
WebCryptoScan — веб-сервис сканера (mini service, порт 3031).

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
import os
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
from engine.detectors import analyze_bytes, analyze_text, get_bip39
from engine.addresses import attach_addresses
from engine.globalsearch import (
    DORK_ENGINE_LABELS,
    DORK_PRESETS,
    GITHUB_PRESETS,
    get_domain_state,
    reset_domain_state,
    run_global,
)
from engine.reports import write_reports
from engine.sitespider import parse_site
from engine.textscan import (
    boxes_for_values,
    collect_document_paths,
    compact_lines_text,
    exif_text_from_path,
    file_text_chunks,
    looks_like_image,
    ocr_base58_repair,
    ocr_image_lines,
    ocr_normalize,
    page_visible_text,
    pdf_rasterize,
)
from PIL import Image
import cv2
import numpy as np

BASE_DIR = Path(__file__).resolve().parent
JOBS_DIR = BASE_DIR / "jobs"
JOBS_DIR.mkdir(exist_ok=True)

VERSION = "2.2.0"

app = FastAPI(title="WebCryptoScan scanner service", version=VERSION)
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
    "detect_seedqr": True,
    "detect_electrum": True,
    "detect_addresses": True,
    "ocr_fallback": True,    # OCR обычных фото (Tesseract), когда QR не найден
    "scan_strings": True,    # строковые значения: EXIF, текстовые файлы, строки, страницы
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
        "ocr_images": 0,
        "text_files": 0,
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

def _render_preview(job_id: str, image_path: Path, boxes: list[list[int]], tags: list[str]) -> str:
    """Рисует рамки (QR или OCR-строки) на уменьшенной копии; возвращает имя файла превью."""
    img = cv2.imdecode(np.fromfile(str(image_path), dtype=np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        img = cv2.cvtColor(np.array(open_image(str(image_path))), cv2.COLOR_RGB2BGR)
    h, w = img.shape[:2]
    thick = max(2, min(h, w) // 300)
    for i, bbox in enumerate(boxes):
        x, y, bw, bh = bbox
        p1 = (max(0, x - 3), max(0, y - 3))
        p2 = (min(w - 1, x + bw + 3), min(h - 1, y + bh + 3))
        cv2.rectangle(img, p1, p2, (52, 211, 153), thick)  # emerald
        label = f"{tags[i]}{i + 1}" if i < len(tags) else "QR"
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


def _annotate(job_id: str, image_path: Path, results: list) -> str:
    """Превью с рамками найденных QR-кодов."""
    return _render_preview(job_id, image_path, [r.bbox for r in results], ["QR"])


def _process_image(job: dict, image_path: Path) -> None:
    options = job["options"]
    try:
        img = open_image(str(image_path))
    except Exception as e:  # noqa: BLE001
        # не изображение? пробуем как источник строк (если включён scan_strings)
        if options.get("scan_strings", True) and not looks_like_image(image_path.name):
            _process_text_file(job, image_path)
            return
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
    preview_made = False
    for qi, r in enumerate(results):
        detected = analyze_text(r.data, options, bip39)
        if r.raw:
            detected += analyze_bytes(r.raw, options, bip39)
        for f in detected:
            f.update(
                image=image_path.name,
                qr_index=qi,
                engine=r.engine,
                variant=r.variant,
                bbox=r.bbox,
                source="qr",
            )
            findings.append(f)

    # --- EXIF-метаданные: описание/комментарии тоже могут прятать секреты ---
    if options.get("scan_strings", True):
        try:
            exif_text = exif_text_from_path(str(image_path))
        except Exception:  # noqa: BLE001
            exif_text = ""
        if exif_text.strip():
            for f in analyze_text(exif_text, options, bip39):
                f.update(
                    image=image_path.name,
                    qr_index=0,
                    engine="text",
                    variant="exif",
                    bbox=[0, 0, 0, 0],
                    source="exif",
                    source_detail="EXIF-метаданные изображения",
                )
                findings.append(f)

    # --- OCR обычных фото: QR не найден -> ищем текст на картинке ---
    if options.get("ocr_fallback", True) and not results:
        try:
            ocr_lines = ocr_image_lines(img)
        except Exception:  # noqa: BLE001
            ocr_lines = []
        if ocr_lines:
            job["stats"]["ocr_images"] += 1
            # нормализация под детекторы + вариант со склеенными строками
            # (tesseract рвёт длинные ключи пробелами, пишет Ox вместо 0x и é вместо e)
            ocr_text = ocr_normalize("\n".join(ln["text"] for ln in ocr_lines))
            ocr_text = ocr_text + "\n" + compact_lines_text(ocr_text)
            ocr_findings = analyze_text(ocr_text, options, bip39)
            # восстановление base58-токенов после OCR (лишний/битый символ):
            # WIF-ключи и адреса BTC/LTC/DOGE/DASH/TRX с проверкой Base58Check
            seen_vals = {f.get("value") for f in ocr_findings}
            for f in ocr_base58_repair(ocr_text):
                if f["value"] not in seen_vals:
                    ocr_findings.append(f)
            if ocr_findings:
                boxes = boxes_for_values([f["value"] for f in ocr_findings], ocr_lines)
                draw: list[list[int]] = []
                for f in ocr_findings:
                    bb = boxes.get(f["value"])
                    if bb:
                        f["bbox"] = bb
                        draw.append(bb)
                    f.update(
                        image=image_path.name,
                        qr_index=0,
                        engine="ocr",
                        variant=f"psm{ocr_lines[0]['psm']}+psm11",
                        source="ocr",
                    )
                    f.setdefault("source_detail", "распознано Tesseract OCR (eng)")
                findings.extend(ocr_findings)
                if draw:
                    try:
                        _render_preview(job["id"], image_path, draw, ["OCR"])
                        preview_made = True
                    except Exception:
                        traceback.print_exc()

    if options.get("detect_addresses", True):
        # мультивалютность: вывод адресов для ключей и валидных сидов
        attach_addresses(findings)

    if results:
        job["stats"]["qr_codes"] += len(results)
        qr_images = job["stats"].setdefault("qr_images", [])
        qr_images.append(image_path.name)
        try:
            _annotate(job["id"], image_path, results)
            preview_made = True
        except Exception:
            traceback.print_exc()

    if findings and not preview_made:
        # превью нужно и без QR/OCR (например, только EXIF) — иначе галерея покажет битую картинку
        try:
            _render_preview(job["id"], image_path, [], [])
        except Exception:
            traceback.print_exc()

    for f in findings:
        t = f["type"]
        job["stats"]["by_type"][t] = job["stats"]["by_type"].get(t, 0) + 1
        if t.startswith(("bip39", "seedqr", "electrum")):
            if f.get("valid_checksum"):
                job["stats"]["valid_seeds"] += 1
            else:
                job["stats"]["invalid_seeds"] += 1
        fid = len(job["findings"]) + 1
        f["id"] = fid
        job["findings"].append(f)
    job["stats"]["findings"] += len(findings)
    job["stats"]["images"] += 1


def _process_text_file(job: dict, file_path: Path) -> None:
    """Строковые значения из не-изображений: txt/json/строки бинарников."""
    options = job["options"]
    try:
        chunks = file_text_chunks(file_path)
    except Exception as e:  # noqa: BLE001
        job["errors"].append({"image": file_path.name, "error": f"не удалось прочитать: {e}"})
        return
    if not chunks:
        return
    bip39 = get_bip39()
    findings = []
    for label, text in chunks:
        for f in analyze_text(text, options, bip39):
            f.update(
                image=file_path.name,
                qr_index=0,
                engine="text",
                variant=label,
                bbox=[0, 0, 0, 0],
                source="file",
                source_detail=f"файл: {file_path.name} ({label})",
            )
            findings.append(f)
    if options.get("detect_addresses", True):
        attach_addresses(findings)
    for f in findings:
        t = f["type"]
        job["stats"]["by_type"][t] = job["stats"]["by_type"].get(t, 0) + 1
        if t.startswith(("bip39", "seedqr", "electrum")):
            if f.get("valid_checksum"):
                job["stats"]["valid_seeds"] += 1
            else:
                job["stats"]["invalid_seeds"] += 1
        fid = len(job["findings"]) + 1
        f["id"] = fid
        job["findings"].append(f)
    job["stats"]["findings"] += len(findings)
    job["stats"]["text_files"] += 1
    job["stats"]["images"] += 0  # текстовые файлы не считаем изображениями


def _process_page_text(job: dict, url: str, text: str, detail: str) -> None:
    """Строковые значения из текста страницы (сайт, архив, PDF)."""
    if not text.strip():
        return
    findings = []
    for f in analyze_text(text, job["options"], get_bip39()):
        f.update(
            image=url,
            qr_index=0,
            engine="text",
            variant="html",
            bbox=[0, 0, 0, 0],
            source="page",
            source_detail=detail,
        )
        findings.append(f)
    if job["options"].get("detect_addresses", True):
        attach_addresses(findings)
    for f in findings:
        t = f["type"]
        job["stats"]["by_type"][t] = job["stats"]["by_type"].get(t, 0) + 1
        if t.startswith(("bip39", "seedqr", "electrum")):
            if f.get("valid_checksum"):
                job["stats"]["valid_seeds"] += 1
            else:
                job["stats"]["invalid_seeds"] += 1
        fid = len(job["findings"]) + 1
        f["id"] = fid
        job["findings"].append(f)
    job["stats"]["findings"] += len(findings)


def _worker(job_id: str, items: list[tuple[Path, str]], crawl_params: dict | None) -> None:
    """items — пары (путь, тип): 'image' | 'doc'. При crawl_params — сначала скачивание."""
    with LOCK:
        job = JOBS.get(job_id)
    try:
        if crawl_params is not None:
            job["status"] = "crawling"
            job["phase"] = "crawl"
            _save_job(job)
            if crawl_params.get("mode") == "site":
                params = {k: v for k, v in crawl_params.items() if k != "mode"}
                res = parse_site(JOBS_DIR / job_id / "images", **params)
            elif crawl_params.get("mode") == "global":
                def _prog(stage: str, done: int, total: int) -> None:
                    job["progress"] = {"total": max(1, total), "processed": done}
                    job["crawl_stage"] = stage
                    if done == 0 or done % 10 == 0 or done == total:
                        _save_job(job)

                gp = {k: v for k, v in crawl_params.items() if k != "mode"}
                gp["mode"] = str(crawl_params.get("global_mode", "archive"))
                res = run_global(JOBS_DIR / job_id, gp, progress=_prog)
            else:
                res = crawl_images(JOBS_DIR / job_id / "images", **crawl_params)
            job["crawl"] = res
            image_paths = collect_image_paths(JOBS_DIR / job_id / "images")
            if crawl_params.get("mode") == "global":
                # файлы из files/ — строковый анализ; подмножество pages/ — как страницы
                doc_paths = collect_document_paths(JOBS_DIR / job_id / "files") \
                    if job["options"].get("scan_strings", True) else []
                items = [(p, "image") for p in image_paths] + [(p, "doc") for p in doc_paths]
            else:
                items = [(p, "image") for p in image_paths]

            # текст страницы (сайт/архив) — тоже источник строковых значений
            if job["options"].get("scan_strings", True) and crawl_params.get("mode") == "site":
                page_text = (res.get("page_text") or "").strip()
                page_url = res.get("page_url") or res.get("label") or "страница"
                if page_text:
                    _process_page_text(job, page_url, page_text, "видимый текст страницы")

            # страницы глобального поиска: манифест pages/manifest.json
            if job["options"].get("scan_strings", True) and crawl_params.get("mode") == "global":
                mf = JOBS_DIR / job_id / "pages" / "manifest.json"
                if mf.is_file():
                    try:
                        entries = json.loads(mf.read_text(encoding="utf-8"))
                    except Exception:  # noqa: BLE001
                        entries = []
                    for e in entries[:200]:
                        pf = JOBS_DIR / job_id / "pages" / e.get("file", "")
                        if not pf.is_file():
                            continue
                        try:
                            text = pf.read_text(encoding="utf-8", errors="replace")
                        except OSError:
                            continue
                        kind = e.get("kind", "html")
                        detail = ("PDF-документ: " if kind == "pdf" else "видимый текст страницы: ") + e.get("url", "")
                        _process_page_text(job, e.get("url", "страница"), text, detail)

        job["status"] = "running"
        job["phase"] = "scan"
        job["progress"]["total"] = len(items)
        job["progress"]["processed"] = 0
        _save_job(job)

        for i, (p, kind) in enumerate(items):
            if kind == "image":
                _process_image(job, p)
            else:
                _process_text_file(job, p)
            job["progress"]["processed"] = i + 1
            if i % 10 == 0 or i == len(items) - 1:
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


def _start_job(job: dict, items: list[tuple[Path, str]] | list[Path], crawl_params: dict | None = None) -> str:
    with LOCK:
        JOBS[job["id"]] = job
    _save_job(job)
    norm: list[tuple[Path, str]] = [
        (p, "image") if not isinstance(p, tuple) else p for p in items
    ]
    threading.Thread(target=_worker, args=(job["id"], norm, crawl_params), daemon=True).start()
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
    ocr = {"available": False, "lang": None}
    try:
        import pytesseract

        ocr["available"] = True
        ocr["lang"] = pytesseract.get_languages() if hasattr(pytesseract, "get_languages") else None
    except Exception:
        pass
    return {"status": "ok", "version": VERSION, "engines": engines, "bip39_words": words, "ocr": ocr}


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
    items: list[tuple[Path, str]] = []
    pdf_pages = 0
    for p in saved:
        if looks_like_image(p.name):
            items.append((p, "image"))
            continue
        if p.suffix.lower() == ".pdf":
            # страницы PDF → JPEG → QR-сканер; сам pdf остаётся в строковом анализе
            for page in pdf_rasterize(p.read_bytes(), img_dir, f"{p.stem}_pdf"):
                items.append((page, "image"))
                pdf_pages += 1
        items.append((p, "doc"))
    return JSONResponse({"job_id": _start_job(job, items), "pdf_pages": pdf_pages})


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
    docs: list[Path] = []
    if opts.get("scan_strings", True):
        docs = collect_document_paths(folder)
    items: list[tuple[Path, str]] = [(p, "image") for p in paths] + [(p, "doc") for p in docs]
    # PDF из папки: страницы → JPEG → QR-сканер (до 20 файлов)
    img_dir = JOBS_DIR / job["id"] / "images"
    img_dir.mkdir(parents=True, exist_ok=True)
    pdf_pages = 0
    pdf_count = 0
    for pf in sorted(folder.rglob("*")):
        if not (pf.is_file() and pf.suffix.lower() == ".pdf"):
            continue
        pdf_count += 1
        if pdf_count > 20:
            break
        try:
            pages = pdf_rasterize(pf.read_bytes(), img_dir, f"{pf.stem}_pdf")
        except OSError:
            continue
        for page in pages:
            items.append((page, "image"))
            pdf_pages += 1
    if not items:
        raise HTTPException(status_code=400, detail="В папке нет изображений, PDF или текстовых файлов")
    _start_job(job, items)
    return {"job_id": job["id"], "images": len(paths), "documents": len(docs), "pdf_pages": pdf_pages}


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


@app.post("/api/scan/site")
def scan_site(body: dict):
    url = str(body.get("url", "") or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="Укажите адрес сайта")
    archive = str(body.get("archive", "auto") or "auto")
    if archive not in ("auto", "yes", "no"):
        raise HTTPException(status_code=400, detail="archive: auto | yes | no")
    max_num = int(body.get("max_num", 30))
    max_num = max(5, min(200, max_num))
    opts = _parse_options(json.dumps(body.get("options", {})))
    job = _new_job(label=f"Сайт: {url}", source_type="site", options=opts)
    job["progress"]["total"] = 1
    crawl_params = {"mode": "site", "url": url, "archive": archive, "max_num": max_num}
    _start_job(job, [], crawl_params)
    return {"job_id": job["id"], "url": url, "archive": archive, "max_num": max_num}


GLOBAL_MODES = ("archive", "dorks", "commoncrawl", "github")


@app.get("/api/global/presets")
def global_presets():
    """Пресеты dork-запросов и GitHub-поиска + метки движков для UI."""
    return {
        "dorks": DORK_PRESETS,
        "github": GITHUB_PRESETS,
        "dork_engines": DORK_ENGINE_LABELS,
    }


@app.get("/api/global/state")
def global_state_get(domain: str = ""):
    """Дельта-состояние домена: граница времени последнего прохода архива."""
    domain = domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Укажите домен")
    return {"domain": domain, "state": get_domain_state(domain)}


@app.delete("/api/global/state")
def global_state_reset(domain: str = ""):
    """Сброс дельты: следующий проход снова перечислит домен целиком."""
    domain = domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Укажите домен")
    return {"domain": domain, "reset": reset_domain_state(domain)}


@app.post("/api/scan/global")
def scan_global(body: dict):
    mode = str(body.get("mode", "") or "").strip()
    if mode not in GLOBAL_MODES:
        raise HTTPException(status_code=400, detail="mode: archive | dorks | commoncrawl | github")
    opts = _parse_options(json.dumps(body.get("options", {})))

    params: dict = {"mode": mode}
    if mode == "archive":
        domain = str(body.get("domain", "") or "").strip()
        if not domain:
            raise HTTPException(status_code=400, detail="Укажите домен для веб-архива")
        provider = str(body.get("provider", "auto") or "auto")
        if provider not in ("auto", "wayback", "arquivo"):
            raise HTTPException(status_code=400, detail="provider: auto | wayback | arquivo")
        delta = bool(body.get("delta", False))
        # run_global читает max_urls (не max_num) — иначе слайдер лимита не действует
        params.update(domain=domain, provider=provider, delta=delta,
                      max_urls=max(5, min(int(body.get("max_urls", 60)), 400)))
        label = f"Архивы: {domain}" + (" — дельта" if delta else "")
    elif mode == "dorks":
        presets = [p for p in (body.get("presets") or []) if p in DORK_PRESETS]
        custom = str(body.get("custom", "") or "").strip()
        engines = [e for e in (body.get("engines") or ["bing"]) if e in DORK_ENGINE_LABELS]
        if not presets and not custom:
            raise HTTPException(status_code=400, detail="Выберите пресет dork-запросов или введите свой")
        if not engines:
            raise HTTPException(status_code=400, detail="Не выбран ни один поисковый движок")
        params.update(presets=presets, custom=custom, engines=engines,
                      max_pages=int(body.get("max_pages", 10)),
                      max_files=int(body.get("max_files", 20)))
        label = f"Dork-поиск: {custom or ', '.join(DORK_PRESETS[p]['label'] for p in presets)}"
    elif mode == "commoncrawl":
        mask = str(body.get("mask", "") or "").strip()
        if not mask:
            raise HTTPException(status_code=400, detail="Укажите маску URL (например, example.com/*)")
        params.update(mask=mask, max_urls=max(5, min(int(body.get("max_urls", 60)), 400)))
        label = f"Common Crawl: {mask}"
    else:  # github
        presets = [p for p in (body.get("presets") or []) if p in GITHUB_PRESETS]
        custom = str(body.get("custom", "") or "").strip()
        token = str(body.get("token", "") or "").strip() or os.environ.get("GITHUB_TOKEN", "")
        if not presets and not custom:
            raise HTTPException(status_code=400, detail="Выберите пресет или введите свой запрос")
        if not token:
            raise HTTPException(status_code=400, detail="Укажите GitHub-токен (поиск кода требует авторизацию)")
        params.update(presets=presets, custom=custom, token=token,
                      max_files=int(body.get("max_files", 20)))
        label = f"GitHub: {custom or ', '.join(GITHUB_PRESETS[p]['label'] for p in presets)}"

    job = _new_job(label=label, source_type=f"global_{mode}", options=opts)
    job["progress"]["total"] = 0
    crawl_params = {"mode": "global", "global_mode": mode, **{k: v for k, v in params.items() if k != "mode"}}
    _start_job(job, [], crawl_params)
    return {"job_id": job["id"], "mode": mode, "label": label}


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
        "addresses": ("addresses.txt", "text/plain; charset=utf-8"),
        "json": ("scan_report.json", "application/json"),
        "csv": ("scan_report.csv", "text/csv; charset=utf-8"),
    }
    if fmt not in names:
        raise HTTPException(status_code=400, detail="fmt: txt | seeds | addresses | json | csv")
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
