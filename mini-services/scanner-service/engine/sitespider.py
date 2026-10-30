#!/usr/bin/env python3
"""
MrRobotQR 2.0 — парсер сайтов: скачиваем изображения со страницы и отправляем
их в общий скан-конвейер.

Логика:
  1. Загружаем HTML страницы напрямую (requests).
  2. Если сайт мёртв/недоступен или пользователь попросил архив — берём ближайший
     снапшот из Wayback Machine (archive.org/wayback/available).
  3. Извлекаем URL картинок: <img src/data-src/srcset>, <source srcset>,
     og:image, link rel=image_src + regex-фолбэк по сырому HTML.
  4. Скачивание — общий конвейер crawler._download_images (валидация, дедуп).

Для архивных страниц ссылки на картинки web.archive.org отдаёт сам — их
качаем как есть; прямые ссылки на оригинал оставляем без перезаписи.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import quote, urljoin, urlparse

import requests

from .crawler import (
    _ANTIBOT_NOTE,  # noqa: F401 — переиспользуем текст подсказки
    _HEADERS,
    _download_images,
    _load_seen_hashes,
)
from .textscan import page_visible_text

HTTP_TIMEOUT = 25
MAX_HTML = 3 * 1024 * 1024          # 3 МБ HTML достаточно
MAX_URLS = 400

_IMG_EXT_RE = re.compile(
    r"https?://[^\s\"'<>\\]+?\.(?:jpe?g|png|gif|webp|bmp)(?:\?[^\s\"'<>\\]*)?",
    re.I,
)


def _is_fetchable_url(url: str) -> bool:
    """Базовая защита: только http(s) на публичные хосты."""
    try:
        p = urlparse(url)
    except ValueError:
        return False
    if p.scheme not in ("http", "https") or not p.netloc:
        return False
    host = (p.hostname or "").lower()
    if not host or host == "localhost" or host.endswith(".local"):
        return False
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        octets = [int(x) for x in host.split(".")]
        if octets[0] in (10, 127) or octets[0] == 192 and octets[1] == 168 \
                or octets[0] == 172 and 16 <= octets[1] <= 31 \
                or octets[0] == 169 and octets[1] == 254 \
                or octets[0] == 0:
            return False
    return True


def _normalize_target(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "https://" + url
    return url


def wayback_latest(url: str) -> tuple[str, str]:
    """Ближайший снапшот Wayback: (snapshot_url, timestamp YYYYMMDDhhmmss).

    Важно: archive.org не принимает полностью закодированный параметр url
    (возвращает пустой archived_snapshots), поэтому : и / оставляем как есть.
    """
    q = quote(url, safe=":/?&=%")
    r = requests.get(
        f"https://archive.org/wayback/available?url={q}",
        headers=_HEADERS,
        timeout=HTTP_TIMEOUT,
    )
    r.raise_for_status()
    snap = ((r.json() or {}).get("archived_snapshots") or {}).get("closest") or {}
    if not snap.get("available") or not snap.get("url"):
        raise ValueError("веб-архив не имеет сохранённых копий этой страницы")
    return snap["url"], str(snap.get("timestamp", ""))


def extract_image_urls(html: str, base_url: str) -> list[str]:
    """Собирает URL картинок из HTML и нормализует относительно base_url."""
    urls: list[str] = []
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(["img", "source"]):
            for attr in ("src", "data-src", "data-original", "data-lazy-src"):
                v = tag.get(attr)
                if v and not v.strip().startswith("data:"):
                    urls.append(v.strip())
            srcset = tag.get("srcset") or tag.get("data-srcset") or ""
            first = srcset.split(",")[0].strip().split(" ")[0]
            if first and not first.startswith("data:"):
                urls.append(first)
        for tag in soup.find_all("meta", attrs={"property": "og:image"}):
            v = tag.get("content")
            if v:
                urls.append(v.strip())
        for tag in soup.find_all("link", attrs={"rel": "image_src"}):
            v = tag.get("href")
            if v:
                urls.append(v.strip())
    except Exception:  # noqa: BLE001 — BS4 не установлен/кривой HTML: regex-фолбэк
        pass

    urls += _IMG_EXT_RE.findall(html)

    out: list[str] = []
    seen: set[str] = set()
    for u in urls:
        try:
            full = urljoin(base_url, u)
        except ValueError:
            continue
        if full.startswith("data:") or full.lower().endswith(".svg"):
            continue
        if not _is_fetchable_url(full):
            continue
        if full not in seen:
            seen.add(full)
            out.append(full)
    return out[:MAX_URLS]


def parse_site(target_dir, url: str, max_num: int, archive: str = "auto") -> dict:
    """Скачивает изображения со страницы (или её снапшота в веб-архиве).

    archive: auto (прямая, при неудаче архив) | yes (только архив) | no (прямая).
    Возвращает формат как у crawl_images — совместим с UI джобы:
      {"keywords": {url: {"engines": {"site": {...}}, "total": N}}, "total": N}
    """
    from pathlib import Path

    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    info: dict = {"count": 0, "error": None, "note": None}
    result: dict = {"keywords": {}, "total": 0}

    target = _normalize_target(url)
    if not _is_fetchable_url(target):
        info["error"] = "некорректный URL (нужен публичный http/https-адрес)"
        result["keywords"][target] = {"engines": {"site": info}, "total": 0}
        return result

    page_url = target
    note: str | None = None
    html: str | None = None

    if archive in ("auto", "no"):
        try:
            r = requests.get(target, headers=_HEADERS, timeout=HTTP_TIMEOUT, stream=True)
            if r.status_code == 200:
                html = r.text[:MAX_HTML]
            else:
                info_r = f"сайт ответил HTTP {r.status_code}"
                if archive == "auto":
                    note = info_r + " → пробую веб-архив"
        except requests.RequestException as e:
            if archive == "auto":
                note = f"сайт недоступен ({type(e).__name__}) → пробую веб-архив"

    if html is None and archive in ("auto", "yes"):
        try:
            snap_url, ts = wayback_latest(target)
            r = requests.get(snap_url, headers=_HEADERS, timeout=HTTP_TIMEOUT)
            r.raise_for_status()
            html = r.text[:MAX_HTML]
            page_url = snap_url
            ts_fmt = f"{ts[6:8]}.{ts[4:6]}.{ts[0:4]}" if len(ts) >= 8 else ""
            snap_note = (
                f"использован снапшот веб-архива от {ts_fmt}" if ts_fmt
                else "использован снапшот веб-архива"
            )
            note = f"{note}; {snap_note}" if note else snap_note
        except ValueError as e:
            info["error"] = str(e) if html is None else info["error"]
        except requests.RequestException as e:
            if html is None:
                info["error"] = f"веб-архив недоступен: {type(e).__name__}: {str(e)[:120]}"

    if html is None:
        if not info["error"]:
            info["error"] = "не удалось загрузить страницу"
        result["keywords"][target] = {"engines": {"site": info}, "total": 0}
        return result

    urls = extract_image_urls(html, page_url)
    if not urls:
        info["error"] = "на странице не найдено изображений (возможно, они подгружаются скриптами)"
        result["keywords"][target] = {"engines": {"site": info}, "total": 0}
        return result

    seen = _load_seen_hashes(target_dir)
    saved, blocked = _download_images(urls, target_dir, "site_k00", max_num, seen)
    info["count"] = saved
    info["note"] = note
    if saved == 0:
        if blocked >= 2:
            info["error"] = "хост с картинками отдаёт 403/429 — блокировка IP дата-центра"
        else:
            info["error"] = (
                f"найдено {len(urls)} ссылок на изображения, но ни одна не скачалась "
                "(мёртвые хосты, неподдерживаемый формат или дубликаты)"
            )
    result["keywords"][target] = {"engines": {"site": info}, "total": saved}
    result["total"] = saved
    # видимый текст страницы — источник строковых значений для сканера
    try:
        result["page_text"] = page_visible_text(html)
        result["page_url"] = page_url
    except Exception:  # noqa: BLE001
        pass
    return result
