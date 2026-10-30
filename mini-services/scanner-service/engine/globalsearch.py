#!/usr/bin/env python3
"""
WebCryptoScan — глобальный поиск: 4 источника URL + универсальный конвейер загрузки.

Источники (режимы):
  archive      — веб-архивы: CDX-перечисление домена целиком.
                 Провайдеры: web.archive.org (локальная машина) и arquivo.pt
                 (работает и из дата-центров, проверено).
  dorks        — dork-пресеты открытых каталогов через текстовые SERP.
                 Bing работает из дата-центров; Baidu и DuckDuckGo — локально.
  commoncrawl  — индекс Common Crawl по маске URL (index.commoncrawl.org).
  github       — поиск кода GitHub API (нужен токен; raw-файлы качаются без него).

Универсальный загрузчик раскладывает контент по типам:
  изображения -> images/ (дальше обычный QR+OCR конвейер);
  документы   -> files/  (строковые детекторы: WIF, сиды, адреса...);
  zip         -> распаковка с лимитами, содержимое раскладывается так же;
  pdf         -> текст pypdf + растеризация страниц в JPEG (страницы идут в QR-сканер);
  html        -> видимый текст страницы (pages/ + manifest).

Все источники возвращают честные статусы: блокировка одного не ломает остальные.
"""

from __future__ import annotations

import base64
import io
import json
import re
import threading
import zipfile
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, unquote, urljoin, urlparse

import requests

from .crawler import _HEADERS, _HTTP_TIMEOUT, _load_seen_hashes, _save_image
from .sitespider import _is_fetchable_url
from .textscan import page_visible_text, pdf_raster_bytes, pdf_text

# --- Константы --------------------------------------------------------------------

MAX_ITEM_BYTES = 25 * 1024 * 1024          # выше — не качаем
ZIP_MAX_ENTRIES = 100                       # максимум файлов из одного архива
ZIP_MAX_TOTAL = 80 * 1024 * 1024            # суммарный лимит распаковки
MAX_PAGES_MANIFEST = 200                    # страниц в джобе — не больше

DOC_EXTS = {
    ".txt", ".json", ".dat", ".wallet", ".key", ".keys", ".csv", ".log",
    ".xml", ".yaml", ".yml", ".conf", ".cfg", ".ini", ".env", ".md",
    ".bak", ".old", ".gpg", ".asc", ".pem", ".crt", ".sql", ".plist",
    ".properties", ".list", ".seed", ".seeds", ".phrase",
}
FILE_LINK_EXTS = DOC_EXTS | {".pdf", ".zip"}
HTML_MIMES = ("text/html", "application/xhtml")

_ARQUIVO_REPLAY = "https://arquivo.pt/noFrame/replay/{ts}id_/{url}"
_WAYBACK_REPLAY = "https://web.archive.org/web/{ts}id_/{url}"

# --- Приоритизация очереди URL ------------------------------------------------------
#
# Лимит «Максимум URL» легко съедают страницы-болтовня, а нам нужны кошельки.
# Поэтому очередь сортируется: URL с ключевыми словами (кошельки/сиды/бэкапы...)
# идут первыми, внутри одинакового ранга — картинки и документы, потом страницы.

PRIORITIZE_KEYWORDS = (
    "wallet", "seed", "mnemonic", "private", "backup", "recover", "passphrase",
    "keystore", "metamask", "electrum", "paperwallet", "paper-wallet", "keys",
    "wallet.dat", "privkey", "wif", "bip39", "bip38", "bitcoin", "btc",
    "ethereum", "monero", "xrp", "crypto", "secret", "coin",
)

_KIND_RANK = {"image": 0, "doc": 1, "page": 2}

# что из страниц рекурсии точно не нужно (остальное — страницы, картинки, документы)
_LINK_JUNK_EXTS = {".css", ".js", ".mjs", ".rss", ".atom", ".ico", ".woff", ".woff2",
                   ".ttf", ".otf", ".eot", ".dtd", ".xsd", ".ashx", ".axd"}


def _url_priority_score(url: str) -> int:
    """Сколько ключевых слов встретилось в URL (без учёта регистра, %XX раскрываются)."""
    low = unquote(url or "").lower()
    return sum(1 for kw in PRIORITIZE_KEYWORDS if kw in low)

_UA = _HEADERS["User-Agent"]

# --- Дельта-состояние доменов ---------------------------------------------------------
#
# Чтобы повторный проход по тому же домену не шёл по кругу, после успешного
# перечисления CDX запоминаем границу времени: самый старый снимок, который
# реально ушёл в загрузку. Следующий дельта-проход спрашивает у архива только
# снимки, сделанные ПОСЛЕ этой границы (параметр from= у CDX API).
# Никаких расписаний и автозапусков — только ручные запуски пользователя.

STATE_FILE = Path(__file__).resolve().parent.parent / "data" / "global_state.json"
_STATE_LOCK = threading.Lock()


def _domain_key(domain: str) -> str:
    """Нормализуем запись домена до ключа состояния: без схемы, слешей и '/*'."""
    dom = (domain or "").strip().lower()
    dom = re.sub(r"^[a-z][a-z0-9+.-]*://", "", dom)
    dom = dom.rstrip("/")
    if dom.endswith("/*"):
        dom = dom[:-2]
    return dom.strip()


def _load_state() -> dict:
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("domains"), dict):
            return data
    except Exception:  # noqa: BLE001 — файла нет или битый JSON: начинаем с пустого
        pass
    return {"domains": {}}


def _save_state(state: dict) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")
        tmp.replace(STATE_FILE)
    except OSError:
        pass


def get_domain_state(domain: str) -> dict | None:
    """Сохранённое дельта-состояние домена или None."""
    st = _load_state()["domains"].get(_domain_key(domain))
    return dict(st) if isinstance(st, dict) and st else None


def reset_domain_state(domain: str) -> bool:
    """Сброс дельты: следующий проход снова пойдёт по всему домену."""
    with _STATE_LOCK:
        state = _load_state()
        key = _domain_key(domain)
        if key in state["domains"]:
            del state["domains"][key]
            _save_state(state)
            return True
    return False


def _ts_plus_second(ts: str) -> str:
    """CDX from= включителен — сдвигаем границу на секунду, чтобы пограничный
    снимок не качался заново при каждом дельта-проходе."""
    s = str(ts)[:14]
    try:
        dt = datetime.strptime(s, "%Y%m%d%H%M%S") + timedelta(seconds=1)
        return dt.strftime("%Y%m%d%H%M%S")
    except ValueError:
        return str(ts)


def _record_domain_state(domain: str, *, provider: str, items: list[dict],
                         queued_ts: list[str], max_urls: int) -> dict:
    """Записывает границу дельты после успешного перечисления CDX.

    Граница — самый старый снимок из реально ушедших в загрузку; complete —
    уложились ли перечисленные снимки в лимит URL (иначе старые не охвачены).
    """
    with _STATE_LOCK:
        state = _load_state()
        boundary = ""
        if queued_ts:
            boundary = min(str(t)[:14] for t in queued_ts)
        elif items:
            boundary = max(str(i.get("ts", ""))[:14] for i in items if i.get("ts"))
        rec = {
            "last_ts": boundary,
            "next_from": _ts_plus_second(boundary) if boundary else "",
            "last_run": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "provider": provider,
            "last_count": len(items),
            "complete": len(items) <= max_urls,
        }
        if boundary:
            state["domains"][_domain_key(domain)] = rec
            _save_state(state)
        return rec


def _get(url: str, *, params: dict | None = None, headers: dict | None = None,
         timeout: tuple[float, float] = (12, _HTTP_TIMEOUT)) -> requests.Response:
    h = {"User-Agent": _UA, "Accept-Language": "en-US,en;q=0.9"}
    if headers:
        h.update(headers)
    return requests.get(url, params=params, headers=h, timeout=timeout)


# --- Пресеты dork-запросов ----------------------------------------------------------
#
# Каждый запрос — два варианта:
#   dork  — полный запрос с операторами (intitle:, filetype:) — работает на локальной
#           машине (DuckDuckGo, Baidu); Bing из дата-центров молча отбрасывает
#           операторы и отдаёт нерелевантную выдачу (проверено 31.10.2026);
#   plain — обычные ключевые слова — Bing и Marginalia из дата-центров исполняют честно.

DORK_PRESETS: dict[str, dict] = {
    "open_dirs": {
        "label": "Открытые каталоги (index of)",
        "queries": [
            {"dork": 'intitle:"index of" wallet.dat', "plain": '"wallet.dat" bitcoin backup download'},
            {"dork": 'intitle:"index of" seed.txt', "plain": '"seed.txt" bitcoin backup'},
            {"dork": 'intitle:"index of" "private keys" bitcoin', "plain": '"private keys" bitcoin txt'},
            {"dork": 'intitle:"index of" keys.txt', "plain": '"keys.txt" bitcoin'},
            {"dork": 'intitle:"index of" "paper wallet"', "plain": '"paper wallet" bitcoin pdf download'},
        ],
    },
    "seed_backups": {
        "label": "Сид-фразы в текстовых файлах",
        "queries": [
            {"dork": '"seed phrase" filetype:txt', "plain": '"seed phrase" backup text bitcoin'},
            {"dork": '"recovery phrase" filetype:txt bitcoin', "plain": '"recovery phrase" words bitcoin write'},
            {"dork": '"mnemonic phrase" filetype:txt', "plain": '"mnemonic phrase" wallet backup'},
            {"dork": '"bip39" "seed" filetype:txt', "plain": '"bip39" seed words backup'},
        ],
    },
    "bip38_wif": {
        "label": "BIP38 / WIF в текстах",
        "queries": [
            {"dork": '"6P" bip38 filetype:txt', "plain": 'bip38 "6P" password protected key'},
            {"dork": 'bip38 "private key" filetype:txt', "plain": 'bip38 "private key" example'},
            {"dork": '"private key" WIF filetype:txt', "plain": '"private key" WIF bitcoin export'},
            {"dork": '"5K" OR "L1" "private key" filetype:txt', "plain": '"L1" OR "5K" private key bitcoin'},
        ],
    },
    "wallet_files": {
        "label": "Файлы кошельков и бэкапы",
        "queries": [
            {"dork": '"wallet.dat" filetype:dat', "plain": '"wallet.dat" bitcoin core dat file'},
            {"dork": 'intitle:"index of" electrum "default_wallet"', "plain": 'electrum "default_wallet" backup file'},
            {"dork": '"metamask" "vault" filetype:json', "plain": 'metamask vault json decrypt backup'},
            {"dork": '"keystore" filetype:json ethereum', "plain": 'keystore json ethereum utc file'},
        ],
    },
}

GITHUB_PRESETS: dict[str, dict] = {
    "wallet_files": {
        "label": "Кошельки в репозиториях",
        "queries": [
            "filename:wallet.dat",
            "filename:seed.txt",
            "filename:default_wallet",
        ],
    },
    "known_seeds": {
        "label": "Известные тестовые сиды",
        "queries": [
            '"abandon abandon abandon abandon abandon abandon abandon abandon"',
            '"candy maple cake sugar pudding cream honey"',
        ],
    },
    "bip39_json": {
        "label": "BIP39 / мнемоники в коде",
        "queries": [
            '"bip39" "mnemonic" filename:.json',
            '"recovery phrase" filename:.env',
        ],
    },
}

DORK_ENGINE_LABELS = {
    "bing": "Bing (из дата-центров, ключевые слова)",
    "marginalia": "Marginalia (старый веб, из дата-центров)",
    "baidu": "Baidu (локально, полные dork)",
    "duckduckgo": "DuckDuckGo (локально, полные dork)",
}


# --- Разбор типа контента ------------------------------------------------------------

def _url_ext(url: str) -> str:
    try:
        path = urlparse(url).path
    except ValueError:
        return ""
    m = re.search(r"\.([A-Za-z0-9]{1,6})$", path)
    return f".{m.group(1).lower()}" if m else ""


def split_kind(url: str, mime: str) -> str:
    """'image' | 'page' | 'doc' | 'skip' — по mime, затем по расширению."""
    mime = (mime or "").split(";")[0].strip().lower()
    ext = _url_ext(url)
    if mime.startswith("image/"):
        return "image"
    if mime in HTML_MIMES:
        return "page"
    if mime == "application/pdf" or ext == ".pdf":
        return "doc"
    if mime in ("application/zip", "application/x-zip-compressed", "application/x-zip",
                "application/gzip", "application/x-gzip") or ext in (".zip", ".gz"):
        return "doc"
    if mime.startswith("text/") or mime in ("application/json", "application/xml",
                                            "application/javascript", "application/x-yaml"):
        return "doc"
    if ext in FILE_LINK_EXTS:
        return "doc"
    if ext in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tif", ".tiff"}:
        return "image"
    if not mime and not ext:
        return "page"  # без подсказок — пробуем как страницу
    return "skip"


def _extract_page_links(html: str, base_url: str, limit: int = 20) -> list[str]:
    """Ссылки со страницы того же домена — материал для рекурсии.

    Остаётся то, что конвейер умеет переварить (картинки, документы, другие
    страницы); стили, скрипты, внешние домены и мусор отфильтровываются.
    """
    try:
        base_host = urlparse(base_url).netloc.lower().removeprefix("www.")
    except ValueError:
        return []
    if not base_host:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for href in re.findall(r'''href=["']([^"'\s>]+)["']''', html, re.I):
        href = unquote(href.strip())
        if not href or href.startswith(("javascript:", "mailto:", "data:", "tel:", "#")):
            continue
        try:
            full = urljoin(base_url, href)
        except ValueError:
            continue
        if not full.startswith(("http://", "https://")):
            continue
        full = full.split("#", 1)[0]
        if not full or full in seen:
            continue
        try:
            host = urlparse(full).netloc.lower().removeprefix("www.")
        except ValueError:
            continue
        if host != base_host or _url_ext(full) in _LINK_JUNK_EXTS:
            continue
        seen.add(full)
        out.append(full)
        if len(out) >= limit:
            break
    return out


# --- Универсальная загрузка -----------------------------------------------------------

class _Store:
    """Приёмник контента одной джобы: images/, files/, pages/ + манифест."""

    def __init__(self, job_dir: Path, prefix: str, seen_images: set[str]):
        self.images_dir = job_dir / "images"
        self.files_dir = job_dir / "files"
        self.pages_dir = job_dir / "pages"
        for d in (self.images_dir, self.files_dir, self.pages_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.prefix = prefix
        self.seen_images = seen_images
        self.doc_hashes: set[str] = set()
        self.pages: list[dict] = []          # [{"url", "kind", "file"}]
        self.counters = {"images": 0, "docs": 0, "pages": 0, "skipped": 0, "blocked": 0}
        self.n = 0
        self.saved_urls: set[str] = set()

    def _free_name(self, base: str, ext: str) -> str:
        k = 0
        name = f"{base}{ext}"
        while (self.files_dir / name).exists() or (self.images_dir / name).exists():
            k += 1
            name = f"{base}_{k}{ext}"
        return name

    def add_image(self, data: bytes, url: str) -> bool:
        import hashlib

        h = hashlib.md5(data).hexdigest()
        if h in self.seen_images:
            self.counters["skipped"] += 1
            return False
        self.n += 1
        name = f"{self.prefix}_n{self.n:03d}_{h[:8]}"
        if _save_image(data, self.images_dir, name):
            self.seen_images.add(h)
            self.counters["images"] += 1
            self.saved_urls.add(url)
            return True
        self.counters["skipped"] += 1
        return False

    def add_doc(self, data: bytes, url: str) -> bool:
        import hashlib

        h = hashlib.md5(data).hexdigest()
        if h in self.doc_hashes:
            self.counters["skipped"] += 1
            return False
        self.doc_hashes.add(h)
        ext = _url_ext(url) or ".bin"
        if ext not in DOC_EXTS:
            ext = ".txt" if ext == ".dat" else (ext if ext in (".pdf", ".zip", ".gz") else ".bin")
        self.n += 1
        base = re.sub(r"[^0-9A-Za-z._-]+", "_", Path(urlparse(url).path).stem)[:60] or "doc"
        name = f"{self.prefix}_n{self.n:03d}_{base}"
        (self.files_dir / self._free_name(name, ext)).write_bytes(data)
        self.counters["docs"] += 1
        self.saved_urls.add(url)
        return True

    def add_page(self, text: str, url: str, kind: str = "html") -> bool:
        if len(self.pages) >= MAX_PAGES_MANIFEST:
            return False
        self.n += 1
        fname = f"page_{self.n:03d}.txt"
        (self.pages_dir / fname).write_text(text, encoding="utf-8")
        self.pages.append({"url": url, "kind": kind, "file": fname})
        self.counters["pages"] += 1
        self.saved_urls.add(url)
        return True

    def write_manifest(self, job_dir: Path) -> None:
        import json

        (job_dir / "pages" / "manifest.json").write_text(
            json.dumps(self.pages, ensure_ascii=False, indent=1), encoding="utf-8")


def _route_bytes(data: bytes, mime: str, url: str, store: _Store, depth: int = 0) -> str:
    """Раскладывает скачанные байты по типам. Возвращает 'image'|'doc'|'page'|'skip'."""
    kind = split_kind(url, mime)
    if kind == "skip" and mime:
        kind = split_kind(url, "")  # mime экзотичный — смотрим на расширение

    if kind == "image":
        return "image" if store.add_image(data, url) else "skip"

    if kind == "page":
        text = page_visible_text(data.decode("utf-8", errors="replace")[:3 * 1024 * 1024])
        return "page" if text and store.add_page(text, url) else "skip"

    if kind == "doc":
        ext = _url_ext(url)
        ct = (mime or "").split(";")[0].strip().lower()
        if ct == "application/pdf" or ext == ".pdf":
            saved: str = "skip"
            text = pdf_text(data)
            if text and store.add_page(text, url, kind="pdf"):
                saved = "page"
            # растеризация страниц PDF → JPEG: страницы уходят в QR-конвейер
            for i, page_bytes in enumerate(pdf_raster_bytes(data), 1):
                if store.add_image(page_bytes, f"{url}#page={i}"):
                    saved = "image"
            return saved
        if ext == ".zip" or ct in ("application/zip", "application/x-zip-compressed"):
            if depth < 1:
                _unpack_zip(data, url, store, depth)
            return "doc" if url in store.saved_urls else "skip"
        return "doc" if store.add_doc(data, url) else "skip"

    store.counters["skipped"] += 1
    return "skip"


def _unpack_zip(data: bytes, url: str, store: _Store, depth: int) -> None:
    """Распаковывает zip с жёсткими лимитами (защита от zip-бомб и traversal)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:  # noqa: BLE001
        return
    total = 0
    n = 0
    for zi in zf.infolist():
        if zi.is_dir():
            continue
        total += zi.file_size
        n += 1
        if total > ZIP_MAX_TOTAL or n > ZIP_MAX_ENTRIES:
            break
        name = Path(zi.filename).name  # только basename — путь вверх запрещён
        if not name or name.startswith("."):
            continue
        try:
            b = zf.read(zi)
        except Exception:  # noqa: BLE001
            continue
        if len(b) > MAX_ITEM_BYTES:
            continue
        inner_url = f"{url}!{zi.filename}"
        if _url_ext(inner_url) in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}:
            store.add_image(b, inner_url)
        else:
            _route_bytes(b, "", inner_url, store, depth + 1)


def _fetch_item(url: str, store: _Store, *, timeout: tuple[float, float] = (12, 40),
                link_base: str = "", link_sink: list[str] | None = None,
                link_limit: int = 20) -> bool:
    """Скачивает один URL и раскладывает контент. True — что-то сохранили.

    link_base + link_sink: если контент — страница, из HTML достаются ссылки того
    же домена, что и link_base, и дописываются в link_sink (для рекурсии).
    """
    try:
        r = requests.get(url, headers=_HEADERS, timeout=timeout, stream=True)
        if r.status_code in (403, 429):
            store.counters["blocked"] += 1
            return False
        if r.status_code != 200:
            store.counters["skipped"] += 1
            return False
        data = r.content
        if not data or len(data) > MAX_ITEM_BYTES:
            store.counters["skipped"] += 1
            return False
        ct = r.headers.get("content-type", "")
        if link_sink is not None and link_base:
            kind = split_kind(url, ct)
            if kind == "skip" and ct:
                kind = split_kind(url, "")
            if kind == "page":
                try:
                    html = data.decode("utf-8", errors="replace")[:3 * 1024 * 1024]
                    link_sink.extend(_extract_page_links(html, link_base, link_limit))
                except Exception:  # noqa: BLE001 — битый HTML не роняет загрузку
                    pass
        return _route_bytes(data, ct, url, store) != "skip"
    except Exception:  # noqa: BLE001 — одна битая ссылка не роняет джобу
        store.counters["skipped"] += 1
        return False


def _fetch_with_recursion(items: list[dict], *, build_url: Callable[[dict], str],
                          depth: int, budget: int, store: _Store,
                          prog: Callable[[str, int, int], None], label: str) -> dict:
    """Качает очередь URL; найденные страницы отдают ссылки того же домена —
    они становятся следующим уровнем очереди (BFS до depth).

    items — [{"url": оригинал, "ts": момент снимка}]; build_url(it) -> URL скачивания
    (для архива это replay-ссылка на момент снимка, для живых источников — сам URL).
    budget — суммарный лимит рекурсивных загрузок по всем уровням.
    Возвращает {"depth", "found", "fetched"} для отчёта в UI.
    """
    stats = {"depth": depth, "found": 0, "fetched": 0}
    total = len(items)
    if depth <= 0:
        done = 0
        for it in items:
            _fetch_item(build_url(it), store)
            done += 1
            if done % 5 == 0 or done == total:
                prog(f"{label}: {done}/{total}", done, total)
        return stats

    seen: set[str] = {it["url"] for it in items}
    frontier: list[tuple[str, str]] = []   # (оригинальный URL, ts снимка)
    done = 0
    for it in items:
        sink: list[str] = []
        _fetch_item(build_url(it), store, link_base=it["url"], link_sink=sink)
        fresh = [l for l in sink if l not in seen]
        for l in fresh:
            seen.add(l)
        frontier.extend((l, str(it.get("ts", ""))) for l in fresh)
        stats["found"] += len(fresh)
        done += 1
        if done % 5 == 0 or done == total:
            prog(f"{label}: {done}/{total}", done, total)

    level = 1
    while level <= depth and frontier and budget > 0:
        plan = frontier[:budget]
        leftover = frontier[len(plan):]
        collect_more = level < depth
        nxt: list[tuple[str, str]] = []
        done = 0
        for base_url, ts in plan:
            sink: list[str] | None = [] if collect_more else None
            if _fetch_item(build_url({"url": base_url, "ts": ts}), store,
                           link_base=base_url if collect_more else None,
                           link_sink=sink):
                stats["fetched"] += 1
            if sink:
                fresh = [l for l in sink if l not in seen]
                for l in fresh:
                    seen.add(l)
                nxt.extend((l, ts) for l in fresh)
                stats["found"] += len(fresh)
            budget -= 1
            done += 1
            if done % 5 == 0 or done == len(plan):
                prog(f"{label} — рекурсия, уровень {level}: {done}/{len(plan)}", done, len(plan))
        frontier = (nxt + leftover) if collect_more else []
        level += 1
    return stats


# --- Режим archive: CDX-перечисление домена -------------------------------------------

def _cdx_wayback(domain: str, limit: int, from_ts: str = "") -> dict:
    params = {
        "url": domain,
        "output": "json",
        "fl": "original,timestamp,mimetype,statuscode",
        "collapse": "urlkey",
        "filter": "statuscode:200",
        "limit": str(limit),
    }
    if from_ts:
        params["from"] = str(from_ts)
    r = _get(
        "https://web.archive.org/cdx/search/cdx",
        params=params,
        timeout=(12, 45),
    )
    r.raise_for_status()
    rows = r.json()
    items: list[dict] = []
    if isinstance(rows, list) and rows:
        header = rows[0] if isinstance(rows[0], list) else ["original", "timestamp", "mimetype", "statuscode"]
        for row in rows[1:] if isinstance(rows[0], list) else rows:
            if not isinstance(row, (list, dict)):
                continue
            if isinstance(row, dict):
                row = [row.get(k, "") for k in ("original", "timestamp", "mimetype", "statuscode")]
            d = dict(zip([str(h).lower() for h in header], row))
            items.append({"url": d.get("original", ""), "ts": d.get("timestamp", ""),
                          "mime": d.get("mimetype", ""), "status": d.get("statuscode", "")})
    return {"provider": "wayback", "items": items}


def _cdx_arquivo(domain: str, limit: int, from_ts: str = "") -> dict:
    params = {"url": domain, "output": "json", "filter": "statuscode:200", "limit": str(limit)}
    if from_ts:
        params["from"] = str(from_ts)
    r = _get(
        "https://arquivo.pt/wayback/cdx",
        params=params,
        timeout=(12, 45),
    )
    r.raise_for_status()
    items: list[dict] = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        items.append({"url": d.get("original") or d.get("url", ""), "ts": d.get("timestamp", ""),
                      "mime": d.get("mimetype") or d.get("mime", ""), "status": d.get("status", "")})
    return {"provider": "arquivo", "items": items}


def cdx_domain(domain: str, limit: int, provider: str = "auto", from_ts: str = "") -> dict:
    """Перечисляет захваченные URL домена через CDX.

    Провайдеры: wayback, arquivo, auto. from_ts — граница дельты (YYYYMMDDhhmmss):
    возвращаются только снимки, сделанные после неё.
    """
    dom = domain.strip()
    dom = re.sub(r"^[a-z][a-z0-9+.-]*://", "", dom, flags=re.I).strip("/")
    if not dom or "/" not in dom and "*" not in dom:
        dom = f"{dom}/*" if dom else dom
    if not dom:
        return {"provider": None, "items": [], "error": "пустой домен"}

    order = [("wayback", _cdx_wayback), ("arquivo", _cdx_arquivo)]
    if provider == "wayback":
        order = order[:1]
    elif provider == "arquivo":
        order = order[1:]

    last_err = ""
    for name, fn in order:
        try:
            res = fn(dom, limit, from_ts)
            items = [i for i in res["items"] if i["url"] and str(i["status"]) == "200"]
            # дедуп по URL (оставляем самый свежий снимок)
            best: dict[str, dict] = {}
            for it in items:
                old = best.get(it["url"])
                if old is None or str(it["ts"]) > str(old["ts"]):
                    best[it["url"]] = it
            items = sorted(best.values(), key=lambda x: str(x["ts"]), reverse=True)
            if items:
                note = None
                if name == "arquivo" and len(items) < 5:
                    note = ("arquivo.pt глубоко индексирует португальский веб; для остальных "
                            "доменов в архиве могут быть только главные страницы. Полный "
                            "охват даёт провайдер wayback — на локальной машине.")
                return {"provider": name, "items": items[:limit], "error": None, "note": note}
            last_err = f"{name}: подходящих снимков не найдено"
        except requests.RequestException as e:
            last_err = f"{name}: {type(e).__name__}"
        except Exception as e:  # noqa: BLE001
            last_err = f"{name}: {type(e).__name__}: {str(e)[:120]}"
    return {"provider": None, "items": [], "error": last_err or "источники недоступны"}


def _replay_url(provider: str, it: dict) -> str:
    """Ссылка на оригинальные байты из архива (id_ — без тулбара архивов)."""
    if provider == "wayback":
        return _WAYBACK_REPLAY.format(ts=it["ts"], url=quote(it["url"], safe=":/?&=%"))
    return _ARQUIVO_REPLAY.format(ts=it["ts"], url=quote(it["url"], safe=":/?&=%"))


# --- Режим dorks: текстовые SERP --------------------------------------------------------

_BING_REDIR_RE = re.compile(r'u=a1([A-Za-z0-9_-]+)')
_ALGO_RE = re.compile(r'<li class="b_algo".*?</li>', re.S)
_HREF_RE = re.compile(r'<a[^>]+href="([^"]+)"', re.I)


def _decode_bing_href(href: str) -> str:
    href = href.replace("&amp;", "&")
    if "bing.com/ck/" not in href:
        return href
    m = _BING_REDIR_RE.search(href)
    if not m:
        return ""
    raw = m.group(1)
    raw += "=" * (-len(raw) % 4)
    try:
        return base64.urlsafe_b64decode(raw).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


def serp_bing(query: str, max_results: int = 20) -> dict:
    out: list[str] = []
    last_empty = False
    first = 1
    while len(out) < max_results and first <= 21:
        r = _get("https://www.bing.com/search",
                 params={"q": query, "count": "15", "first": str(first), "setlang": "en"},
                 timeout=(12, 25))
        if r.status_code != 200:
            break
        found = 0
        for block in _ALGO_RE.findall(r.text):
            for href in _HREF_RE.findall(block):
                real = _decode_bing_href(href)
                if real and real.startswith("http") and _is_fetchable_url(real):
                    out.append(real)
                    found += 1
                    break  # одна ссылка на результат
        if not found:
            # Bing чередует варианты ответа: иногда JS-оболочка без b_algo.
            # Если первая попытка пуста — один ретрай, потом сдаёмся.
            if first == 1 and not last_empty:
                last_empty = True
                continue
            break
        last_empty = False
        first += 15
    seen: set[str] = set()
    uniq = [u for u in out if not (u in seen or seen.add(u))]
    if not uniq:
        return {"urls": [], "error": "Bing: выдача пуста или анти-бот блокировка"}
    return {"urls": uniq[:max_results], "error": None}


_MARG_STOP = {"bitcoin", "file", "backup", "download", "example", "format", "txt", "json",
              "words", "phrase", "key", "keys", "private", "seed", "wallet", "core"}


def _marginalia_tokens(query: str) -> list[str]:
    """Marginalia стабильно отвечает только на одиночные токены (многословные висят,
    проверено). Выбираем 1-2 самых значимых: сначала токены с точкой (wallet.dat,
    seed.txt), затем первые не-стоп-слова."""
    raw = re.findall(r"[A-Za-z0-9_.-]{2,}", query)
    seen: list[str] = []
    for t in raw:
        if t.lower() not in seen:
            seen.append(t)
    dotted = [t for t in seen if "." in t]
    plain = [t for t in seen if "." not in t and t.lower() not in _MARG_STOP]
    out = dotted + plain
    return (out or seen)[:2]


def serp_marginalia(query: str, max_results: int = 20) -> dict:
    """Marginalia — независимый поисковик, хорошо индексирует старый/нестандартный веб.
    Открытый ключ 'public' работает из дата-центров, но жёстко троттлит повторные
    запросы (держит соединение до таймаута), поэтому — один запрос за вызов,
    самый значимый токен (с точкой типа wallet.dat, иначе первое ключевое слово)."""
    tokens = _marginalia_tokens(query)[:1]
    if not tokens:
        return {"urls": [], "error": "Marginalia: нечего искать в запросе"}
    try:
        r = _get("https://api.marginalia.nu/public/search/" + quote(tokens[0], safe=""),
                 timeout=(10, 20))
    except requests.RequestException as e:
        return {"urls": [], "error": f"Marginalia: {type(e).__name__} (лимит запросов публичного ключа)"}
    if r.status_code != 200:
        return {"urls": [], "error": f"Marginalia: HTTP {r.status_code}"}
    try:
        data = r.json()
    except Exception:  # noqa: BLE001
        return {"urls": [], "error": "Marginalia: некорректный JSON"}
    out: list[str] = []
    for it in data.get("results", []):
        u = (it.get("url") or "").strip()
        if u.startswith("http") and _is_fetchable_url(u):
            out.append(u)
        if len(out) >= max_results:
            break
    if not out:
        return {"urls": [], "error": "Marginalia: по запросу ничего не найдено"}
    return {"urls": out, "error": None}


def serp_duckduckgo(query: str, max_results: int = 20) -> dict:
    r = _get("https://html.duckduckgo.com/html/", params={"q": query}, timeout=(12, 25))
    if r.status_code != 200:
        return {"urls": [], "error": f"DuckDuckGo: HTTP {r.status_code} (анти-бот из дата-центра)"}
    out: list[str] = []
    for href in re.findall(r'class="result__a"[^>]*href="([^"]+)"', r.text):
        if "uddg=" in href:
            m = re.search(r"uddg=([^&]+)", href)
            if m:
                real = unquote(m.group(1))
                if real.startswith("http") and _is_fetchable_url(real):
                    out.append(real)
    if not out:
        return {"urls": [], "error": "DuckDuckGo: выдача пуста или анти-бот блокировка"}
    seen: set[str] = set()
    return {"urls": [u for u in out if not (u in seen or seen.add(u))][:max_results], "error": None}


def serp_baidu(query: str, max_results: int = 20) -> dict:
    s = requests.Session()
    s.headers.update(_HEADERS)
    try:
        s.get("https://www.baidu.com/", timeout=(10, 20))  # печенье BAIDUID
        r = s.get("https://www.baidu.com/s", params={"wd": query, "rn": "20"}, timeout=(12, 25))
    except requests.RequestException as e:
        return {"urls": [], "error": f"Baidu: {type(e).__name__}"}
    if r.status_code != 200 or "百度安全验证" in r.text or "wappass" in r.text:
        return {"urls": [], "error": f"Baidu: анти-бот блокировка (HTTP {r.status_code})"}
    out: list[str] = []
    for href in re.findall(r'<h3[^>]*>\s*<a[^>]+href="([^"]+)"', r.text):
        if href.startswith("http") and _is_fetchable_url(href):
            out.append(href)
    if not out:
        return {"urls": [], "error": "Baidu: выдача пуста"}
    return {"urls": out[:max_results], "error": None}


SERPS = {"bing": serp_bing, "duckduckgo": serp_duckduckgo, "baidu": serp_baidu,
         "marginalia": serp_marginalia}
# движки, которым операторы не по зубам из дата-центров (им отдаём plain-вариант запроса)
PLAIN_ONLY_ENGINES = {"bing", "marginalia"}


def file_links_from_html(html: str, base_url: str, limit: int = 12) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for href in re.findall(r'''href=["']([^"']+)["']''', html, re.I):
        path = href.split("?")[0].split("#")[0]
        if not re.search(r"\.(?:%s)$" % "|".join(e.strip(".") for e in FILE_LINK_EXTS), path, re.I):
            continue
        try:
            full = urljoin(base_url, href)
        except ValueError:
            continue
        if not full.startswith("http") or not _is_fetchable_url(full) or full in seen:
            continue
        seen.add(full)
        out.append(full)
        if len(out) >= limit:
            break
    return out


# --- Режим commoncrawl ------------------------------------------------------------------

def commoncrawl_list(mask: str, limit: int) -> dict:
    r = _get("https://index.commoncrawl.org/collinfo.json", timeout=(12, 30))
    r.raise_for_status()
    colls = r.json()
    if not colls:
        return {"index": None, "items": [], "error": "список индексов Common Crawl пуст"}
    latest = colls[0].get("id")
    r2 = _get(
        f"https://index.commoncrawl.org/{latest}-index",
        params={"url": mask, "output": "json", "limit": str(limit)},
        timeout=(15, 60),
    )
    if r2.status_code != 200:
        return {"index": latest, "items": [],
                "error": f"CDX-сервер Common Crawl ответил HTTP {r2.status_code}"}
    items: list[dict] = []
    for line in r2.text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        if str(d.get("status", "")) == "200":
            items.append({"url": d.get("url", ""), "ts": "", "mime": d.get("mime", ""), "status": "200"})
    return {"index": latest, "items": items[:limit], "error": None if items else "по маске ничего не найдено"}


# --- Режим github ------------------------------------------------------------------------

def github_search(query: str, token: str, max_items: int = 20) -> dict:
    if not token:
        return {"files": [], "error": "нужен GitHub-токен (поле на панели или переменная GITHUB_TOKEN)"}
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"token {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    r = _get("https://api.github.com/search/code",
             params={"q": query, "per_page": str(min(50, max_items))}, headers=headers,
             timeout=(12, 30))
    if r.status_code == 401:
        return {"files": [], "error": "GitHub-токен отклонён (401)"}
    if r.status_code == 403:
        return {"files": [], "error": "лимит запросов GitHub исчерпан (403)"}
    if r.status_code == 422:
        msg = ""
        try:
            msg = (r.json().get("message") or "")[:120]
        except Exception:  # noqa: BLE001
            pass
        return {"files": [], "error": f"запрос отклонён (422): {msg or 'проверьте синтаксис'}"}
    if r.status_code != 200:
        return {"files": [], "error": f"GitHub API: HTTP {r.status_code}"}
    files: list[dict] = []
    for it in r.json().get("items", [])[:max_items]:
        repo = it.get("repository", {}).get("full_name", "")
        path = it.get("path", "")
        if repo and path:
            raw = f"https://raw.githubusercontent.com/{repo}/HEAD/{quote(path)}"
            files.append({"repo": repo, "path": path, "raw": raw})
    return {"files": files, "error": None if files else "по запросу ничего не найдено"}


# --- Главная точка входа -------------------------------------------------------------------

def _load_doc_hashes(files_dir: Path) -> set[str]:
    import hashlib

    out: set[str] = set()
    if files_dir.exists():
        for p in files_dir.iterdir():
            if p.is_file():
                try:
                    out.add(hashlib.md5(p.read_bytes()).hexdigest())
                except OSError:
                    continue
    return out


def run_global(job_dir: Path, params: dict, progress=None) -> dict:
    """Глобальный поиск: перечисление URL источником -> универсальная загрузка.

    progress(stage, done, total) — колбэк для UI-прогресса.
    Возвращает структуру для job['crawl'].
    """
    job_dir = Path(job_dir)
    job_dir.mkdir(parents=True, exist_ok=True)
    mode = str(params.get("mode", "archive"))
    prefix = {"archive": "arx", "dorks": "drk", "commoncrawl": "cc", "github": "gh"}.get(mode, "gl")

    def prog(stage: str, done: int, total: int) -> None:
        if progress:
            try:
                progress(stage, done, total)
            except Exception:  # noqa: BLE001
                pass

    store = _Store(job_dir, prefix, _load_seen_hashes(job_dir / "images"))
    store.doc_hashes = _load_doc_hashes(job_dir / "files")
    result: dict = {"mode": mode, "sources": {}, "images": 0, "docs": 0, "pages": 0, "total": 0}

    if mode == "archive":
        domain = str(params.get("domain", "")).strip()
        provider = str(params.get("provider", "auto") or "auto")
        max_urls = max(5, min(int(params.get("max_urls", 60)), 400))
        delta = bool(params.get("delta"))
        prioritize = bool(params.get("prioritize", True))
        depth = max(0, min(int(params.get("depth", 0) or 0), 2))

        from_ts = ""
        prev: dict | None = None
        if delta:
            prev = get_domain_state(domain)
            if prev and prev.get("next_from"):
                from_ts = str(prev["next_from"])

        prog("Перечисление снимков веб-архива…", 0, 1)
        res = cdx_domain(domain, max_urls * 3, provider, from_ts=from_ts)
        items = res["items"]
        result["sources"]["cdx"] = {
            "count": len(items), "provider": res["provider"], "error": res["error"],
            "note": res.get("note") or (
                None if res["provider"] else
                "web.archive.org и arquivo.pt недоступны с этого сервера; на локальной машине обычно работает"),
        }
        if delta:
            result["sources"]["cdx"]["delta"] = {
                "enabled": True,
                "from_ts": from_ts or None,
                "prev_run": (prev or {}).get("last_run"),
                "prev_count": (prev or {}).get("last_count"),
            }
        if items:
            split: dict[str, list[dict]] = {"image": [], "page": [], "doc": []}
            for it in items:
                k = split_kind(it["url"], it["mime"])
                if k in ("image", "page", "doc"):
                    split[k].append(it)
            result["sources"]["cdx"]["images_found"] = len(split["image"])
            result["sources"]["cdx"]["pages_found"] = len(split["page"])
            result["sources"]["cdx"]["docs_found"] = len(split["doc"])
            combined = [(k, it) for k in ("image", "doc", "page") for it in split[k]]
            if prioritize:
                # URL с ключевыми словами — наверх, далее картинки/документы,
                # потом страницы; внутри ранга — свежие снимки первыми
                decorated = [(_url_priority_score(it["url"]), -_KIND_RANK[k],
                              str(it.get("ts", "")), n, k, it)
                             for n, (k, it) in enumerate(combined)]
                decorated.sort(key=lambda t: (t[0], t[1], t[2], t[3]), reverse=True)
                combined = [(t[4], t[5]) for t in decorated]
            queue = [it for _, it in combined][:max_urls]
            if prioritize:
                result["sources"]["cdx"]["prioritize"] = {
                    "enabled": True,
                    "keywords_hit": sum(1 for _, it in combined if _url_priority_score(it["url"]) > 0),
                    "queued_hit": sum(1 for it in queue if _url_priority_score(it["url"]) > 0),
                    "top": [it["url"] for it in queue[:4]],
                }
            # граница дельты пишется сразу после перечисления: загрузки могут
            # длиться долго, а перечисленный охват от этого не меняется
            if res["provider"]:
                result["sources"]["cdx"]["delta_state"] = _record_domain_state(
                    domain, provider=res["provider"], items=items,
                    queued_ts=[str(i.get("ts", "")) for i in queue if i.get("ts")],
                    max_urls=max_urls,
                )
            provider_name = res["provider"] or "arquivo"
            rec = _fetch_with_recursion(
                queue,
                build_url=lambda it, p=provider_name: _replay_url(p, it),
                depth=depth, budget=min(max_urls, 120),
                store=store, prog=prog, label="Загрузка из архива",
            )
            if depth > 0:
                result["sources"]["cdx"]["recursion"] = rec
        elif delta and from_ts and res["provider"]:
            result["sources"]["cdx"]["note"] = (
                "новых снимков с последнего прохода не найдено — домен уже охвачен"
            )

    elif mode == "dorks":
        engines = [e for e in (params.get("engines") or ["bing"]) if e in SERPS] or ["bing"]
        presets = params.get("presets") or []
        custom = str(params.get("custom", "") or "").strip()
        variants: list[dict] = []   # [{"dork": ..., "plain": ...}]
        for p in presets:
            variants += list(DORK_PRESETS.get(p, {}).get("queries", []))
        if custom:
            variants.append({"dork": custom, "plain": custom})
        variants = list({v.get("dork", v.get("plain")): v for v in variants}.values())[:12]
        max_pages = max(3, min(int(params.get("max_pages", 10)), 30))
        max_files = max(3, min(int(params.get("max_files", 20)), 60))

        # карта вариантов по движкам: Marginalia троттлит публичный ключ —
        # не более двух запросов на джобу (уникальные значимые токены пресетов)
        eng_variants: dict[str, list[dict]] = {}
        for eng in engines:
            if eng == "marginalia":
                toks: list[str] = []
                for v in variants:
                    toks += _marginalia_tokens(v.get("plain") or v.get("dork") or "")
                toks = list(dict.fromkeys(toks))[:2]
                eng_variants[eng] = [{"dork": t, "plain": t} for t in toks]
            else:
                eng_variants[eng] = variants
        total_q = sum(len(v) for v in eng_variants.values())
        done = 0
        for eng in engines:
            stats = {"count": 0, "error": None, "note": None, "urls_found": 0}
            if eng in PLAIN_ONLY_ENGINES:
                stats["note"] = "Bing/Marginalia из дата-центров отбрасывают операторы — использованы ключевые слова"
            urls: list[str] = []
            for v in eng_variants[eng]:
                q = v.get("plain") if eng in PLAIN_ONLY_ENGINES else v.get("dork")
                q = q or v.get("dork") or v.get("plain") or ""
                if not q:
                    continue
                try:
                    res = SERPS[eng](q, 15)
                except Exception as e:  # noqa: BLE001
                    res = {"urls": [], "error": f"{type(e).__name__}"}
                urls += res["urls"]
                if res["error"]:
                    stats["error"] = res["error"]
                done += 1
                prog(f"Поиск: {eng} — запрос {done}/{total_q}", done, total_q)
            urls = list(dict.fromkeys(urls))
            stats["urls_found"] = len(urls)
            pages_done = 0
            for u in urls:
                if pages_done >= max_pages:
                    break
                before = dict(store.counters)
                try:
                    r = requests.get(u, headers=_HEADERS, timeout=(12, 30), stream=True)
                    if r.status_code in (403, 429):
                        store.counters["blocked"] += 1
                        continue
                    if r.status_code != 200:
                        continue
                    data = r.content
                    if not data or len(data) > MAX_ITEM_BYTES:
                        continue
                    ct = r.headers.get("content-type", "")
                    kind = _route_bytes(data, ct, u, store)
                    if kind == "page" and store.counters["docs"] < max_files:
                        # из листингов каталогов тянем файлы
                        links = file_links_from_html(data.decode("utf-8", errors="replace")[:2_000_000], u)
                        for link in links:
                            if store.counters["docs"] >= max_files:
                                break
                            if link in store.saved_urls:
                                continue
                            _fetch_item(link, store)
                    pages_done += 1
                except Exception:  # noqa: BLE001
                    continue
                finally:
                    stats["count"] += sum(store.counters[k] - before[k] for k in ("images", "docs", "pages"))
                prog(f"Загрузка находок: {pages_done}/{max_pages}", pages_done, max_pages)
            result["sources"][eng] = stats

    elif mode == "commoncrawl":
        mask = str(params.get("mask", "")).strip()
        max_urls = max(5, min(int(params.get("max_urls", 60)), 400))
        prog("Запрос к индексу Common Crawl…", 0, 1)
        try:
            res = commoncrawl_list(mask, max_urls)
        except requests.RequestException as e:
            res = {"index": None, "items": [], "error": f"{type(e).__name__}: index.commoncrawl.org недоступен"}
        result["sources"]["commoncrawl"] = {
            "count": len(res["items"]), "index": res["index"], "error": res["error"],
            "note": None if res["items"] else "index.commoncrawl.org недоступен с этого сервера; на локальной машине обычно работает",
        }
        cc_depth = max(0, min(int(params.get("depth", 0) or 0), 2))
        rec = _fetch_with_recursion(
            [{"url": it["url"], "ts": ""} for it in res["items"]],
            build_url=lambda it: it["url"],
            depth=cc_depth, budget=min(max_urls, 120),
            store=store, prog=prog, label="Загрузка",
        )
        if cc_depth > 0:
            result["sources"]["commoncrawl"]["recursion"] = rec

    elif mode == "github":
        presets = params.get("presets") or []
        custom = str(params.get("custom", "") or "").strip()
        queries: list[str] = []
        for p in presets:
            queries += list(GITHUB_PRESETS.get(p, {}).get("queries", []))
        if custom:
            queries.append(custom)
        queries = list(dict.fromkeys(queries))[:8]
        token = str(params.get("token", "") or "").strip()
        max_files = max(3, min(int(params.get("max_files", 20)), 60))

        files: dict[str, dict] = {}
        err = None
        for i, q in enumerate(queries):
            try:
                res = github_search(q, token, 30)
            except Exception as e:  # noqa: BLE001
                res = {"files": [], "error": f"{type(e).__name__}"}
            for f in res["files"]:
                files.setdefault(f["raw"], f)
            if res["error"]:
                err = res["error"]
            prog(f"GitHub: поиск {i + 1}/{len(queries)}", i + 1, len(queries))
        result["sources"]["github"] = {
            "count": len(files), "queries": len(queries), "error": err,
        }
        done = 0
        for f in list(files.values())[:max_files]:
            _fetch_item(f["raw"], store)
            done += 1
            if done % 5 == 0 or done == max_files:
                prog(f"Скачивание файлов GitHub: {done}", done, max_files)

    store.write_manifest(job_dir)
    result["images"] = store.counters["images"]
    result["docs"] = store.counters["docs"]
    result["pages"] = store.counters["pages"]
    result["total"] = store.counters["images"] + store.counters["docs"]
    result["blocked"] = store.counters["blocked"]
    result["skipped"] = store.counters["skipped"]
    return result
