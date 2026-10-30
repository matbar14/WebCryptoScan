#!/usr/bin/env python3
"""
WebCryptoScan — краулер изображений: 9 поисковых систем.

Движки:
  icrawler (встроенные) : Google, Bing, Baidu
  кастомные (requests)  : 360 Поиск, Sogou, DuckDuckGo, Яндекс, Openverse, Wikimedia

Каждый движок обрабатывается независимо: ошибка или анти-бот блокировка одного
не ломает остальные и честно попадает в отчёт джобы. Дедупlication по md5:
одна и та же картинка не скачается дважды разными движками.

Пресеты включают наборы для поиска фото с сид-фразами (bip39/seed phrase),
бумажных кошельков и QR-кодов.
"""

from __future__ import annotations

import hashlib
import io
import re
import traceback
from pathlib import Path
from urllib.parse import quote, unquote

import requests

# --- Пресеты ключевых слов ------------------------------------------------------

PRESETS: dict[str, dict] = {
    "btc_qr": {
        "label": "Bitcoin QR / бумажные кошельки",
        "keywords": [
            "bitcoin qr code",
            "bitcoin paper wallet",
            "bitcoin wallet qr",
            "crypto paper wallet qr",
            "btc private key qr",
        ],
    },
    "seed_phrase": {
        "label": "Сид-фразы (BIP39)",
        "keywords": [
            "bitcoin seed phrase",
            "crypto seed phrase 12 words",
            "bip39 mnemonic phrase",
            "seed phrase recovery words",
            "metamask seed phrase paper",
            "recovery phrase wallet backup",
            "secret words crypto wallet",
            "mnemonic phrase paper backup",
        ],
    },
    "mixed": {
        "label": "Смешанный (ключи + фразы)",
        "keywords": [
            "bitcoin qr code",
            "bitcoin paper wallet",
            "crypto seed phrase",
            "bip39 mnemonic phrase",
            "wallet recovery phrase",
        ],
    },
}

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff"}

# --- Реестр движков ---------------------------------------------------------------

ENGINE_LABELS: dict[str, str] = {
    "google": "Google",
    "bing": "Bing",
    "duckduckgo": "DuckDuckGo",
    "baidu": "Baidu",
    "so360": "360",
    "sogou": "Sogou",
    "yandex": "Яндекс",
    "wikimedia": "Wikimedia",
    "openverse": "Openverse",
}
ENGINE_NAMES: list[str] = list(ENGINE_LABELS)

_ANTIBOT_NOTE = (
    "анти-бот блокировка запросов из дата-центра; на локальной машине обычно работает"
)

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
_HEADERS = {"User-Agent": _UA, "Accept-Language": "en-US,en;q=0.9"}
_WIKI_UA = "WebCryptoScan/1.0 (offline QR scanner; https://github.com/matbar14/WebCryptoScan)"
_HTTP_TIMEOUT = 15
_MIN_BYTES = 3072          # меньше 3 КБ — мусор
_MIN_SIDE = 120            # меньшая сторона < 120 px — бесполезна для декодера
_MAX_BYTES = 25 * 1024 * 1024


def _get(url: str, *, params: dict | None = None, headers: dict | None = None,
         timeout: int = _HTTP_TIMEOUT) -> requests.Response:
    h = dict(_HEADERS)
    if headers:
        h.update(headers)
    return requests.get(url, params=params, headers=h, timeout=timeout)


# --- Кастомные поисковые движки: (keyword, max_num) -> list[url] ------------------

def _url_budget(max_num: int) -> int:
    """Запас ссылок: часть хостов всегда мертва/заблокирована, качаем max_num."""
    return min(max_num * 4, 200)


def _search_so360(kw: str, max_num: int) -> list[str]:
    """360 Поиск (image.so.com) — JSON API, работает и из дата-центров."""
    urls: list[str] = []
    budget = _url_budget(max_num)
    sn = 0
    while len(urls) < budget and sn < 240:
        r = _get("https://image.so.com/j", params={
            "q": kw, "src": "srp", "correct": "", "pn": 60, "sn": sn,
        })
        r.raise_for_status()
        items = (r.json() or {}).get("list") or []
        if not items:
            break
        for it in items:
            u = it.get("img") or it.get("downurl") or ""
            if u.startswith("//"):
                u = "https:" + u
            if u.startswith("http"):
                urls.append(u)
        sn += 60
    return urls[:budget]


def _search_duckduckgo(kw: str, max_num: int) -> list[str]:
    """DuckDuckGo Images: vqd-токен + i.js JSON."""
    r = _get("https://duckduckgo.com/", params={"q": kw, "iax": "images", "ia": "images"})
    r.raise_for_status()
    m = re.search(r'vqd=["\']?([\d-]+)["\']?', r.text)
    if not m:
        raise ValueError("DuckDuckGo: не удалось получить vqd-токен (" + _ANTIBOT_NOTE + ")")
    r2 = _get("https://duckduckgo.com/i.js", params={
        "l": "us-en", "o": "json", "q": kw, "vqd": m.group(1), "f": ",,,", "p": "1",
    }, headers={"Referer": "https://duckduckgo.com/"})
    if r2.status_code == 202 or "challenge" in r2.text[:60]:
        raise ValueError("DuckDuckGo: anti-bot challenge (" + _ANTIBOT_NOTE + ")")
    r2.raise_for_status()
    data = r2.json()
    urls = [it.get("image", "") for it in data.get("results", [])]
    urls = [u for u in urls if u.startswith("http")]
    if not urls:
        raise ValueError("DuckDuckGo: пустая выдача (" + _ANTIBOT_NOTE + ")")
    return urls[:_url_budget(max_num)]


def _search_sogou(kw: str, max_num: int) -> list[str]:
    """Sogou Картинки: JSON napi (data.items[].picUrl)."""
    urls: list[str] = []
    budget = _url_budget(max_num)
    start = 0
    while len(urls) < budget and start < 240:
        r = _get("https://pic.sogou.com/napi/pc/searchList", params={
            "mode": 1, "start": start, "xml_len": 48, "query": kw,
        })
        r.raise_for_status()
        data = r.json() or {}
        if data.get("status") != 0:
            raise ValueError("Sogou: сервер ответил forbid (" + _ANTIBOT_NOTE + ")")
        items = ((data.get("data") or {}).get("items")) or []
        if not items:
            break
        for it in items:
            u = it.get("picUrl") or it.get("oriPicUrl") or ""
            if u.startswith("//"):
                u = "https:" + u
            if u.startswith("http"):
                urls.append(u)
        start += 48
    if not urls:
        raise ValueError("Sogou: пустая выдача (" + _ANTIBOT_NOTE + ")")
    return urls[:budget]


def _search_yandex(kw: str, max_num: int) -> list[str]:
    """Яндекс.Картинки: best-effort парсинг ссылок из HTML выдачи."""
    r = _get("https://yandex.com/images/search", params={"text": kw, "nomisspell": 1})
    r.raise_for_status()
    text = unquote(r.text)
    urls: list[str] = []
    urls += re.findall(r'"orig":\s*\{[^}]*?"url":"(https?://[^"]+)"', text)
    urls += re.findall(r'(https?://avatars\.mds\.yandex\.net/get-[^"\\\s]+)', text)
    urls = [u.replace("\\u0026", "&").replace("\\/", "/") for u in urls]
    urls = list(dict.fromkeys(urls))
    if not urls:
        raise ValueError("Яндекс: в HTML нет ссылок на изображения (" + _ANTIBOT_NOTE + ")")
    return urls[:_url_budget(max_num)]


def _search_openverse(kw: str, max_num: int) -> list[str]:
    """Openverse (WordPress) — открытый API без ключа, CC-изображения.

    Анонимам доступно не более 20 результатов на страницу (page_size > 20 -> 401),
    поэтому набираем бюджет постранично.
    """
    budget = _url_budget(max_num)
    page_size = min(20, budget)
    urls: list[str] = []
    for page in range(1, 6):
        if len(urls) >= budget:
            break
        r = _get("https://api.openverse.org/v1/images/", params={
            "q": kw, "page_size": page_size, "page": page,
        }, headers={"Accept": "application/json"}, timeout=25)
        r.raise_for_status()
        results = (r.json() or {}).get("results") or []
        if not results:
            break
        urls += [it.get("url") or "" for it in results]
        urls = [u for u in urls if u.startswith("http")]
    if not urls:
        raise ValueError("Openverse: пустая выдача")
    return urls[:budget]


def _search_wikimedia(kw: str, max_num: int) -> list[str]:
    """Wikimedia Commons — открытый API без ключа (превью 1024 px)."""
    r = _get("https://commons.wikimedia.org/w/api.php", params={
        "action": "query", "format": "json", "generator": "search",
        "gsrsearch": f"{kw} filetype:bitmap", "gsrnamespace": 6,
        "gsrlimit": min(_url_budget(max_num), 50), "prop": "imageinfo", "iiprop": "url|mime",
        "iiurlwidth": 1024,
    }, headers={"User-Agent": _WIKI_UA, "Api-User-Agent": _WIKI_UA})
    if r.status_code == 403:
        raise ValueError("Wikimedia: 403 — Commons блокирует IP дата-центров (" + _ANTIBOT_NOTE + ")")
    r.raise_for_status()
    pages = ((r.json() or {}).get("query") or {}).get("pages") or {}
    urls: list[str] = []
    for p in pages.values():
        for ii in p.get("imageinfo") or []:
            u = ii.get("thumburl") or ii.get("url") or ""
            if u.startswith("http"):
                urls.append(u)
    if not urls:
        raise ValueError("Wikimedia: ничего не найдено по запросу")
    return urls[:_url_budget(max_num)]


CUSTOM_SEARCH = {
    "so360": _search_so360,
    "duckduckgo": _search_duckduckgo,
    "sogou": _search_sogou,
    "yandex": _search_yandex,
    "openverse": _search_openverse,
    "wikimedia": _search_wikimedia,
}

# --- Скачивание -------------------------------------------------------------------


def _save_image(data: bytes, target_dir: Path, name: str) -> bool:
    """Валидирует байты как изображение и сохраняет; True — если сохранено."""
    from PIL import Image

    try:
        img = Image.open(io.BytesIO(data))
        img.verify()
        img = Image.open(io.BytesIO(data))
        w, h = img.size
        if w < _MIN_SIDE or h < _MIN_SIDE:
            return False
        fmt = (img.format or "").lower()
        ext = {"jpeg": ".jpg", "png": ".png", "webp": ".webp", "gif": ".gif",
               "bmp": ".bmp"}.get(fmt)
        if ext is None:  # AVIF/HEIF и прочая экзотика — конвертируем в JPG
            img.convert("RGB").save(target_dir / f"{name}.jpg", "JPEG", quality=92)
        else:
            (target_dir / f"{name}{ext}").write_bytes(data)
        return True
    except Exception:  # noqa: BLE001 — битые/экзотичные файлы просто пропускаем
        return False


def _download_images(urls: list[str], target_dir: Path, prefix: str,
                     max_num: int, seen: set[str]) -> tuple[int, int]:
    """Скачивает URLs с проверкой формата, размеров и md5-дедупом.

    Возвращает (сохранено, заблокировано_403_429).
    """
    saved = 0
    blocked = 0
    for i, u in enumerate(urls):
        if saved >= max_num:
            break
        try:
            r = requests.get(u, headers=_HEADERS, timeout=_HTTP_TIMEOUT, stream=True)
            if r.status_code in (403, 429):
                blocked += 1
                continue
            ct = r.headers.get("content-type", "")
            if r.status_code != 200 or ("image" not in ct and "octet-stream" not in ct):
                continue
            data = r.content
            if len(data) < _MIN_BYTES or len(data) > _MAX_BYTES:
                continue
            h = hashlib.md5(data).hexdigest()
            if h in seen:
                continue
            name = f"{prefix}_n{i:03d}_{h[:8]}"
            if _save_image(data, target_dir, name):
                seen.add(h)
                saved += 1
        except Exception:  # noqa: BLE001 — одна битая ссылка не роняет движок
            continue
    return saved, blocked


def _load_seen_hashes(d: Path) -> set[str]:
    seen = set()
    if d.exists():
        for p in d.iterdir():
            if p.suffix.lower() in IMAGE_EXTS and p.is_file():
                try:
                    if p.stat().st_size >= _MIN_BYTES:
                        seen.add(hashlib.md5(p.read_bytes()).hexdigest())
                except OSError:
                    continue
    return seen


# --- Главная точка входа ------------------------------------------------------------


def crawl_images(target_dir: Path, keyword_list: list[str], engines: list[str],
                 max_num: int) -> dict:
    """Скачивает изображения по списку ключевых слов в target_dir.

    Возвращает {"keywords": {kw: {"engines": {...}, "total": N}}, "total": N}.
    """
    from icrawler.builtin import BaiduImageCrawler, BingImageCrawler, GoogleImageCrawler

    target_dir.mkdir(parents=True, exist_ok=True)
    result: dict = {"keywords": {}, "total": 0}
    crawler_map = {
        "google": GoogleImageCrawler,
        "bing": BingImageCrawler,
        "baidu": BaiduImageCrawler,
    }
    seen = _load_seen_hashes(target_dir)

    for kw_idx, kw in enumerate(keyword_list):
        kw_info: dict = {"engines": {}, "total": 0}
        for name in engines:
            if name not in crawler_map and name not in CUSTOM_SEARCH:
                continue
            info = {"count": 0, "error": None}
            before = _count_images(target_dir)
            try:
                if name in crawler_map:
                    cls = crawler_map[name]
                    crawler = cls(parser_threads=4, downloader_threads=8,
                                  storage={"root_dir": str(target_dir)})
                    crawler.crawl(keyword=kw, offset=0, max_num=max_num)
                    seen = _load_seen_hashes(target_dir)
                else:
                    urls = CUSTOM_SEARCH[name](kw, max_num)
                    if not urls:
                        raise ValueError(f"{ENGINE_LABELS.get(name, name)}: пустая выдача ({_ANTIBOT_NOTE})")
                    n, blocked = _download_images(urls, target_dir,
                                                  f"{name}_k{kw_idx:02d}", max_num, seen)
                    if n == 0:
                        label = ENGINE_LABELS.get(name, name)
                        if blocked >= 2:
                            info["error"] = (
                                f"{label}: хост с картинками отдаёт 403/429 — блокировка IP "
                                "дата-центра; на локальной машине обычно работает"
                            )
                        else:
                            info["error"] = (
                                f"{label}: ссылки не прошли проверку формата/размера "
                                "или все дубликаты"
                            )
            except ValueError as e:
                info["error"] = str(e)
            except requests.RequestException as e:
                info["error"] = f"сеть: {type(e).__name__}: {str(e)[:140]}"
            except Exception as e:  # noqa: BLE001
                info["error"] = f"{type(e).__name__}: {e}"
                traceback.print_exc()
            after = _count_images(target_dir)
            info["count"] = max(0, after - before)
            if info["count"] == 0 and info["error"] is None:
                info["error"] = (
                    "поисковик не вернул изображений (возможна анти-бот блокировка запросов "
                    "из дата-центра; на локальной машине обычно работает)"
                )
            kw_info["engines"][name] = info
            kw_info["total"] += info["count"]
            result["total"] += info["count"]
        result["keywords"][kw] = kw_info

    return result


def _count_images(d: Path) -> int:
    return sum(1 for p in d.iterdir() if p.suffix.lower() in IMAGE_EXTS) if d.exists() else 0


def collect_image_paths(folder: Path, limit: int = 5000) -> list[Path]:
    """Все изображения в папке (без рекурсии), отсортированные по имени."""
    if not folder.exists():
        return []
    paths = [p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in IMAGE_EXTS]
    paths.sort(key=lambda p: p.name)
    return paths[:limit]
