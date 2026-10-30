#!/usr/bin/env python3
"""
MrRobotQR 2.0 — краулер изображений (icrawler) с пресетами ключевых слов.

Пресеты включают наборы для поиска фото с сид-фразами (bip39/seed phrase),
бумажных кошельков и QR-кодов. Каждая поисковая система обрабатывается
независимо: ошибка одной не ломает остальные.
"""

from __future__ import annotations

import traceback
from pathlib import Path

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


def crawl_images(target_dir: Path, keyword_list: list[str], engines: list[str], max_num: int) -> dict:
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

    for kw in keyword_list:
        kw_info: dict = {"engines": {}, "total": 0}
        for name in engines:
            cls = crawler_map.get(name)
            if cls is None:
                continue
            info = {"count": 0, "error": None}
            before = _count_images(target_dir)
            try:
                crawler = cls(parser_threads=4, downloader_threads=8, storage={"root_dir": str(target_dir)})
                crawler.crawl(keyword=kw, offset=0, max_num=max_num)
            except Exception as e:  # noqa: BLE001
                info["error"] = f"{type(e).__name__}: {e}"
                traceback.print_exc()
            after = _count_images(target_dir)
            info["count"] = max(0, after - before)
            if info["count"] == 0 and info["error"] is None:
                info["error"] = (
                    "поисковик не вернул изображений (возможна анти-бот блокировка запросов из дата-центра; "
                    "на локальной машине обычно работает)"
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
