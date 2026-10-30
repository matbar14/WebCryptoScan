#!/usr/bin/env python3
"""
WebCryptoScan — каскадное декодирование QR-кодов.

Каскад (на каждом шаге собираем все найденные коды, уникальные по содержимому):
  1. pyzbar (libzbar) по исходному изображению
  2. WeChatQRCode (OpenCV, свёрточная модель) по исходному
  3. QRCodeDetector (OpenCV) по исходному
  4. Препроцессинг (если включён), до 4 вариантов, каждый через каскад 1-2:
     v1 grayscale + масштабирование (мелкие коды увеличиваем, гигантские ужимаем)
     v2 CLAHE — выравнивание контраста
     v3 бинаризация Отсу
     v4 адаптивная гауссова бинаризация

Возвращает список DecodeResult(data, barcode_type, bbox, engine, variant).
"""

from __future__ import annotations

from dataclasses import dataclass, asdict

import cv2
import numpy as np
from PIL import Image, ImageOps
from pyzbar import pyzbar

# --- Структуры -----------------------------------------------------------------

@dataclass
class DecodeResult:
    data: str
    barcode_type: str
    bbox: list[int]          # [x, y, w, h]
    engine: str              # pyzbar | wechat | opencv
    variant: str             # original | v1_scale | v2_clahe | v3_otsu | v4_adaptive
    raw: bytes | None = None  # исходные байты QR (для Standard SeedQR); None у wechat/opencv

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("raw", None)
        return d


# --- Инициализация движков (ленивая, потокобезопасная через GIL) ---------------

_wechat = None


def _get_wechat():
    global _wechat
    if _wechat is None:
        _wechat = cv2.wechat_qrcode_WeChatQRCode()
    return _wechat


# --- Вспомогательные функции ---------------------------------------------------

def open_image(path: str) -> Image.Image:
    """Открытие изображения с учётом EXIF-поворота, RGB."""
    img = Image.open(path)
    img = ImageOps.exif_transpose(img)
    img = img.convert("RGB")
    img.load()
    return img


def _bbox_from_pyzbar(obj) -> list[int]:
    r = obj.rect
    return [int(r.left), int(r.top), int(r.width), int(r.height)]


def _bbox_from_points(points) -> list[int]:
    pts = np.array(points, dtype=np.float32).reshape(-1, 2)
    x0, y0 = pts.min(axis=0)
    x1, y1 = pts.max(axis=0)
    return [int(max(0, x0)), int(max(0, y0)), int(x1 - x0), int(y1 - y0)]


def _restore_binary(data: bytes) -> bytes:
    """zbar перекодирует byte-mode данные как latin1->utf8; восстанавливаем оригинал.

    Для валидного UTF-8 текста latin-1 re-encode упадёт и байты останутся как есть;
    для произвольной бинарной последовательности (Standard SeedQR) вернём исходные байты.
    """
    try:
        return data.decode("utf-8").encode("latin-1")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return data


def _run_pyzbar(gray: np.ndarray) -> list[DecodeResult]:
    out: list[DecodeResult] = []
    try:
        for obj in pyzbar.decode(gray):
            if obj.type == "QRCODE":
                data = obj.data.decode("utf-8", errors="replace")
                out.append(DecodeResult(data, "QRCODE", _bbox_from_pyzbar(obj), "pyzbar", "",
                                        raw=_restore_binary(obj.data)))
    except Exception:
        pass
    return out


def _run_wechat(bgr: np.ndarray) -> list[DecodeResult]:
    out: list[DecodeResult] = []
    try:
        texts, points_list = _get_wechat().detectAndDecode(bgr)
        for text, pts in zip(texts, points_list):
            if text:
                out.append(DecodeResult(text, "QRCODE", _bbox_from_points(pts), "wechat", ""))
    except Exception:
        pass
    return out


def _run_opencv(bgr: np.ndarray) -> list[DecodeResult]:
    out: list[DecodeResult] = []
    try:
        ok, texts, points = cv2.QRCodeDetector().detectAndDecodeMulti(bgr)
        if ok and texts is not None:
            for text, pts in zip(texts, points if points is not None else []):
                if text:
                    out.append(DecodeResult(text, "QRCODE", _bbox_from_points(pts), "opencv", ""))
    except Exception:
        pass
    return out


def _fit_scale(gray: np.ndarray) -> tuple[np.ndarray, float]:
    """Масштабирование: мелкие коды увеличиваем до мин. стороны ~900, огромные ужимаем до 2200.

    Возвращает (изображение, масштаб)."""
    h, w = gray.shape[:2]
    min_side, max_side = min(h, w), max(h, w)
    scale = 1.0
    if min_side < 500:
        scale = min(4.0, 900.0 / max(1, min_side))
    elif max_side > 2200:
        scale = 2200.0 / max_side
    if scale == 1.0:
        return gray, 1.0
    interp = cv2.INTER_CUBIC if scale > 1 else cv2.INTER_AREA
    out = cv2.resize(gray, (int(w * scale), int(h * scale)), interpolation=interp)
    return out, scale


def _variants(gray: np.ndarray) -> list[tuple[str, np.ndarray, np.ndarray, float]]:
    """Список вариантов препроцессинга: (имя, gray, bgr, масштаб)."""
    up, scale = _fit_scale(gray)
    variants: list[tuple[str, np.ndarray, np.ndarray, float]] = [("v1_scale", up, _gray_to_bgr(up), scale)]

    try:
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(up)
        variants.append(("v2_clahe", clahe, _gray_to_bgr(clahe), scale))
    except Exception:
        pass

    try:
        blur = cv2.GaussianBlur(up, (3, 3), 0)
        _, otsu = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        variants.append(("v3_otsu", otsu, _gray_to_bgr(otsu), scale))
    except Exception:
        pass

    try:
        adaptive = cv2.adaptiveThreshold(up, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 10)
        variants.append(("v4_adaptive", adaptive, _gray_to_bgr(adaptive), scale))
    except Exception:
        pass

    return variants


def _gray_to_bgr(gray: np.ndarray) -> np.ndarray:
    return cv2.cvtColor(gray, cv2.COLOR_GRAY2BGR)


# --- Основной каскад -----------------------------------------------------------

def decode_image(img: Image.Image, use_preprocess: bool = True) -> list[DecodeResult]:
    """Полный каскад декодирования одного изображения."""
    rgb = np.array(img)
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    bgr = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)

    found: dict[str, DecodeResult] = {}

    def merge(results: list[DecodeResult], variant: str, scale: float = 1.0) -> bool:
        any_new = False
        for r in results:
            r.variant = variant
            if r.data not in found:
                if scale != 1.0:
                    x, y, w, h = r.bbox
                    r.bbox = [
                        int(x / scale),
                        int(y / scale),
                        max(1, int(w / scale)),
                        max(1, int(h / scale)),
                    ]
                found[r.data] = r
                any_new = True
        return any_new

    # --- прямой проход ---
    if merge(_run_pyzbar(gray), "original"):
        pass
    if not found:
        merge(_run_wechat(bgr), "original")
    if not found:
        merge(_run_opencv(bgr), "original")

    # --- препроцессинг ---
    if use_preprocess:
        for name, v_gray, v_bgr, v_scale in _variants(gray):
            if not merge(_run_pyzbar(v_gray), name, v_scale):
                merge(_run_wechat(v_bgr), name, v_scale)

    return list(found.values())
