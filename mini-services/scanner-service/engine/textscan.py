#!/usr/bin/env python3
"""
MrRobotQR 2.0 — поиск секретов ВНЕ QR-кодов: обычные фото и строковые значения.

Источники текста (все прогоняются через общий analyze_text() — детекторы ключей,
сидов и мультивалютная деривация адресов работают без изменений):

  * OCR обычных фото  — Tesseract (eng): фото бумажных кошельков, скриншоты,
                        печатные фразы. Два режима разбиения: блок (PSM 6) и
                        разрежённый текст (PSM 11). Возвращаем строки с их
                        координатами — по ним рисуем рамки на превью.
  * EXIF-метаданные   — описание/комментарии JPEG/PNG (туда часто прячут ключи).
  * Текстовые файлы   — txt/json/csv/md/html/log/... (в т.ч. из краулера).
  * Бинарные файлы    — печатаемые строки (как утилита strings).
  * HTML страниц      — видимый текст страницы (сайт / веб-архив).

Всё офлайн, без обращений к блокчейну.
"""

from __future__ import annotations

import html as html_mod
import re
from pathlib import Path

from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS

# --- Константы -------------------------------------------------------------------

# Текстовые файлы, читаемые как есть
TEXT_EXTS = {
    ".txt", ".md", ".markdown", ".json", ".csv", ".tsv", ".log", ".nfo",
    ".ini", ".cfg", ".conf", ".yaml", ".yml", ".xml", ".html", ".htm",
    ".url", ".me", ".properties", ".env", ".toml", ".list", ".lst",
}

MAX_TEXT_FILE = 8 * 1024 * 1024        # текстовые файлы больше 8 МБ режем
MAX_BIN_FILE = 64 * 1024 * 1024        # бинарники больше 64 МБ пропускаем
STRINGS_MIN_LEN = 20                   # как у strings: печатаемая последовательность от 20 символов
MAX_STRINGS = 800                      # максимум строк из одного файла

TEXT_CHUNK = 200_000                   # размер чанка текста для анализа
TEXT_CHUNK_OVERLAP = 2_000             # перекрытие, чтобы не разрезать фразу на границе
MAX_PAGE_TEXT = 300_000                # видимый текст страницы: берём первые 300 КБ

MAX_OCR_SIDE = 2000                    # ограничение стороны для OCR
MIN_OCR_SIDE = 800                     # мелкие изображения увеличиваем
OCR_LANG = "eng"

# EXIF-теги с потенциально интересным текстом (id -> человекочитаемое имя)
_EXIF_TEXT_TAGS = {
    0x010E: "ImageDescription",
    0x0131: "Software",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x9C9B: "XPTitle",
    0x9C9C: "XPComment",
    0x9C9D: "XPAuthor",
    0x9C9E: "XPKeywords",
    0x9C9F: "XPSubject",
    0x9286: "UserComment",
}

_TAG_NAMES = {**TAGS, **GPSTAGS}


# --- EXIF ------------------------------------------------------------------------

def _decode_exif_value(v) -> str:
    if isinstance(v, bytes):
        raw = v
        # UserComment: префикс кодировки ASCII\0 / UNICODE\0 (UTF-16)
        if raw.startswith(b"UNICODE\x00"):
            try:
                return raw[8:].decode("utf-16-le", errors="ignore").strip("\x00 ")
            except Exception:  # noqa: BLE001
                return ""
        if raw.startswith(b"ASCII\x00"):
            raw = raw[8:]
        return raw.decode("utf-8", errors="ignore").strip("\x00 ")
    if isinstance(v, str):
        return v
    return ""


def exif_text_from_path(path: str | Path) -> str:
    """Собирает текстовые EXIF-поля изображения (описание, комментарии, автор...)."""
    try:
        img = Image.open(path)
        exif = img.getexif()
    except Exception:  # noqa: BLE001
        return ""
    parts: list[str] = []
    try:
        ifds = [exif]
        try:
            ifds.append(exif.get_ifd(0x8769))   # Exif IFD (UserComment)
        except Exception:  # noqa: BLE001
            pass
        for ifd in ifds:
            for tag_id, value in ifd.items():
                if tag_id not in _EXIF_TEXT_TAGS:
                    continue
                text = _decode_exif_value(value).strip()
                if text:
                    name = _TAG_NAMES.get(tag_id) or _EXIF_TEXT_TAGS[tag_id]
                    parts.append(f"{name}: {text}")
    except Exception:  # noqa: BLE001
        pass
    return "\n".join(parts)


# --- Текстовые и бинарные файлы ----------------------------------------------------

def looks_like_image(name: str) -> bool:
    return Path(name).suffix.lower() in {
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tif", ".tiff",
    }


def is_text_file(name: str) -> bool:
    return Path(name).suffix.lower() in TEXT_EXTS


def strings_from_bytes(data: bytes, min_len: int = STRINGS_MIN_LEN) -> list[str]:
    """Печатаемые ASCII-последовательности (аналог утилиты strings)."""
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    out: list[str] = []
    for m in pat.finditer(data):
        s = m.group(0).decode("ascii", errors="ignore").strip()
        if s:
            out.append(s)
        if len(out) >= MAX_STRINGS:
            break
    return out


def file_text_chunks(path: str | Path) -> list[tuple[str, str]]:
    """Читает файл как источник текста. Возвращает [(метка, текст), ...].

    Текстовые файлы — чанками с перекрытием; бинарные — печатаемые строки.
    """
    p = Path(path)
    size = p.stat().st_size
    chunks: list[tuple[str, str]] = []

    if is_text_file(p.name):
        if size > MAX_TEXT_FILE:
            with open(p, "rb") as fh:
                data = fh.read(MAX_TEXT_FILE)
        else:
            data = p.read_bytes()
        text = data.decode("utf-8", errors="replace")
        if len(text) <= TEXT_CHUNK:
            chunks.append(("text", text))
        else:
            i, n = 0, 0
            while i < len(text) and n < 40:
                chunk = text[i : i + TEXT_CHUNK]
                chunks.append((f"text#{n + 1}", chunk))
                i += TEXT_CHUNK - TEXT_CHUNK_OVERLAP
                n += 1
        return chunks

    if size > MAX_BIN_FILE:
        return []
    data = p.read_bytes()
    strs = strings_from_bytes(data)
    if not strs:
        return []
    # строки объединяем в чанки: analyze_text любит контекст вокруг значений
    joined = "\n".join(strs)
    if len(joined) <= TEXT_CHUNK:
        chunks.append((f"strings({len(strs)})", joined))
    else:
        i, n = 0, 0
        while i < len(strs) and n < 10:
            part = strs[i : i + 200]
            chunks.append((f"strings#{n + 1}({len(part)})", "\n".join(part)))
            i += 200
            n += 1
    return chunks


def collect_document_paths(folder: str | Path, limit: int = 500) -> list[Path]:
    """Все файлы-кандидаты на строковый анализ в папке (кроме изображений)."""
    root = Path(folder)
    out: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if looks_like_image(p.name):
            continue
        if p.suffix.lower() in {".zip", ".gz", ".7z", ".rar", ".pdf", ".mp3", ".mp4", ".avi", ".mkv"}:
            continue  # архивы/медиа бессмысленны для strings, кроме редких случаев
        out.append(p)
        if len(out) >= limit:
            break
    return out


# --- HTML ------------------------------------------------------------------------

_SCRIPT_RE = re.compile(r"<(script|style|noscript)\b[^>]*>.*?</\1>", re.S | re.I)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[ \t\r\f\v]+")


def page_visible_text(html: str) -> str:
    """Видимый текст HTML-страницы (без скриптов, стилей и тегов)."""
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "html.parser")
        for bad in soup(["script", "style", "noscript", "template"]):
            bad.decompose()
        text = soup.get_text("\n")
    except Exception:  # noqa: BLE001 — bs4 не установлен: regex-фолбэк
        text = _SCRIPT_RE.sub(" ", html)
        text = _COMMENT_RE.sub(" ", text)
        text = _TAG_RE.sub("\n", text)
        text = html_mod.unescape(text)
    lines = [_WS_RE.sub(" ", ln).strip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln]
    return "\n".join(lines)[:MAX_PAGE_TEXT]


# --- OCR ---------------------------------------------------------------------------

def _prep_for_ocr(img: Image.Image) -> "object":
    """Серый масштаб + масштабирование до рабочего размера. Возвращает np.ndarray."""
    import cv2
    import numpy as np

    rgb = np.array(img.convert("RGB"))
    gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
    h, w = gray.shape[:2]
    scale = 1.0
    if min(h, w) < MIN_OCR_SIDE:
        scale = min(3.0, MIN_OCR_SIDE / max(1, min(h, w)))
    elif max(h, w) > MAX_OCR_SIDE:
        scale = MAX_OCR_SIDE / max(h, w)
    if scale != 1.0:
        interp = cv2.INTER_CUBIC if scale > 1 else cv2.INTER_AREA
        gray = cv2.resize(gray, (int(w * scale), int(h * scale)), interpolation=interp)
    return gray


def _lines_from_data(data: dict, psm: int) -> list[dict]:
    """Группирует слова image_to_data в строки с объединённым bbox."""
    import numpy as np

    if data is None or not len(data.get("text", [])):
        return []
    groups: dict[tuple, dict] = {}
    n = len(data["text"])
    for i in range(n):
        word = (data["text"][i] or "").strip()
        conf = float(data["conf"][i]) if data["conf"][i] not in ("-1", -1) else -1.0
        if not word or conf < 20:
            continue
        key = (data["block_num"][i], data["par_num"][i], data["line_num"][i])
        x, y, w, h = data["left"][i], data["top"][i], data["width"][i], data["height"][i]
        g = groups.get(key)
        if g is None:
            groups[key] = {"words": [word], "bbox": [int(x), int(y), int(w), int(h)], "confs": [conf]}
        else:
            g["words"].append(word)
            bx, by, bw, bh = g["bbox"]
            nx, ny = min(bx, int(x)), min(by, int(y))
            nx2, ny2 = max(bx + bw, int(x + w)), max(by + bh, int(y + h))
            g["bbox"] = [nx, ny, nx2 - nx, ny2 - by]
            g["confs"].append(conf)
    lines: list[dict] = []
    for g in groups.values():
        text = " ".join(g["words"])
        if len(text.strip()) < 3:
            continue
        lines.append({
            "text": text,
            "bbox": g["bbox"],
            "conf": round(sum(g["confs"]) / len(g["confs"]), 1),
            "psm": psm,
        })
    return lines


def ocr_image_lines(img: Image.Image) -> list[dict]:
    """OCR изображения. Возвращает строки [{"text", "bbox", "conf", "psm"}, ...].

    Два прохода Tesseract: PSM 6 (однородный блок текста) и PSM 11
    (разрежённый текст — подписи, надписи поверх картинки). Дубликаты строк
    между проходами отбрасываются.
    """
    try:
        import pytesseract
    except ImportError:
        return []
    gray = _prep_for_ocr(img)
    out: list[dict] = []
    seen: set[str] = set()
    for psm in (6, 11):
        try:
            data = pytesseract.image_to_data(
                gray, lang=OCR_LANG,
                config=f"--oem 3 --psm {psm}",
                output_type=pytesseract.Output.DICT,
            )
        except Exception:  # noqa: BLE001
            continue
        for line in _lines_from_data(data, psm):
            norm = re.sub(r"\s+", " ", line["text"]).lower()
            if norm in seen:
                continue
            seen.add(norm)
            out.append(line)
    return out


# --- Сопоставление находок со строками OCR -------------------------------------------

def ocr_normalize(text: str) -> str:
    """Нормализация OCR-текста под детекторы (все замены безопасны):

    * акценты/лигатуры -> ASCII (é -> e, «Wvr6éF» -> «Wvr6eF»);
    * типовая подмена tesseract «Ox/oX» -> «0x» перед 40 hex-символами (ETH);
    * одиночные «l»/«I» внутри base58-подобных строк не трогаем — их чинит
      сама валидация Base58Check (невалидные отпадут).
    """
    import unicodedata

    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = re.sub(
        r"(?<![0-9A-Fa-f])[OoQ][xX](?=[0-9A-Fa-f]{40})",
        "0x",
        text,
    )
    return text


def compact_lines_text(text: str) -> str:
    """Вариант текста, где из каждой строки убраны пробелы.

    Tesseract часто рвёт длинные base58/hex-токены пробелами. Склейка даёт
    целые токены; ложные срабатывания невозможны — детекторы проверяют
    контрольные суммы (Base58Check, bech32, EIP-55, checksum BIP39).
    """
    out: list[str] = []
    for ln in text.splitlines():
        compact = re.sub(r"\s+", "", ln)
        out.append(compact if compact else ln)
    return "\n".join(out)


def ocr_base58_repair(text: str) -> list[dict]:
    """Восстановление base58-токенов, «покалеченных» OCR.

    Одиночная лишняя/заменённая буква ломает Base58Check. Перебираем удаление
    по одному символу; если после удаления проверка проходит — это наш токен.
    Ложные срабатывания практически невозможны: нужен ещё и корректный
    version-байт + 4-байтовая контрольная сумма (~1/2^32 на кандидата).

    Возвращает находки в формате детекторов: WIF-ключи и адреса сетей
    BTC/LTC/DOGE/DASH/TRX из B58_COIN_VERSIONS.
    """
    from .addresses import B58_COIN_VERSIONS
    from .bitcoin import BASE58_ALPHABET, b58decode_check, validate_wif

    pat = re.compile(
        r"(?<![1-9A-HJ-NP-Za-km-z])[" + BASE58_ALPHABET + r"]{26,55}(?![1-9A-HJ-NP-Za-km-z])"
    )
    out: list[dict] = []
    seen: set[str] = set()

    def push(f: dict | None, note: str) -> None:
        if not f or f["value"] in seen:
            return
        seen.add(f["value"])
        if note:
            f["detail"] = f"{f.get('detail', '')} · {note}".strip(" ·")
        out.append(f)

    def repair(token: str) -> tuple[str, dict] | None:
        for i in range(len(token)):
            cand = token[:i] + token[i + 1 :]
            f = validate_wif(cand)
            if f:
                return f.to_dict(), f"OCR: удалён лишний символ (позиция {i + 1})"
            try:
                version, payload = b58decode_check(cand)
            except ValueError:
                continue
            if len(payload) == 20 and version in B58_COIN_VERSIONS:
                t, label = B58_COIN_VERSIONS[version]
                return (
                    {"type": t, "value": cand, "address": cand,
                     "detail": f"Адрес {label}, Base58Check верна · OCR: удалён лишний символ (позиция {i + 1})"},
                    "",
                )
        return None

    for m in pat.finditer(text):
        tok = m.group(0)
        if tok in seen:
            continue
        seen.add(tok)
        f = validate_wif(tok)
        if f:
            push(f.to_dict(), "")
            continue
        try:
            version, payload = b58decode_check(tok)
            if len(payload) == 20 and version in B58_COIN_VERSIONS:
                t, label = B58_COIN_VERSIONS[version]
                push({"type": t, "value": tok, "address": tok,
                      "detail": f"Адрес {label}, Base58Check верна"}, "")
                continue
        except ValueError:
            pass
        hit = repair(tok)
        if hit:
            f, note = hit
            push(f, note)
    return out


def _norm(s: str) -> str:
    return re.sub(r"[^0-9a-z]+", "", s.lower())


def boxes_for_values(values: list[str], lines: list[dict]) -> dict[str, list[int] | None]:
    """Для каждого значения ищет строки OCR, где оно встречается, и объединяет их bbox.

    Устойчиво к типичным ошибкам OCR: сравниваем без пробелов и регистра,
    только [0-9a-z]. Для сид-фраз берём первые 4 слова как маркер.
    """
    result: dict[str, list[int] | None] = {}
    norm_lines = [(ln, _norm(ln["text"])) for ln in lines]
    for value in values:
        v = value.strip()
        if not v:
            result[value] = None
            continue
        if " " in v:
            words = v.split()
            probes = [" ".join(words[:4]), " ".join(words[:3]), words[0] + " " + words[1]]
            hit = None
            for probe in probes:
                np_ = _norm(probe)
                if len(np_) < 6:
                    continue
                hit = [ln for ln, nl in norm_lines if np_ and np_ in nl]
                if hit:
                    break
        else:
            nv = _norm(v)
            if len(nv) < 8:
                result[value] = None
                continue
            # полная строка либо её фрагмент (OCR мог съесть края)
            probe = nv if len(nv) <= 40 else nv[:24]
            hit = [ln for ln, nl in norm_lines if probe and probe in nl]
            if not hit and len(nv) > 24:
                probe2 = nv[-16:]
                hit = [ln for ln, nl in norm_lines if probe2 in nl]
        if hit:
            x0 = min(ln["bbox"][0] for ln in hit)
            y0 = min(ln["bbox"][1] for ln in hit)
            x1 = max(ln["bbox"][0] + ln["bbox"][2] for ln in hit)
            y1 = max(ln["bbox"][1] + ln["bbox"][3] for ln in hit)
            result[value] = [int(x0), int(y0), int(x1 - x0), int(y1 - y0)]
        else:
            result[value] = None
    return result
