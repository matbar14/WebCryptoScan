#!/usr/bin/env python3
"""
MrRobotQR 2.0 — детекторы секретов в расшифрованном тексте QR-кода.

Всё работает офлайн:
  * WIF-ключи       — проверка Base58Check + префикса сети, вывод адреса
  * Mini-ключи      — проверка Casascius (SHA256(code+'?') начинается с 0x00)
  * Hex-ключи       — проверка диапазона secp256k1, вывод WIF и адреса
  * BIP39 сид-фразы — все слова из официального словаря (2048) + проверка
                      контрольной суммы (entropy/checksum), длины 12/15/18/21/24
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from pathlib import Path

from .bitcoin import (
    BASE58_ALPHABET,
    validate_hex_key,
    validate_mini_key,
    validate_wif,
)
from .addresses import detect_addresses_in_text

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
WORDLIST_PATH = DATA_DIR / "bip39_english.txt"
ELECTRUM_LEGACY_PATH = DATA_DIR / "electrum_legacy_english.txt"  # старые сиды 2011-2016 (1626)

MNEMONIC_LENGTHS = (24, 21, 18, 15, 12)  # от длинных к коротким
SEEDQR_ENTROPY_SIZES = (16, 20, 24, 28, 32)  # байты энтропии BIP39 -> 12/15/18/21/24 слов

# --- Токенизация ---------------------------------------------------------------

_TOKEN_RE = re.compile(r"[0-9A-Za-z]+")
B58_TOKEN_RE = re.compile(r"[" + re.escape(BASE58_ALPHABET) + r"]{50,52}")
MINI_TOKEN_RE = re.compile(r"S[" + re.escape(BASE58_ALPHABET) + r"]{21,29}")
HEX_TOKEN_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def _tokens(text: str) -> list[str]:
    return _TOKEN_RE.findall(text)


# --- BIP39 ---------------------------------------------------------------------

class Bip39:
    """Официальный английский словарь BIP39 (2048 слов) + проверка контрольной суммы."""

    def __init__(self, path: Path = WORDLIST_PATH):
        words = path.read_text(encoding="utf-8").split()
        if len(words) != 2048:
            raise ValueError(f"словарь BIP39 должен содержать 2048 слов, получено {len(words)}")
        self.words = words
        self.index = {w: i for i, w in enumerate(words)}

    def word_index(self, w: str) -> int | None:
        return self.index.get(w)

    @staticmethod
    def checksum_valid(mnemonic_words: list[str], idx: list[int]) -> bool:
        n = len(idx)
        bits = "".join(f"{i:011b}" for i in idx)
        cs_len = n * 11 // 33
        ent_bits = bits[: n * 11 - cs_len]
        cs_bits = bits[n * 11 - cs_len:]
        try:
            ent = int(ent_bits, 2).to_bytes((n * 11 - cs_len) // 8, "big")
        except (ValueError, OverflowError):
            return False
        digest = hashlib.sha256(ent).digest()
        return bin(int.from_bytes(digest, "big"))[2:].zfill(256).startswith(cs_bits)

    def scan_text(self, text: str) -> list[dict]:
        """Скользящее окно по словам: ищем фразы длины 12..24, все слова из словаря.

        Для QR-текста (одна фраза) ведёт себя как раньше. В свободном тексте
        (OCR, файлы, страницы) метки вроде «seed:» сами могут быть словарными
        словами, поэтому окна перекрываются: сдвиг на длину фразы делаем
        только при валидной контрольной сумме, иначе — на кратчайшее
        совпадение словаря.
        """
        tokens = [unicodedata.normalize("NFKC", t).lower().strip(".,;:!?\"'`*()[]{}") for t in _tokens(text)]
        findings: list[dict] = []
        i = 0
        n = len(tokens)
        while i < n:
            jump = 0
            for size in MNEMONIC_LENGTHS:
                if i + size > n:
                    continue
                window = tokens[i : i + size]
                idx = [self.word_index(w) for w in window]
                if any(x is None for x in idx):
                    continue
                cs_ok = self.checksum_valid(window, idx)
                findings.append(
                    {
                        "type": f"bip39_seed_phrase_{size}",
                        "value": " ".join(window),
                        "valid_checksum": cs_ok,
                        "word_count": size,
                        "detail": "BIP39 сид-фраза, контрольная сумма верна"
                        if cs_ok
                        else "BIP39: все слова из словаря, но контрольная сумма НЕ совпадает "
                        "(возможно, это сид Electrum — у него другая контрольная сумма)",
                    }
                )
                if cs_ok:
                    jump = size
                    break
            i += jump if jump else 1

        # Подавляем «сдвинутые» окна-артефакты: невалидное окно, которое после
        # отбрасывания 1-3 слов с краёв совпадает с валидной фразой — это метка
        # перед фразой (например «seed: thank coconut ...»), а не отдельный сид.
        valid_windows = [tuple(f["value"].split()) for f in findings if f.get("valid_checksum")]
        if valid_windows:
            def _artifact(w: tuple[str, ...]) -> bool:
                for v in valid_windows:
                    for k in range(1, 4):
                        rest = len(w) - k
                        if rest >= 10 and (w[k:] == v[:rest] or w[:rest] == v[len(v) - rest:]):
                            return True
                return False
            findings = [f for f in findings if f.get("valid_checksum") or not _artifact(tuple(f["value"].split()))]
        return findings


# --- Compact SeedQR -------------------------------------------------------------

def detect_compact_seedqr(text: str, bip39: "Bip39") -> list[dict]:
    """Compact SeedQR (SeedSigner): строка цифр, по 4 на слово BIP39 (индекс 1-based).

    12 слов -> 48 цифр, 24 -> 96. Ищем подстроку с цифровыми границами (QR может
    содержать и другие данные рядом). Восстанавливаем фразу и проверяем checksum.
    """
    out: list[dict] = []
    seen_values: set[str] = set()
    for m in re.finditer(r"(?<!\d)(\d{48}|\d{60}|\d{72}|\d{84})(?!\d)", text):
        digits = m.group(1)
        idx = [int(digits[i : i + 4]) for i in range(0, len(digits), 4)]
        if any(not (1 <= x <= 2048) for x in idx):
            continue
        words = [bip39.words[x - 1] for x in idx]
        zero_based = [x - 1 for x in idx]
        cs_ok = bip39.checksum_valid(words, zero_based)
        value = " ".join(words)
        if value in seen_values:
            continue
        seen_values.add(value)
        n = len(words)
        out.append({
            "type": f"seedqr_compact_{n}",
            "value": value,
            "valid_checksum": cs_ok,
            "word_count": n,
            "detail": (
                f"Compact SeedQR (SeedSigner): {n} слов BIP39 в виде цифровых индексов, "
                + ("контрольная сумма верна" if cs_ok else "контрольная сумма НЕ совпадает")
            ),
        })
    return out


def entropy_to_mnemonic(entropy: bytes, bip39: "Bip39") -> list[str]:
    """BIP39: энтропия -> мнемоника (entropy + SHA256-checksum, по 11 бит на слово)."""
    bits = bin(int.from_bytes(entropy, "big"))[2:].zfill(len(entropy) * 8)
    digest = hashlib.sha256(entropy).digest()
    cs_len = len(entropy) * 8 // 32
    bits += bin(int.from_bytes(digest, "big"))[2:].zfill(256)[:cs_len]
    if len(bits) % 11:
        raise ValueError("некорректная длина энтропии")
    return [bip39.words[int(bits[i : i + 11], 2)] for i in range(0, len(bits), 11)]


def detect_standard_seedqr(raw: bytes, bip39: "Bip39") -> dict | None:
    """Standard SeedQR: энтропия BIP39 (16/20/24/28/32 байта) в byte-mode QR."""
    if len(raw) not in SEEDQR_ENTROPY_SIZES:
        return None
    try:
        words = entropy_to_mnemonic(raw, bip39)
    except ValueError:
        return None
    idx = [bip39.word_index(w) for w in words]
    cs_ok = bip39.checksum_valid(words, idx)
    n = len(words)
    return {
        "type": f"seedqr_standard_{n}",
        "value": " ".join(words),
        "valid_checksum": cs_ok,
        "word_count": n,
        "detail": (
            f"Standard SeedQR: энтропия BIP39 ({len(raw)} байт) в QR byte-mode, "
            + ("контрольная сумма верна" if cs_ok else "контрольная сумма НЕ совпадает")
        ),
    }


# --- Electrum -------------------------------------------------------------------

class Wordlist12:
    """Словарь для поиска 12-словных фраз Electrum."""

    def __init__(self, path: Path):
        self.words = path.read_text(encoding="utf-8").split()
        self.index = set(self.words)

    def scan_text(self, text: str) -> list[list[str]]:
        tokens = [unicodedata.normalize("NFKC", t).lower().strip(".,;:!?\"'`*()[]{}") for t in _tokens(text)]
        out: list[list[str]] = []
        i = 0
        while i <= len(tokens) - 12:
            window = tokens[i : i + 12]
            if all(w in self.index for w in window):
                out.append(window)
                i += 12
            else:
                i += 1
        return out


# --- Общий анализ текста QR ----------------------------------------------------

def analyze_text(text: str, options: dict, bip39: Bip39) -> list[dict]:
    """Возвращает список находок всех поддерживаемых типов в одном тексте QR-кода."""
    results: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def push(f: dict) -> None:
        key = (f.get("type", ""), f.get("value", ""))
        if key not in seen:
            seen.add(key)
            results.append(f)

    tokens = _tokens(text)

    if options.get("detect_wif", True):
        for m in B58_TOKEN_RE.finditer(text):
            f = validate_wif(m.group(0))
            if f:
                push(f.to_dict())

    if options.get("detect_mini", True):
        for m in MINI_TOKEN_RE.finditer(text):
            f = validate_mini_key(m.group(0))
            if f:
                push(f.to_dict())

    if options.get("detect_hex", True):
        for m in HEX_TOKEN_RE.finditer(text):
            f = validate_hex_key(m.group(0))
            if f:
                push(f.to_dict())

    if options.get("detect_seed", True):
        for f in bip39.scan_text(text):
            push(f)

        if options.get("detect_seedqr", True):
            for sq in detect_compact_seedqr(text, bip39):
                push(sq)

        if options.get("detect_electrum", True):
            # старый формат Electrum (2011-2016, словарь 1626 слов)
            for window in get_electrum_legacy().scan_text(text):
                phrase = " ".join(window)
                idx = [bip39.word_index(w) for w in window]
                if len(idx) == len(window) and all(x is not None for x in idx) \
                        and bip39.checksum_valid(window, idx):
                    continue  # это валидная BIP39 — уже поймана выше
                push({
                    "type": "electrum_legacy_seed",
                    "value": phrase,
                    "word_count": 12,
                    "detail": "Старый формат Electrum (до 2.7): 12 слов из словаря 1626; "
                              "контрольная сумма Electrum офлайн не проверяется",
                })
            # Современные сиды Electrum (12 слов из 2048-словаря) неотличимы по словарю
            # от BIP39: их ловит bip39.scan_text с checksum=FAIL — см. подсказку в detail.

    if options.get("detect_addresses", True):
        for f in detect_addresses_in_text(text):
            push(f)

    return results


def analyze_bytes(raw: bytes, options: dict, bip39: Bip39) -> list[dict]:
    """Анализ исходных байтов QR (byte-mode): Standard SeedQR."""
    if not options.get("detect_seed", True) or not options.get("detect_seedqr", True):
        return []
    if not raw:
        return []
    f = detect_standard_seedqr(raw, bip39)
    return [f] if f else []


_bip39: Bip39 | None = None
_electrum_legacy: Wordlist12 | None = None


def get_bip39() -> Bip39:
    global _bip39
    if _bip39 is None:
        _bip39 = Bip39()
    return _bip39


def get_electrum_legacy() -> Wordlist12:
    global _electrum_legacy
    if _electrum_legacy is None:
        _electrum_legacy = Wordlist12(ELECTRUM_LEGACY_PATH)
    return _electrum_legacy
