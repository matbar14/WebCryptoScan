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

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
WORDLIST_PATH = DATA_DIR / "bip39_english.txt"

MNEMONIC_LENGTHS = (24, 21, 18, 15, 12)  # от длинных к коротким

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

        Жадный проход слева направо, при находке окно сдвигается за её конец.
        """
        tokens = [unicodedata.normalize("NFKC", t).lower().strip(".,;:!?\"'`*()[]{}") for t in _tokens(text)]
        findings: list[dict] = []
        i = 0
        n = len(tokens)
        while i < n:
            matched = False
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
                        else "BIP39: все слова из словаря, но контрольная сумма НЕ совпадает",
                    }
                )
                i += size
                matched = True
                break
            if not matched:
                i += 1
        return findings


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

    return results


_bip39: Bip39 | None = None


def get_bip39() -> Bip39:
    global _bip39
    if _bip39 is None:
        _bip39 = Bip39()
    return _bip39
