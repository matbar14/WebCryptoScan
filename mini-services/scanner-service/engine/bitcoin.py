#!/usr/bin/env python3
"""
WebCryptoScan — офлайн-валидация Bitcoin-ключей (без сетевых запросов).

Поддерживаемые форматы:
  * WIF-приватный ключ (51-52 символа Base58Check, префикс 0x80)
  * Mini private key (22/30 символов, формат Casascius, префикс 'S')
  * Сырой приватный ключ в hex (64 символа)
Для каждого валидного ключа выводится P2PKH-адрес (compressed/uncompressed).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

# --- Base58Check ---------------------------------------------------------------

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {c: i for i, c in enumerate(BASE58_ALPHABET)}

CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def is_base58(s: str) -> bool:
    return bool(s) and all(c in BASE58_INDEX for c in s)


def b58decode_check(s: str) -> bytes:
    """Декодирование Base58Check; бросает ValueError при неверной контрольной сумме."""
    if not is_base58(s):
        raise ValueError("не Base58")
    num = 0
    for c in s:
        num = num * 58 + BASE58_INDEX[c]
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    # ведущие нули ('1' в Base58)
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    raw = b"\x00" * pad + raw
    if len(raw) < 5:
        raise ValueError("слишком коротко")
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        raise ValueError("неверная контрольная сумма Base58Check")
    return payload


# --- Детекторы -----------------------------------------------------------------

@dataclass
class KeyFinding:
    """Результат распознавания приватного ключа."""
    type: str            # wif_compressed | wif_uncompressed | mini_private_key | hex_private_key
    value: str           # исходное значение
    address: str         # P2PKH-адрес (compressed по умолчанию)
    address_uncompressed: str = ""
    wif: str = ""        # канонический WIF (для hex/mini)
    detail: str = ""     # человекочитаемое описание

    def to_dict(self) -> dict:
        d = {
            "type": self.type,
            "value": self.value,
            "address": self.address,
        }
        if self.address_uncompressed:
            d["address_uncompressed"] = self.address_uncompressed
        if self.wif and self.wif != self.value:
            d["wif"] = self.wif
        if self.detail:
            d["detail"] = self.detail
        return d


def _key_from_secret(secret_bytes: bytes):
    from pycoin.symbols.btc import network

    se = int.from_bytes(secret_bytes, "big")
    if not (0 < se < CURVE_ORDER):
        raise ValueError("ключ вне диапазона кривой secp256k1")
    return network.parse.private_key("%064x" % se)


def validate_wif(code: str) -> KeyFinding | None:
    """WIF: Base58Check, версия 0x80, payload 32 байта (или 33 с флагом 0x01)."""
    if not (49 <= len(code) <= 52) or not code.startswith(("5", "K", "L")):
        return None
    try:
        payload = b58decode_check(code)
    except ValueError:
        return None
    if not payload or payload[0] != 0x80:
        return None
    body = payload[1:]
    if len(body) == 33 and body[-1] == 0x01:
        compressed = True
        se = int.from_bytes(body[:-1], "big")
    elif len(body) == 32:
        compressed = False
        se = int.from_bytes(body, "big")
    else:
        return None
    if not (0 < se < CURVE_ORDER):
        return None
    try:
        from pycoin.symbols.btc import network

        key = network.parse.private_key(code)
        addr_c = key.address()
        key_u = network.parse.private_key(key.wif(is_compressed=False)) if compressed else key
        addr_u = key_u.address()
        return KeyFinding(
            type="wif_compressed" if compressed else "wif_uncompressed",
            value=code,
            address=addr_c,
            address_uncompressed=addr_u,
            detail="WIF, сжатый pubkey" if compressed else "WIF, несжатый pubkey",
        )
    except Exception:
        return None


def validate_mini_key(code: str) -> KeyFinding | None:
    """Mini private key: 22 символа (устаревший) или 30 символов, префикс 'S'.

    Проверка валидности: SHA256(code + '?') должен начинаться с нулевого байта.
    Приватный ключ = SHA256(code).
    """
    if len(code) not in (22, 30) or not code.startswith("S") or not is_base58(code):
        return None
    if hashlib.sha256((code + "?").encode("ascii")).digest()[0] != 0x00:
        return None
    try:
        secret = hashlib.sha256(code.encode("ascii")).digest()
        key = _key_from_secret(secret)
        return KeyFinding(
            type="mini_private_key",
            value=code,
            address=key.address(),
            wif=key.wif(is_compressed=True),
            detail="Mini-ключ (Casascius), 22 символа" if len(code) == 22 else "Mini-ключ (Casascius), 30 символов",
        )
    except Exception:
        return None


def validate_hex_key(code: str) -> KeyFinding | None:
    """Сырой приватный ключ: 64 hex-символа."""
    if len(code) != 64:
        return None
    try:
        raw = bytes.fromhex(code)
        key = _key_from_secret(raw)
    except (ValueError, Exception):
        return None
    key_u = None
    try:
        from pycoin.symbols.btc import network

        key_u = network.parse.private_key(key.wif(is_compressed=False))
    except Exception:
        pass
    return KeyFinding(
        type="hex_private_key",
        value=code,
        address=key.address(),
        address_uncompressed=key_u.address() if key_u else "",
        wif=key.wif(is_compressed=True),
        detail="Сырой ключ (hex 64), адрес для сжатого pubkey",
    )
