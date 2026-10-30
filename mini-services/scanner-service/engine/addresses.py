#!/usr/bin/env python3
"""
MrRobotQR 2.0 — мультивалютные адреса: детектирование в тексте QR и вывод
адресов для найденных приватных ключей и сид-фраз.

Детектирование (офлайн, с проверкой контрольных сумм):
  * BTC   — P2PKH (1...), P2SH (3...), SegWit (bc1q), Taproot (bc1p)
  * LTC   — P2PKH (L...), P2SH (M...), SegWit (ltc1)
  * DOGE  — P2PKH (D...)
  * DASH  — P2PKH (X...), P2SH (7...)
  * ETH   — 0x... с проверкой EIP-55
  * BCH   — CashAddr bitcoincash:q...
  * XRP   — r... (алфавит Ripple)
  * TRX   — T... (версия 0x41)
  * SOL   — Base58, 43-44 символа (ed25519, без контрольной суммы)

Вывод адресов (деривация):
  * WIF / mini / hex ключ -> BTC (legacy, uncompressed, taproot), LTC, DOGE,
    DASH, ETH — все сети из одного приватного ключа secp256k1
  * валидная BIP39/SeedQR фраза -> стандартные пути BIP44/BIP84/BIP86
    (BTC legacy/SegWit/Taproot, LTC, LTC SegWit, DOGE, ETH), passphrase ""
"""

from __future__ import annotations

import re

from . import crypto
from .crypto import (
    BASE58_ALPHABET,
    BECH32_CHARSET,
    XRP_ALPHABET,
    b58check_encode,
    b58decode_check,
    eth_check,
)

# --- Метки сетей (для UI и отчётов) ---------------------------------------------

ADDRESS_LABELS: dict[str, str] = {
    "btc_legacy": "BTC Legacy",
    "btc_legacy_uncompressed": "BTC Legacy (uncompressed)",
    "btc_segwit": "BTC SegWit",
    "btc_taproot": "BTC Taproot",
    "ltc": "LTC",
    "ltc_segwit": "LTC SegWit",
    "doge": "DOGE",
    "dash": "DASH",
    "eth": "ETH",
}

# --- Регулярные выражения ---------------------------------------------------------

# Base58-подобные токены (без 0, O, I, l): адреса, WIF, xpub-фрагменты
B58_TOKEN_RE = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[" + BASE58_ALPHABET + r"]{25,55}(?![1-9A-HJ-NP-Za-km-z])")
ETH_TOKEN_RE = re.compile(r"(?<![0-9a-fA-Fx])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])")
SEGWIT_TOKEN_RE = re.compile(r"(?<![a-zA-Z0-9])(?:bc|ltc)1[" + BECH32_CHARSET + r"]{14,71}(?![a-zA-Z0-9])")
CASHADDR_TOKEN_RE = re.compile(r"(?<![a-zA-Z0-9])(?:bitcoincash:|bchtest:)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{41,50}(?![a-zA-Z0-9])")

# --- Версии Base58Check ------------------------------------------------------------

B58_COIN_VERSIONS: dict[int, tuple[str, str]] = {
    0x00: ("address_btc_p2pkh", "BTC Legacy (P2PKH)"),
    0x05: ("address_btc_p2sh", "BTC P2SH"),
    0x30: ("address_ltc_p2pkh", "LTC (L...)"),
    0x32: ("address_ltc_p2sh", "LTC (M...)"),
    0x1E: ("address_doge", "DOGE"),
    0x4C: ("address_dash", "DASH"),
    0x10: ("address_dash_p2sh", "DASH P2SH"),
    0x41: ("address_trx", "TRON"),
}


def _classify_base58(token: str) -> dict | None:
    """Классификация Base58Check-токена по версии байта."""
    try:
        version, payload = b58decode_check(token)
    except ValueError:
        return None
    if len(payload) != 20:
        if version == 0x80:
            return None  # WIF — ловится детектором ключей
        return None
    hit = B58_COIN_VERSIONS.get(version)
    if not hit:
        return None
    t, label = hit
    return {"type": t, "value": token, "address": token, "detail": f"Адрес {label}, Base58Check верна"}


def _classify_xrp(token: str) -> dict | None:
    try:
        version, payload = b58decode_check(token, XRP_ALPHABET)
    except ValueError:
        return None
    if version != 0x00 or len(payload) not in (20, 24):
        return None
    return {"type": "address_xrp", "value": token, "address": token,
            "detail": "Адрес XRP (алфавит Ripple), Base58Check верна"}


def _classify_sol(token: str) -> dict | None:
    """Solana: ed25519 pubkey в Base58, без контрольной суммы."""
    if len(token) not in (43, 44):
        return None
    num = 0
    for c in token:
        if c not in BASE58_ALPHABET:
            return None
        num = num * 58 + BASE58_ALPHABET.index(c)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    if len(raw) != 32:
        return None
    return {"type": "address_sol", "value": token, "address": token,
            "detail": "Возможный адрес Solana (Base58, 32 байта); без контрольной суммы"}


def _classify_segwit(token: str) -> dict | None:
    for hrp, t, t_tap, label in (
        ("bc", "address_btc_segwit", "address_btc_taproot", "BTC SegWit (bech32/bech32m)"),
        ("ltc", "address_ltc_segwit", "address_ltc_taproot", "LTC SegWit (bech32/bech32m)"),
    ):
        decoded = crypto.segwit_decode(hrp, token)
        if decoded:
            witver, _witprog = decoded
            if witver == 1:
                t = t_tap
                label = f"{hrp.upper()} Taproot"
            fmt = "bech32" if witver == 0 else "bech32m (Taproot)" if witver == 1 else f"witver {witver}"
            return {"type": t, "value": token, "address": token,
                    "detail": f"Адрес {label}, {fmt}, checksum верна"}
    return None


def _classify_cashaddr(token: str) -> dict | None:
    decoded = crypto.cashaddr_decode(token)
    if not decoded:
        return None
    type_bit, h = decoded
    kind = "P2PKH" if type_bit == 0 else "P2SH"
    return {"type": "address_bch_cashaddr", "value": token, "address": token,
            "detail": f"Адрес BCH CashAddr ({kind}, hash160 {len(h)*8} бит), checksum верна"}


def _classify_eth(token: str) -> dict | None:
    if not eth_check(token):
        return None
    has_checksum = token[2:] != token[2:].lower()
    detail = "Адрес ETH, EIP-55 checksum верна" if has_checksum else \
             "Адрес ETH (без чек-суммы в регистре — принят)"
    return {"type": "address_eth", "value": token, "address": token, "detail": detail}


# --- Публичное API: детектирование ---------------------------------------------------

def detect_addresses_in_text(text: str) -> list[dict]:
    """Ищет адреса всех поддерживаемых сетей в тексте QR-кода."""
    out: list[dict] = []
    seen: set[str] = set()

    def push(f: dict | None) -> None:
        if f and f["value"] not in seen:
            seen.add(f["value"])
            out.append(f)

    for m in ETH_TOKEN_RE.finditer(text):
        push(_classify_eth(m.group(0)))

    for m in SEGWIT_TOKEN_RE.finditer(text):
        push(_classify_segwit(m.group(0)))

    for m in CASHADDR_TOKEN_RE.finditer(text):
        push(_classify_cashaddr(m.group(0)))

    for m in B58_TOKEN_RE.finditer(text):
        token = m.group(0)
        hit = _classify_base58(token)
        if hit:
            push(hit)
            continue
        push(_classify_xrp(token) or _classify_sol(token))

    return out


# --- Публичное API: деривация ---------------------------------------------------------

def _secret_int_from_value(f: dict) -> int | None:
    """Достаёт приватный ключ (int) из находки wif/mini/hex."""
    t = f.get("type", "")
    try:
        if t in ("wif_compressed", "wif_uncompressed"):
            value = f.get("value", "")
            version, payload = b58decode_check(value)
            if version != 0x80:
                return None
            body = payload
            if len(body) == 33 and body[-1] == 0x01:
                body = body[:-1]
            if len(body) != 32:
                return None
            return int.from_bytes(body, "big")
        if t == "mini_private_key":
            import hashlib
            return int.from_bytes(hashlib.sha256(f["value"].encode("ascii")).digest(), "big")
        if t == "hex_private_key":
            return int.from_bytes(bytes.fromhex(f["value"]), "big")
    except Exception:  # noqa: BLE001
        return None
    return None


def addresses_for_secret(secret: int) -> dict[str, str]:
    """Адреса всех поддерживаемых сетей из приватного ключа secp256k1."""
    pub_c = crypto.pubkey_bytes(secret, compressed=True)
    pub_u = crypto.pubkey_bytes(secret, compressed=False)
    h160c = crypto.hash160(pub_c)
    h160u = crypto.hash160(pub_u)
    return {
        "btc_legacy": b58check_encode(0x00, h160c),
        "btc_legacy_uncompressed": b58check_encode(0x00, h160u),
        "btc_taproot": crypto.taproot_address(pub33=pub_c),
        "ltc": b58check_encode(0x30, h160c),
        "doge": b58check_encode(0x1E, h160c),
        "dash": b58check_encode(0x4C, h160c),
        "eth": crypto.eth_address_from_pubkey(pub_u),
    }


def addresses_for_mnemonic(mnemonic: str, passphrase: str = "") -> dict[str, str]:
    """Стандартные адреса BIP44/BIP84/BIP86 для валидной BIP39-фразы.

    btc_legacy   m/44'/0'/0'/0/0   (1...)
    btc_segwit   m/84'/0'/0'/0/0   (bc1q...)
    btc_taproot  m/86'/0'/0'/0/0   (bc1p...)
    ltc          m/44'/2'/0'/0/0   (L...)
    ltc_segwit   m/84'/2'/0'/0/0   (ltc1...)
    doge         m/44'/3'/0'/0/0   (D...)
    dash         m/44'/5'/0'/0/0   (X...)
    eth          m/44'/60'/0'/0/0  (0x...)
    """
    seed = crypto.bip39_seed(mnemonic, passphrase)
    paths = {
        "btc_legacy": ("m/44'/0'/0'/0/0", "btc"),
        "btc_segwit": ("m/84'/0'/0'/0/0", "bc_segwit"),
        "btc_taproot": ("m/86'/0'/0'/0/0", "bc_taproot"),
        "ltc": ("m/44'/2'/0'/0/0", "ltc"),
        "ltc_segwit": ("m/84'/2'/0'/0/0", "ltc_segwit"),
        "doge": ("m/44'/3'/0'/0/0", "doge"),
        "dash": ("m/44'/5'/0'/0/0", "dash"),
        "eth": ("m/44'/60'/0'/0/0", "eth"),
    }
    out: dict[str, str] = {}
    for key, (path, kind) in paths.items():
        try:
            secret = int.from_bytes(crypto.bip32_derive(seed, path), "big")
            pub_c = crypto.pubkey_bytes(secret, compressed=True)
            if kind == "btc":
                out[key] = b58check_encode(0x00, crypto.hash160(pub_c))
            elif kind == "bc_segwit":
                out[key] = crypto.p2wpkh_address(pub_c, "bc")
            elif kind == "bc_taproot":
                out[key] = crypto.taproot_address(pub33=pub_c)
            elif kind == "ltc":
                out[key] = b58check_encode(0x30, crypto.hash160(pub_c))
            elif kind == "ltc_segwit":
                out[key] = crypto.p2wpkh_address(pub_c, "ltc")
            elif kind == "doge":
                out[key] = b58check_encode(0x1E, crypto.hash160(pub_c))
            elif kind == "dash":
                out[key] = b58check_encode(0x4C, crypto.hash160(pub_c))
            elif kind == "eth":
                pub_u = crypto.pubkey_bytes(secret, compressed=False)
                out[key] = crypto.eth_address_from_pubkey(pub_u)
        except Exception:  # noqa: BLE001 — не роняем скан из-за одной сети
            continue
    return out


def attach_addresses(findings: list[dict]) -> None:
    """Дополняет находки ключей и валидных сидов словарём адресов (на месте)."""
    for f in findings:
        t = f.get("type", "")
        try:
            if t in ("wif_compressed", "wif_uncompressed", "mini_private_key", "hex_private_key"):
                secret = _secret_int_from_value(f)
                if secret is not None:
                    f["addresses"] = addresses_for_secret(secret)
            elif t.startswith(("bip39_seed_phrase", "seedqr")) and f.get("valid_checksum"):
                f["addresses"] = addresses_for_mnemonic(f["value"])
        except Exception:  # noqa: BLE001 — деривация не должна ломать скан
            continue
