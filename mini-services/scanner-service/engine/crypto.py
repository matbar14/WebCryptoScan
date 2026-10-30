#!/usr/bin/env python3
"""
MrRobotQR 2.0 — криптографическое ядро для мультивалютных адресов.

Всё работает офлайн и без внешних зависимостей (только стандартная библиотека;
keccak256 при наличии берётся из pycryptodome):

  * secp256k1 (чистый Python, якобианы)  — публичные ключи, TapTweak
  * BIP32 (master + CKDpriv)             — деривация путей из BIP39-сида
  * BIP39 seed (PBKDF2-HMAC-SHA512)
  * Base58Check (алфавит Bitcoin и Ripple/XRP)
  * Bech32/Bech32m (BIP173/350)          — bc1q / bc1p / ltc1
  * CashAddr (BCH)                       — bitcoincash:q...
  * EIP-55 (keccak-256)                  — чек-сумма ETH-адресов
"""

from __future__ import annotations

import hashlib
import hmac

# --- secp256k1 ------------------------------------------------------------------

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

_INF = (0, 1, 0)  # нейтральный элемент в якобианских координатах


def _jac_double(pt: tuple[int, int, int]) -> tuple[int, int, int]:
    X1, Y1, Z1 = pt
    if not Z1:
        return _INF
    A = X1 * X1 % P
    B = Y1 * Y1 % P
    C = B * B % P
    D = 2 * ((X1 + B) * (X1 + B) - A - C) % P
    E = 3 * A % P
    F = E * E % P
    X3 = (F - 2 * D) % P
    Y3 = (E * (D - X3) - 8 * C) % P
    Z3 = 2 * Y1 * Z1 % P
    return (X3, Y3, Z3)


def _jac_add(p: tuple[int, int, int], q: tuple[int, int, int]) -> tuple[int, int, int]:
    if not p[2]:
        return q
    if not q[2]:
        return p
    X1, Y1, Z1 = p
    X2, Y2, Z2 = q
    Z1Z1 = Z1 * Z1 % P
    Z2Z2 = Z2 * Z2 % P
    U1 = X1 * Z2Z2 % P
    U2 = X2 * Z1Z1 % P
    S1 = Y1 * Z2 * Z2Z2 % P
    S2 = Y2 * Z1 * Z1Z1 % P
    if U1 == U2:
        return _jac_double(p) if S1 == S2 else _INF
    H = (U2 - U1) % P
    R = (S2 - S1) % P
    HH = H * H % P
    HHH = H * HH % P
    V = U1 * HH % P
    X3 = (R * R - HHH - 2 * V) % P
    Y3 = (R * (V - X3) - S1 * HHH) % P
    Z3 = Z1 * Z2 * H % P
    return (X3, Y3, Z3)


def _jac_mul(k: int, pt: tuple[int, int, int] = (GX, GY, 1)) -> tuple[int, int, int]:
    r = _INF
    p = pt
    while k:
        if k & 1:
            r = _jac_add(r, p)
        p = _jac_double(p)
        k >>= 1
    return r


def _jac_to_affine(pt: tuple[int, int, int]) -> tuple[int, int]:
    X, Y, Z = pt
    if not Z:
        raise ValueError("точка на бесконечности")
    zinv = pow(Z, -1, P)
    zinv2 = zinv * zinv % P
    return X * zinv2 % P, Y * zinv2 * zinv % P


def check_secret(secret: int) -> None:
    if not (0 < secret < N):
        raise ValueError("ключ вне диапазона secp256k1")


def pubkey_bytes(secret: int, compressed: bool = True) -> bytes:
    """Публичный ключ secp256k1 из приватного (int)."""
    check_secret(secret)
    x, y = _jac_to_affine(_jac_mul(secret))
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _point_from_x(x: int, odd: bool) -> tuple[int, int]:
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if (y * y) % P != y2:
        raise ValueError("x не лежит на кривой")
    if bool(y & 1) != odd:
        y = P - y
    return x, y


def tagged_hash(tag: str, data: bytes) -> bytes:
    t = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(t + t + data).digest()


def taproot_xonly(secret: int | None = None, pub33: bytes | None = None) -> bytes:
    """X-only выходной ключ P2TR (BIP86 tweak) из приватного ключа или pubkey."""
    if pub33 is None:
        if secret is None:
            raise ValueError("нужен secret или pub33")
        pub33 = pubkey_bytes(secret, compressed=True)
    x, y = _point_from_x(int.from_bytes(pub33[1:], "big"), bool(pub33[0] & 1))
    t = int.from_bytes(tagged_hash("TapTweak", pub33[1:]), "big") % N
    Qx, _ = _jac_to_affine(_jac_add((x, y, 1), _jac_mul(t)))
    return Qx.to_bytes(32, "big")


# --- Хеши ------------------------------------------------------------------------

def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data)) — стандартный хеш адресов."""
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


try:
    from Crypto.Hash import keccak as _keccak  # pycryptodome

    def keccak256(data: bytes) -> bytes:
        return _keccak.new(digest_bits=256, data=data).digest()

except ImportError:  # pragma: no cover — pycryptodome есть в requirements.txt

    def keccak256(data: bytes) -> bytes:  # noqa: F811
        raise RuntimeError(
            "keccak256 требует pycryptodome (pip install pycryptodome)"
        )


# --- Base58Check ------------------------------------------------------------------

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# Алфавит Ripple/XRP: порядок символов отличается
XRP_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

BASE58_INDEX = {a: {c: i for i, c in enumerate(ab)} for a, ab in
                (("btc", BASE58_ALPHABET), ("xrp", XRP_ALPHABET))}


def is_base58(s: str, alphabet: str = BASE58_ALPHABET) -> bool:
    idx = BASE58_INDEX["xrp"] if alphabet is XRP_ALPHABET else BASE58_INDEX["btc"]
    return bool(s) and all(c in idx for c in s)


def b58decode_check(s: str, alphabet: str = BASE58_ALPHABET) -> tuple[int, bytes]:
    """Base58Check -> (version, payload); ValueError при неверной checksum."""
    idx = BASE58_INDEX["xrp"] if alphabet is XRP_ALPHABET else BASE58_INDEX["btc"]
    if not s or not all(c in idx for c in s):
        raise ValueError("не Base58")
    num = 0
    for c in s:
        num = num * 58 + idx[c]
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip(alphabet[0]))
    raw = b"\x00" * pad + raw
    if len(raw) < 5:
        raise ValueError("слишком коротко")
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        raise ValueError("неверная контрольная сумма")
    return payload[0], payload[1:]


def b58check_encode(version: int, payload: bytes, alphabet: str = BASE58_ALPHABET) -> str:
    raw = bytes([version]) + payload
    checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    num = int.from_bytes(raw + checksum, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = alphabet[rem] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return alphabet[0] * pad + out


# --- Bech32 / Bech32m (BIP173 / BIP350) --------------------------------------------

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3
_BECH32_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _bech32_polymod(values: list[int]) -> int:
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= _BECH32_GEN[i]
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits: int, tobits: int, pad: bool = True) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def segwit_encode(hrp: str, witver: int, witprog: bytes) -> str:
    """Bech32 (witver=0) или Bech32m (witver>=1) адрес из witness-программы."""
    const = 1 if witver == 0 else BECH32M_CONST
    data = _convertbits(list(witprog), 8, 5)
    values = _hrp_expand(hrp) + [witver] + data
    mod = _bech32_polymod(values + [0] * 6) ^ const
    checksum = [(mod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in [witver] + data + checksum)


def segwit_decode(hrp: str, addr: str) -> tuple[int, bytes] | None:
    """Проверка segwit-адреса; возвращает (witver, witprog) или None."""
    if not addr or addr != addr.lower() and addr != addr.upper():
        return None
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        return None
    if addr[:pos] != hrp:
        return None
    try:
        data = [BECH32_CHARSET.index(c) for c in addr[pos + 1:]]
    except ValueError:
        return None
    if not data:
        return None
    witver = data[0]
    if witver > 16:
        return None
    const = 1 if witver == 0 else BECH32M_CONST
    if _bech32_polymod(_hrp_expand(hrp) + data) != const:
        return None
    witprog = bytes(_convertbits(data[1:-6], 5, 8, False))
    if witver == 0 and len(witprog) not in (20, 32):
        return None
    if 1 <= witver <= 16 and len(witprog) not in (2, 20, 32):
        return None
    return witver, witprog


# --- CashAddr (Bitcoin Cash) --------------------------------------------------------

_CASH_GEN = (0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470)


def _cash_polymod(values: list[int]) -> int:
    c = 1
    for d in values:
        c0 = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ d
        for i, g in enumerate(_CASH_GEN):
            if (c0 >> i) & 1:
                c ^= g
    return c ^ 1  # по спецификации CashAddr


def cashaddr_decode(addr: str) -> tuple[int, bytes] | None:
    """CashAddr -> (type_bit, hash) или None. Префикс обязателен или bitcoincash."""
    addr = addr.strip()
    if ":" in addr:
        prefix, body = addr.split(":", 1)
    else:
        prefix, body = "bitcoincash", addr
    prefix = prefix.lower()
    if prefix not in ("bitcoincash", "bchtest", "bchreg") or not body:
        return None
    if body != body.lower() and body != body.upper():
        return None
    body = body.lower()
    if not (30 <= len(body) <= 120):
        return None
    try:
        data = [BECH32_CHARSET.index(c) for c in body]
    except ValueError:
        return None
    if _cash_polymod([ord(c) & 31 for c in prefix] + [0] + data) != 0:
        return None
    payload = data[:-8]
    if len(payload) < 2:
        return None
    # добивочные биты последнего символа должны быть нулями
    total_bits = len(payload) * 5
    pad_bits = total_bits - (total_bits // 8) * 8
    if pad_bits and (payload[-1] & ((1 << pad_bits) - 1)):
        return None
    converted = _convertbits(payload, 5, 8, False)
    if len(converted) < 2:
        return None
    ver8 = converted[0]
    if ver8 & 0x0F:  # 4 младших бита версии зарезервированы (нули)
        return None
    type_bit = ver8 >> 7
    size_code = (ver8 >> 3) & 0x07
    expected_len = (20, 24, 28, 32, 40, 48, 64)[size_code]
    h = bytes(converted[1:])
    if len(h) != expected_len:
        return None
    return type_bit, h


# --- EIP-55 (Ethereum) ---------------------------------------------------------------

def eth_checksum(addr_hex: str) -> str:
    """EIP-55 чек-сумма для 0x-адреса (вход: 0x... или 40 hex-символов)."""
    a = addr_hex.lower().removeprefix("0x")
    digest = keccak256(a.encode("ascii")).hex()
    return "0x" + "".join(
        c.upper() if int(digest[i], 16) >= 8 else c for i, c in enumerate(a)
    )


def eth_check(addr_hex: str) -> bool:
    """True, если 40 hex-символов согласуются с EIP-55 (или в нижнем регистре)."""
    a = addr_hex.removeprefix("0x")
    if len(a) != 40 or any(c not in "0123456789abcdefABCDEF" for c in a):
        return False
    if a == a.lower():
        return True
    return eth_checksum("0x" + a.lower()) == "0x" + a


# --- Адреса --------------------------------------------------------------------------

def base58_address(version: int, h160: bytes, alphabet: str = BASE58_ALPHABET) -> str:
    return b58check_encode(version, h160, alphabet)


def p2wpkh_address(pub33: bytes, hrp: str = "bc") -> str:
    return segwit_encode(hrp, 0, hash160(pub33))


def taproot_address(pub33: bytes | None = None, secret: int | None = None, hrp: str = "bc") -> str:
    return segwit_encode(hrp, 1, taproot_xonly(secret=secret, pub33=pub33))


def eth_address_from_pubkey(pub65: bytes) -> str:
    """ETH-адрес из несжатого pubkey (65 байт, 0x04...)."""
    if len(pub65) != 65 or pub65[0] != 0x04:
        raise ValueError("нужен несжатый pubkey (65 байт)")
    return eth_checksum("0x" + keccak256(pub65[1:])[-20:].hex())


# --- BIP39 / BIP32 ---------------------------------------------------------------------

HARDENED = 0x80000000


def bip39_seed(mnemonic: str, passphrase: str = "") -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha512", mnemonic.encode("utf-8"), ("mnemonic" + passphrase).encode("utf-8"), 2048
    )


def bip32_master(seed: bytes) -> tuple[bytes, bytes]:
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(I[:32], "big")
    if not (0 < k < N):
        raise ValueError("некорректный мастер-ключ BIP32")
    return I[:32], I[32:]


def _ckd_priv(k: bytes, c: bytes, index: int) -> tuple[bytes, bytes]:
    if index >= HARDENED:
        data = b"\x00" + k + index.to_bytes(4, "big")
    else:
        data = pubkey_bytes(int.from_bytes(k, "big"), compressed=True) + index.to_bytes(4, "big")
    I = hmac.new(c, data, hashlib.sha512).digest()
    tweak = int.from_bytes(I[:32], "big")
    if tweak >= N:
        raise ValueError("некорректный индекс BIP32")
    kn = (tweak + int.from_bytes(k, "big")) % N
    if kn == 0:
        raise ValueError("некорректный индекс BIP32 (нулевая дочерняя)")
    return kn.to_bytes(32, "big"), I[32:]


def bip32_derive(seed: bytes, path: str) -> bytes:
    """Приватный ключ (32 байта) по пути BIP32, например m/44'/0'/0'/0/0."""
    k, c = bip32_master(seed)
    for part in path.split("/"):
        part = part.strip()
        if not part or part == "m":
            continue
        hard = part.endswith(("'", "H", "h"))
        idx = int(part.rstrip("'Hh"))
        if hard:
            idx += HARDENED
        k, c = _ckd_priv(k, c, idx)
    return k
