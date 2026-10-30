#!/usr/bin/env python3
"""Тесты мультивалютного ядра на публично известных векторах."""
import base64
import hashlib
import sys
import time

sys.path.insert(0, "/home/z/my-project/mini-services/scanner-service")

from engine import crypto, addresses  # noqa: E402

FAIL = 0


def check(name, got, want):
    global FAIL
    ok = got == want
    if not ok:
        FAIL += 1
    print(f"{'OK ' if ok else 'FAIL'} {name}: got={got!r} want={want!r}")


def check_true(name, cond, extra=""):
    global FAIL
    if not cond:
        FAIL += 1
    print(f"{'OK ' if cond else 'FAIL'} {name} {extra if not cond else ''}")


# --- secp256k1: pubkey(1) ---
check("pub_c(1)", crypto.pubkey_bytes(1, True).hex().upper(),
      "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
check("pub_u(1) head", crypto.pubkey_bytes(1, False).hex()[:10], "0479be667e")

# --- Base58Check адреса для privkey=1 ---
a_c = crypto.base58_address(0x00, crypto.hash160(crypto.pubkey_bytes(1, True)))
a_u = crypto.base58_address(0x00, crypto.hash160(crypto.pubkey_bytes(1, False)))
check("btc addr compressed", a_c, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
check("btc addr uncompressed", a_u, "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")

# --- WIF для privkey=1 (известные значения) ---
wif_c = crypto.b58check_encode(0x80, b"\x00" * 31 + b"\x01" + b"\x01")
check("wif compressed(1)", wif_c, "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")
wif_u = crypto.b58check_encode(0x80, b"\x00" * 31 + b"\x01")
check("wif uncompressed(1)", wif_u, "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")

# --- ETH: keccak + EIP-55 ---
check("eth addr(1)", crypto.eth_address_from_pubkey(crypto.pubkey_bytes(1, False)),
      "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf")
eip55_vectors = [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
]
for v in eip55_vectors:
    check_true(f"eip55 valid {v[:14]}", crypto.eth_check(v))
    check_true(f"eip55 lower ok {v[:14]}", crypto.eth_check(v.lower()))
    expected = crypto.eth_checksum(v.lower())
    broken = None
    for i, c in enumerate(expected[2:]):
        if c.isalpha():
            cand = expected[:2 + i] + (c.lower() if c.isupper() else c.upper()) + expected[3 + i:]
            if cand != expected and cand[2:] != cand[2:].lower():
                broken = cand
                break
    check_true(f"eip55 broken rejected {v[:14]}", broken is not None and not crypto.eth_check(broken))

# --- Bech32/Bech32m ---
d = crypto.segwit_decode("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
check_true("bip173 vector", d is not None and d[0] == 0 and len(d[1]) == 20, str(d))
check_true("bech32m vector",
           crypto.segwit_decode("bc", "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
           is not None)
check_true("bech32 invalid rejected", crypto.segwit_decode("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5") is None)

# --- CashAddr ---
d = crypto.cashaddr_decode("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a")
check_true("cashaddr vector", d is not None and d[0] == 0 and len(d[1]) == 20, str(d))
d2 = crypto.cashaddr_decode("bitcoincash:qqs3kax2g6r0s8ha54jpwelusnh3dkh7pvu23rzrru")
check_true("cashaddr vector (reference.cash)", d2 is not None and len(d2[1]) == 20, str(d2))

# --- XRP ---
check_true("xrp vector", addresses._classify_xrp("r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59") is not None)

# --- BIP39 seed + BIP32 деривация (abandon*11 about, passphrase "") ---
mn = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
seed = crypto.bip39_seed(mn)
check("bip39 seed", seed.hex(),
      "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")

t0 = time.time()
derived = addresses.addresses_for_mnemonic(mn)
dt = time.time() - t0
check("bip44 btc legacy", derived.get("btc_legacy", ""), "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA")
check("bip84 btc segwit", derived.get("btc_segwit", ""), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
check("bip44 eth", derived.get("eth", "").lower(), "0x9858effd232b4033e47d90003d41ec34ecaeda94")
print(f"деривация 8 адресов за {dt:.2f}s")
for k, v in derived.items():
    print(f"   {k:14s} {v}")

# --- addresses_for_secret(1) ---
sec = addresses.addresses_for_secret(1)
check("secret->btc", sec["btc_legacy"], "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
check("secret->eth", sec["eth"], "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf")
check_true("secret->doge D", sec["doge"].startswith("D"), sec["doge"])
check_true("secret->ltc L", sec["ltc"].startswith("L"), sec["ltc"])
check_true("secret->dash X", sec["dash"].startswith("X"), sec["dash"])
check_true("secret->taproot bc1p", sec["btc_taproot"].startswith("bc1p"), sec["btc_taproot"])
# round-trip taproot
check_true("taproot roundtrip", crypto.segwit_decode("bc", sec["btc_taproot"]) is not None)

# --- Детектор в тексте ---
sol_raw = hashlib.sha256(b"sol-test").digest()
num = int.from_bytes(sol_raw, "big")
sol = ""
while num:
    num, r = divmod(num, 58)
    sol = crypto.BASE58_ALPHABET[r] + sol
print(f"SOL token: {sol} ({len(sol)})")

# реальные адреса для текста считаем из privkey=1 (гарантированно валидные)
h160 = crypto.hash160(crypto.pubkey_bytes(1, True))
ltc_addr = crypto.base58_address(0x30, h160)
doge_addr = crypto.base58_address(0x1E, h160)
dash_addr = crypto.base58_address(0x4C, h160)

text = (
    f" donate: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH or 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy "
    f"segwit bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 taproot bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0 "
    f"eth 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed ethbad 0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed "
    f"ltc {ltc_addr} doge {doge_addr} dash {dash_addr} "
    f" xrp r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59 trx TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t "
    f"bch bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a sol {sol} "
    f"wif KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn "
)
found = addresses.detect_addresses_in_text(text)
types = {}
for f in found:
    types[f["type"]] = f["value"]
    print(f"   {f['type']:24s} {f['value']}")
check_true("btc_p2pkh detected", "address_btc_p2pkh" in types)
check_true("btc_p2sh detected", "address_btc_p2sh" in types)
check_true("btc_segwit detected", "address_btc_segwit" in types)
check_true("btc_taproot detected", "address_btc_taproot" in types)
check_true("eth detected", "address_eth" in types)
check_true("eth bad rejected", len([f for f in found if f["type"] == "address_eth"]) == 1)
check_true("wif not address", not any("KwDiBf89" in f["value"] for f in found))
check_true("trx detected", "address_trx" in types)
check_true("xrp detected", "address_xrp" in types)
check_true("cashaddr detected", "address_bch_cashaddr" in types)
check_true("sol detected", "address_sol" in types)
check_true("ltc detected", "address_ltc_p2pkh" in types)
check_true("doge detected", "address_doge" in types)

print(f"\n{'=' * 40}\nИТОГ: {'ВСЕ ТЕСТЫ ПРОШЛИ' if FAIL == 0 else f'ПРОВАЛЕНО: {FAIL}'}")
sys.exit(1 if FAIL else 0)
