#!/usr/bin/env python3
"""Генерация тестовых изображений с QR-кодами + проверка движка WebCryptoScan."""
import hashlib
import random
import sys
from pathlib import Path

import numpy as np
import qrcode
import cv2
from PIL import Image

sys.path.insert(0, "/home/z/my-project/mini-services/scanner-service")

OUT = Path("/home/z/my-project/testdata")
OUT.mkdir(exist_ok=True)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
WORDS = Path("/home/z/my-project/mini-services/scanner-service/data/bip39_english.txt").read_text().split()


def make_qr(text: str) -> Image.Image:
    return qrcode.make(text).convert("RGB")


def gen_valid_mnemonic(n=12, seed=b"seed-a"):
    ent_len = (n * 11 - n * 11 // 33) // 8
    ent = hashlib.sha256(seed).digest()[:ent_len]
    bits = bin(int.from_bytes(ent, "big"))[2:].zfill(ent_len * 8)
    h = bin(int.from_bytes(hashlib.sha256(ent).digest(), "big"))[2:].zfill(256)
    bits += h[: n * 11 // 33]
    return " ".join(WORDS[int(bits[i * 11 : (i + 1) * 11], 2)] for i in range(n))


def break_checksum(mn):
    ws = mn.split()
    for w in WORDS[::-1]:
        if w == ws[-1]:
            continue
        cand = " ".join(ws[:-1] + [w])
        idx = [WORDS.index(x) for x in cand.split()]
        bits = "".join(f"{i:011b}" for i in idx)
        cs = len(idx) * 11 // 33
        ent = int(bits[: len(idx) * 11 - cs], 2).to_bytes((len(idx) * 11 - cs) // 8, "big")
        hb = bin(int.from_bytes(hashlib.sha256(ent).digest(), "big"))[2:].zfill(256)
        if hb[:cs] != bits[len(idx) * 11 - cs :]:
            return cand
    raise RuntimeError


def find_mini_key():
    while True:
        code = "S" + "".join(random.choice(B58) for _ in range(21))
        if hashlib.sha256((code + "?").encode()).digest()[0] == 0:
            return code


def save(img, name):
    img.save(OUT / name)
    print("saved", name, img.size)


def main():
    from pycoin.symbols.btc import network

    hexkey = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
    key = network.parse.private_key(hexkey)
    wif_c = key.wif(is_compressed=True)
    wif_u = key.wif(is_compressed=False)
    print("WIF compressed:", wif_c)
    print("WIF uncompressed:", wif_u)

    mn12 = gen_valid_mnemonic(12, b"seed-a")
    mn24 = gen_valid_mnemonic(24, b"seed-b")
    bad_mn = break_checksum(mn12)
    mini = find_mini_key()
    print("mnemonic 12:", mn12)
    print("mnemonic 24:", mn24)
    print("bad mnemonic:", bad_mn)
    print("mini key:", mini)

    # 1. Простой WIF
    save(make_qr(wif_c), "01_wif.png")
    # 2. Валидная сид-фраза 12
    save(make_qr(mn12), "02_seed12.png")
    # 3. Сид-фраза 24
    save(make_qr(mn24), "03_seed24.png")
    # 4. Битая контрольная сумма
    save(make_qr(bad_mn), "04_bad_seed.png")
    # 5. URL — не должен дать находок
    save(make_qr("https://example.com/bitcoin"), "05_url.png")
    # 6. Mini-ключ
    save(make_qr(mini), "06_mini.png")
    # 7. WIF uncompressed + текст вокруг
    save(make_qr(f"Wallet backup\nPrivate key: {wif_u}\nDo not share!"), "07_wif_text.png")
    # 8. Мелкий QR на большом холсте (тест upscale)
    qr = make_qr(wif_c).resize((60, 60))
    canvas = Image.new("RGB", (800, 600), "white")
    canvas.paste(qr, (370, 270))
    save(canvas, "08_tiny.png")
    # 9. Зашумлённый малоконтрастный QR (тест CLAHE/Otsu)
    arr = np.array(make_qr(wif_c).resize((240, 240))).astype(np.float32)
    arr = arr * 0.35 + 90  # низкий контраст
    noise = np.random.default_rng(7).normal(0, 14, arr.shape)
    arr = np.clip(arr + noise, 0, 255).astype(np.uint8)
    save(Image.fromarray(arr), "09_noisy.png")
    # 10. Два QR на одном изображении
    canvas = Image.new("RGB", (520, 280), "white")
    canvas.paste(make_qr(wif_c).resize((240, 240)), (10, 20))
    canvas.paste(make_qr(mn12).resize((240, 240)), (270, 20))
    save(canvas, "10_multi.png")

    print("\n--- Проверка движка ---")
    from engine.decoder import decode_image, open_image
    from engine.detectors import analyze_text, get_bip39

    bip39 = get_bip39()
    opts = dict(preprocess=True, detect_wif=True, detect_mini=True, detect_hex=True, detect_seed=True)
    for p in sorted(OUT.glob("*.png")):
        img = open_image(str(p))
        results = decode_image(img, use_preprocess=True)
        findings = []
        for r in results:
            findings += analyze_text(r.data, opts, bip39)
        summary = [(f["type"], f["value"][:40]) for f in findings]
        eng = [(r.engine, r.variant) for r in results]
        print(f"{p.name:16s} qr={len(results)} {eng} findings={summary}")


if __name__ == "__main__":
    main()
