#!/usr/bin/env python3
"""Генератор тестовых материалов для «обычных фото + строковых значений».

Создаёт /home/z/my-project/testdata/textscan_test/:
  * фото с напечатанным WIF (без QR)
  * фото с сид-фразой BIP39 (без QR)
  * «скриншот» с мультивалютными адресами
  * JPEG с WIF, спрятанным в EXIF ImageDescription
  * docs_keys.txt — текстовый файл с ключами/сидами/адресами
  * docs_binary.bin — бинарник со строкой (аналог strings)

И прогоняет OCR + analyze_text напрямую, без сервера.
"""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, "/home/z/my-project/mini-services/scanner-service")

from PIL import Image, ImageDraw, ImageFont

from engine.addresses import addresses_for_secret
from engine.crypto import b58check_encode
from engine.detectors import analyze_text, entropy_to_mnemonic, get_bip39
from engine.textscan import boxes_for_values, compact_lines_text, exif_text_from_path, ocr_base58_repair, ocr_image_lines, ocr_normalize

OUT = Path("/home/z/my-project/testdata/textscan_test")
OUT.mkdir(parents=True, exist_ok=True)

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"


def make_secret(tag: str) -> int:
    return int.from_bytes(hashlib.sha256(tag.encode()).digest(), "big") % (N - 1) + 1


secret1 = make_secret("mrrobotqr-textscan-wif")
secret_b32 = secret1.to_bytes(32, "big")
WIF = b58check_encode(0x80, secret_b32 + b"\x01")
HEX64 = secret_b32.hex()

entropy = hashlib.sha256(b"mrrobotqr-textscan-seed").digest()[:16]
SEED12 = " ".join(entropy_to_mnemonic(entropy, get_bip39()))

addresses = addresses_for_secret(secret1)
BTC, ETH, DOGE = addresses["btc_legacy"], addresses["eth"], addresses["doge"]

print(f"WIF   : {WIF}")
print(f"SEED12: {SEED12}")
print(f"BTC   : {BTC}")
print(f"ETH   : {ETH}")


def paper(path, bg, fg, lines, mono_from=1):
    w, h = 1440, 860
    img = Image.new("RGB", (w, h), bg)
    d = ImageDraw.Draw(img)
    f1 = ImageFont.truetype(FONT_B, 44)
    fm = ImageFont.truetype(MONO, 34)
    ft = ImageFont.truetype(FONT, 30)
    y = 90
    for i, ln in enumerate(lines):
        f = fm if i >= mono_from else f1
        if isinstance(ln, tuple):
            d.text((80, y), ln[0], fill=fg, font=ft)
            y += 52
            continue
        d.text((80, y), ln, fill=fg, font=f)
        y += 66
    img.save(path)
    print(f"  ok {path.name}")


print("Генерация изображений...")
paper(OUT / "01_wif_photo.png", "#f3ecdd", "#1b1b1b", [
    "PAPER WALLET - COLD STORAGE",
    "Private key (WIF):",
    WIF,
    "Keep this offline. Do not share.",
])
words = SEED12.split()
paper(OUT / "02_seed_photo.png", "#ffffff", "#111111", [
    "Wallet recovery phrase (12 words):",
    " ".join(words[0:4]),
    " ".join(words[4:8]),
    " ".join(words[8:12]),
    "Write it down. Never type it online.",
])
paper(OUT / "03_addr_shot.png", "#12121a", "#d8e4ff", [
    "Deposit addresses (multi-coin)",
    BTC,
    ETH,
    DOGE,
    "Created 2024-01-15, wallet v0.9",
])

# --- JPEG с секретом в EXIF -----------------------------------------------------
img = Image.new("RGB", (900, 620), "#204030")
d = ImageDraw.Draw(img)
d.ellipse((300, 160, 600, 460), fill="#70c090")
exif = Image.Exif()
exif[270] = f"backup: {WIF}"  # ImageDescription
img.save(OUT / "04_exif_secret.jpg", exif=exif.tobytes())
print("  ok 04_exif_secret.jpg")

# --- Текстовый файл --------------------------------------------------------------
(OUT / "docs_keys.txt").write_text(
    "old backup from 2024\n"
    f"wif: {WIF}\n"
    f"hex: {HEX64}\n"
    f"seed: {SEED12}\n"
    f"btc: {BTC}\n"
    f"eth: {ETH}\n",
    encoding="utf-8",
)
print("  ok docs_keys.txt")

# --- Бинарник со спрятанной строкой ----------------------------------------------
import os

blob = os.urandom(3000) + b"leaked hex private key: " + HEX64.encode() + os.urandom(2500)
(OUT / "docs_binary.bin").write_bytes(blob)
print("  ok docs_binary.bin")

# --- Проверка EXIF ----------------------------------------------------------------
got = exif_text_from_path(OUT / "04_exif_secret.jpg")
assert WIF in got, f"EXIF не прочитался: {got!r}"
print(f"EXIF ok: {got!r}")

# --- OCR + детекторы на трёх фото -------------------------------------------------
bip39 = get_bip39()
for name in ("01_wif_photo.png", "02_seed_photo.png", "03_addr_shot.png"):
    img = Image.open(OUT / name)
    lines = ocr_image_lines(img)
    text = ocr_normalize("\n".join(ln["text"] for ln in lines))
    text = text + "\n" + compact_lines_text(text)
    findings = analyze_text(text, {}, bip39)
    vals = {f["value"] for f in findings}
    for f in ocr_base58_repair(text):
        if f["value"] not in vals:
            findings.append(f)
    boxes = boxes_for_values([f["value"] for f in findings], lines)
    print(f"\n{name}: строк OCR={len(lines)}, находок={len(findings)}")
    for f in findings:
        print(f"   {f['type']:28s} src_box={boxes.get(f['value'])} :: {f['value'][:52]}")
    if not findings:
        print("   OCR TEXT:", repr(text[:300]))

print("\nГотово.")
