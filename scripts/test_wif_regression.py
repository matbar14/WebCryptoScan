#!/usr/bin/env python3
"""Регрессия: WIF-ключи в тексте и OCR-repair путь.

Проверяет сценарий пользователя: «тест с WIF L51…p9N не добавился».
Ключ пользователя — обрезанный (44 симв. вместо 52), движок обязан его
отклонять. Полный ключ (52 симв.) обязан находиться. Заодно закрывает
баг ocr_base58_repair: валидные токены отбрасывались из-за путаницы
между seen (обработанные кандидаты) и выводом.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "mini-services" / "scanner-service"
sys.path.insert(0, str(ROOT))

from engine.bitcoin import validate_wif  # noqa: E402
from engine.textscan import ocr_base58_repair  # noqa: E402
from engine.detectors import analyze_text, get_bip39  # noqa: E402

TRUNC = "L51Uc2DVUmVXTftYY3oqzbf5UkTnHgNk4LKsrKJadp9N"          # 44 симв. — обрезок пользователя
FULL = "L51Uc2DVUmVXTftYY3oqzbf5UkTnHgNk4LKsrKJadp9NAyzHqUP1"   # 52 симв. — полный WIF


fails = []


def check(name, cond, extra=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{(' — ' + extra) if extra else ''}")
    if not cond:
        fails.append(name)


print("1) validate_wif:")
f = validate_wif(TRUNC)
check("обрезанный ключ (44 симв.) отклонён", f is None)
f = validate_wif(FULL)
check("полный ключ (52 симв.) валиден", f is not None and f.type == "wif_compressed",
      f.address if f else "")
check("адрес полного ключа", f and f.address == "1CGXL3qxNPEJc38KeMcpLCGor9o3PMrzUB")

print("2) analyze_text (пайплайн текстовых файлов):")
bip39 = get_bip39()
hits = analyze_text(f"wallet key: {TRUNC} end", {"detect_wif": True, "detect_addresses": True}, bip39)
check("обрезанный ключ не даёт находок", len(hits) == 0)
hits = analyze_text(f"wallet key: {FULL} end", {"detect_wif": True, "detect_addresses": True}, bip39)
check("полный ключ найден", any(h["type"] == "wif_compressed" and h["value"] == FULL for h in hits))

print("3) ocr_base58_repair (OCR-путь):")
# чистый валидный WIF в тексте — раньше отбрасывался багом seen/push
hits = ocr_base58_repair(f"PRIVATE KEY\n{FULL}\n")
check("чистый WIF возвращается", any(h["value"] == FULL for h in hits),
      str([h["value"][:20] + "…" for h in hits]))
# побитый OCR символ — восстанавливается (вставляем 'a' — она есть в base58;
# 'l'/'I' не подходят: их в Base58 нет, regex такой токен не возьмёт)
DAMAGED2 = FULL[:10] + "a" + FULL[10:]
hits = ocr_base58_repair(f"key {DAMAGED2} end")
rep = [h for h in hits if h["value"] == FULL and "OCR" in h.get("detail", "")]
check("повреждённый WIF восстановлен", bool(rep), rep[0]["detail"] if rep else "нет")
# обрезок не «чинится» и не находится
hits = ocr_base58_repair(f"key {TRUNC} end")
check("обрезок не даёт находок", not any(TRUNC == h["value"] for h in hits))
check("обрезок не даёт и восстановленных WIF",
      not any(h["type"].startswith("wif") for h in hits))
# дедупликация: один токен дважды
hits = ocr_base58_repair(f"{FULL} и снова {FULL}")
check("дубль не плодится", sum(1 for h in hits if h["value"] == FULL) == 1)

print()
if fails:
    print(f"ПРОВАЛЕНО: {len(fails)} -> {fails}")
    sys.exit(1)
print("ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ")
