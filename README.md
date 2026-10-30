# MrRobotQR 2.0 — веб-панель для сканирования QR-кодов

Модернизированная версия сканера **MrRobotQR**: от связки bash-скриптов 2018 года
(`qrcrawler.py` → `mrrobotqr.sh` → `qr2key.py`) до локальной веб-панели с каскадным
распознаванием QR-кодов, офлайн-валидацией приватных ключей Bitcoin и BIP39 сид-фраз.

> ⚠️ **Назначение.** Инструмент для исследований безопасности и демонстрации того, как
> быстро публичные QR-коды с секретами находятся и вскрываются. Вся валидация выполняется
> **локально, без сетевых запросов** — инструмент ничего не переводит и не выводит средства.
> Не публикуйте QR-коды с приватными ключами и сид-фразами.

---

## Что изменилось по сравнению с оригиналом (10MrRobotQR, 2018)

| Оригинал | MrRobotQR 2.0 |
| --- | --- |
| `zbarlight` (мёртв, не собирается на новых Python) | Каскад: **pyzbar → WeChatQRCode (CV-модель) → OpenCV QRCodeDetector** |
| Один проход по исходной картинке | Препроцессинг: масштабирование, **CLAHE**, **бинаризация Отсу**, адаптивный порог — до 5 попыток на изображение |
| Поиск только WIF-ключей по регулярокам | WIF (compressed/uncompressed), **mini-ключи Casascius**, **hex-ключи**, **BIP39 сид-фразы (12/15/18/21/24)** с проверкой контрольной суммы |
| `requests.get(blockchain.info)` — падает без retry | **Полностью офлайн**: Base58Check, префикс сети, secp256k1, вывод P2PKH-адреса |
| `keylist.txt` + `sort | uniq` | **keylist.txt, seedlist.txt, scan_report.json, scan_report.csv** + веб-интерфейс с галереей |
| Краулер на 3 поисковика одной пачкой | Краулер с **пресетами**, включая пресет «Сид-фразы (BIP39)», отчёт по каждой поисковой системе отдельно |
| Зависимости-пины 2022 года | Python 3.10+, актуальные версии, всё запускается одной командой |

## Архитектура

```
Браузер ── Caddy (XTransformPort) ──► Next.js 16 (:3000)  — интерфейс на русском
                                 └──► Python-сервис (:3031) — движок сканера
                                       ├─ engine/decoder.py   каскад декодирования
                                       ├─ engine/detectors.py WIF / mini / hex / BIP39
                                       ├─ engine/bitcoin.py   офлайн-валидация ключей
                                       ├─ engine/crawler.py   icrawler + пресеты
                                       ├─ engine/reports.py   TXT / JSON / CSV
                                       └─ data/bip39_english.txt  словарь BIP39 (2048 слов)
```

- Python-сервис поднимается **автоматически** вместе с Next.js
  (`src/instrumentation.ts` + резервный роут `GET /api/scanner-boot`).
- Джобы выполняются в фоновых потоках; прогресс, статистика и находки
  сохраняются в `mini-services/scanner-service/jobs/<id>/job.json`.

## Запуск (локально)

```bash
# 1. Системные зависимости
sudo apt install libzbar0          # для pyzbar (Debian/Ubuntu)
# macOS: brew install zbar

# 2. Python-зависимости движка
python3 -m pip install -r mini-services/scanner-service/requirements.txt

# 3. Фронтенд (Next.js 16 + TypeScript)
npm install         # или bun install
npm run dev         # http://localhost:3000

# 4. (опционально) Python-сервис отдельно — иначе он стартует сам
python3 mini-services/scanner-service/server.py   # порт 3031
```

## Возможности интерфейса

- **Источники изображений**: загрузка файлов (drag&drop), папка на сервере
  (например `qrbooty` от старого MrRobotQR), краулер по ключевым словам.
- **Пресеты краулера**: `Bitcoin QR / бумажные кошельки`, `Сид-фразы (BIP39)`,
  `Смешанный` — 8 запросов на пресет, **9 поисковых систем** (Google, Bing,
  Baidu, 360 Поиск, Sogou, DuckDuckGo, Яндекс, Wikimedia Commons, Openverse),
  регулировка числа фото. Ошибки и результат каждой поисковой системы
  показываются отдельно: из дата-центров Google/Bing/Sogou/Яндекс/Wikimedia
  часто блокируются, Baidu и 360 работают стабильно. Скачивание — с
  md5-дедупликацией между движками и проверкой формата/размера.
- **Настройки детекторов**: независимые переключатели WIF / BIP39 / mini / hex,
  тумблер улучшения изображений.
- **Результаты**: прогресс в реальном времени, счётчики, таблица находок
  с копированием значений и адресов, галерея изображений с рамками вокруг QR
  и деталями по клику, история сканирований.
- **Отчёты**: `keylist.txt` (как в оригинале), `seedlist.txt`,
  `scan_report.json`, `scan_report.csv`.

## API Python-сервиса (порт 3031)

| Метод | Путь | Описание |
| --- | --- | --- |
| GET | `/api/health` | состояние сервиса и движков |
| GET | `/api/presets` | пресеты ключевых слов |
| POST | `/api/scan/upload` | multipart: файлы + options |
| POST | `/api/scan/folder` | `{path, options}` |
| POST | `/api/scan/crawl` | `{preset|keyword, engines[], max_num, options}` |
| GET | `/api/jobs` | список джоб |
| GET | `/api/jobs/{id}` | статус, прогресс, статистика, находки |
| DELETE | `/api/jobs/{id}` | удалить джобу |
| GET | `/api/jobs/{id}/report?fmt=txt\|seeds\|csv\|json` | отчёты |
| GET | `/api/jobs/{id}/images/{name}` · `/annotated/{name}` | изображения |

## Валидация (офлайн)

- **WIF**: Base58Check-декодирование, версия `0x80`, флаг сжатия, диапазон
  secp256k1 → P2PKH-адрес (compressed и uncompressed).
- **Mini-ключ**: `SHA256(code + '?')` начинается с нулевого байта (Casascius).
- **Hex-ключ**: 64 символа, диапазон кривой → WIF + адреса.
- **BIP39**: все слова из официального словаря (2048), пересчёт
  entropy/checksum для длин 12/15/18/21/24. Фразы с битой контрольной
  суммой помечаются `checksum FAIL`.

## Кредиты

- Оригинальный скрипт: Marco Zollinger (MIT, 2018), кейс «CRYPTO DEEP TECH» / demining.
- Модернизация 2.0: веб-панель, каскад декодирования, детекторы, отчёты.
- Словарь BIP39: bitcoin/bips (bip-0039/english.txt).

Лицензия: MIT.
