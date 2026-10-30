#!/usr/bin/env bash
# Ручной запуск Python-сервиса сканера (порт 3031).
# Обычно запускается автоматически из Next.js (src/instrumentation.ts).
cd "$(dirname "$0")" && exec python3 server.py
