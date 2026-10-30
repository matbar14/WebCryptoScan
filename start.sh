#!/usr/bin/env bash
# WebCryptoScan — запуск всё-в-одном (Linux / macOS).
# Сам создаёт venv, ставит зависимости Python, поднимает движок (:3031)
# и фронтенд (:3000). Повторный запуск безопасен: готовое переиспользуется.
set -u

cd "$(dirname "$0")"
ROOT="$(pwd)"
SVC="$ROOT/mini-services/scanner-service"
VENV="$SVC/.venv"

log() { printf '\033[1;32m[WebCryptoScan]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[WebCryptoScan]\033[0m %s\n' "$*" >&2; exit 1; }

# --- 0. Базовые утилиты -------------------------------------------------------
command -v curl >/dev/null 2>&1 || die "не найден curl: sudo apt install curl"
PY=python3
command -v "$PY" >/dev/null 2>&1 || die "python3 не найден: sudo apt install python3 python3-venv python3-pip"

# --- 1. venv и зависимости движка ---------------------------------------------
if [ ! -x "$VENV/bin/python" ]; then
  log "Создаю виртуальное окружение Python (mini-services/scanner-service/.venv)…"
  "$PY" -m venv "$VENV" 2>/dev/null || die "не удалось создать venv. Установите: sudo apt install python3-venv python3-pip"
fi

log "Ставлю зависимости движка (в первый раз 1–3 минуты, дальше — быстро)…"
"$VENV/bin/pip" install -q --upgrade pip || true
"$VENV/bin/pip" install -q -r "$SVC/requirements.txt" || die "pip install не прошёл — см. текст ошибки выше"

"$VENV/bin/python" -c "import fastapi, uvicorn, pyzbar, cv2, PIL" 2>/dev/null \
  || die "модули движка не импортируются. Нужны системные библиотеки: sudo apt install libzbar0 build-essential"
command -v pdftoppm >/dev/null 2>&1 \
  || log "ВНИМАНИЕ: pdftoppm не найден — PDF будет разбираться только текстом (sudo apt install poppler-utils)"

# --- 2. Движок (:3031) ----------------------------------------------------------
SVC_PID=""
if curl -sf "http://127.0.0.1:3031/api/health" >/dev/null 2>&1; then
  log "Python-движок уже работает на :3031 — переиспользую"
else
  log "Запускаю Python-движок (порт 3031)…"
  ( cd "$SVC" && exec "$VENV/bin/python" server.py ) > "$SVC/server.log" 2>&1 &
  SVC_PID=$!
  ok=""
  for i in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:3031/api/health" >/dev/null 2>&1; then ok=1; break; fi
    kill -0 "$SVC_PID" 2>/dev/null || { tail -n 25 "$SVC/server.log"; die "движок упал при старте — лог выше"; }
    [ "$i" -eq 25 ] && log "движок ещё поднимается… (первый импорт opencv бывает долгим)"
    sleep 1
  done
  [ -n "$ok" ] || { tail -n 25 "$SVC/server.log"; die "движок не ответил за 60 секунд — лог выше"; }
  log "Движок готов: http://127.0.0.1:3031/api/health"
fi

cleanup() { if [ -n "$SVC_PID" ]; then kill "$SVC_PID" 2>/dev/null || true; fi; }
trap cleanup EXIT INT TERM

# --- 3. Фронтенд (:3000) --------------------------------------------------------
if [ ! -d "$ROOT/node_modules" ]; then
  log "Ставлю зависимости фронтенда (npm ci)…"
  npm ci --no-audit --no-fund || npm install --no-audit --no-fund
fi

log "Готово. Открывайте http://localhost:3000  (остановить всё: Ctrl+C)"
npm run dev
