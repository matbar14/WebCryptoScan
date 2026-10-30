@echo off
rem WebCryptoScan - запуск всё-в-одном (Windows).
rem Создаёт venv, ставит зависимости Python, поднимает движок (:3031)
rem и фронтенд (:3000) в отдельных окнах.
setlocal
chcp 65001 >nul
cd /d "%~dp0"
set SVC=mini-services\scanner-service
set VENV=%SVC%\.venv

echo [WebCryptoScan] Проверяю Python...
python --version >nul 2>&1 || (echo Нужен Python 3.10+ с сайта python.org, при установке отметьте "Add to PATH" & pause & exit /b 1)

if not exist "%VENV%\Scripts\python.exe" (
  echo [WebCryptoScan] Создаю виртуальное окружение ^(.venv^)...
  python -m venv "%VENV%" || (echo Не удалось создать venv & pause & exit /b 1)
)

echo [WebCryptoScan] Ставлю зависимости движка (в первый раз 1-3 минуты)...
"%VENV%\Scripts\python.exe" -m pip install -q --upgrade pip
"%VENV%\Scripts\python.exe" -m pip install -q -r "%SVC%\requirements.txt" || (echo pip install не прошёл - см. ошибку выше & pause & exit /b 1)

echo [WebCryptoScan] Запускаю Python-движок (порт 3031)...
start "WebCryptoScan engine" cmd /k "cd /d %SVC% && .venv\Scripts\python.exe server.py"

if not exist node_modules (
  echo [WebCryptoScan] Ставлю зависимости фронтенда (npm ci)...
  call npm ci || call npm install
)

echo [WebCryptoScan] Запускаю фронтенд: http://localhost:3000
start "WebCryptoScan web" cmd /k npm run dev
timeout /t 8 >nul
start http://localhost:3000
echo Готово: движок и фронтенд открыты в отдельных окнах. Закройте их, чтобы всё остановить.
pause
