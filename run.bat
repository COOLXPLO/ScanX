@echo off
:: ─────────────────────────────────────────────
::  ScanX v2.0  —  Windows Launcher
::  by iamunknown77
:: ─────────────────────────────────────────────

title ScanX v2.0

echo.
echo   =====================================================
echo    ScanX v2.0  --  Advanced Security Scanner
echo    by iamunknown77
echo   =====================================================
echo.
echo   WARNING: Use only on systems you own or have
echo   explicit written permission to test.
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [X] Python not found.
    echo       Download from https://www.python.org/downloads/
    echo       Make sure to tick "Add Python to PATH" during install.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version 2^>^&1') do echo   [+] %%i

:: Install deps if needed
python -c "import fastapi, uvicorn, aiohttp" >nul 2>&1
if %errorlevel% neq 0 (
    echo   [!] Installing dependencies...
    pip install -r requirements.txt --quiet
    if %errorlevel% neq 0 (
        echo   [X] pip install failed. Run manually: pip install -r requirements.txt
        pause
        exit /b 1
    )
)

echo   [OK] Dependencies ready
echo   [*]  Starting backend on http://localhost:8000 ...
echo   [i]  Opening browser automatically...
echo   [i]  Press Ctrl+C to stop.
echo.

:: Open browser after 2 seconds
start "" /B cmd /c "timeout /t 2 >nul && start http://localhost:8000"

python scanner_backend.py

pause
