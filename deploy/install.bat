@echo off
REM ============================================================================
REM BradlyAI - Windows installer (cmd.exe / PowerShell compatible)
REM Usage:  deploy\install.bat
REM ============================================================================
setlocal enabledelayedexpansion

echo.
echo === BradlyAI Windows Installer ===
echo.

REM ---- Locate project root (one level up from deploy/) ----
cd /d "%~dp0\.."

REM ---- Python check ----
where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found in PATH.
    echo         Install Python 3.10+ from https://www.python.org/downloads/
    echo         IMPORTANT: Tick "Add Python to PATH" during install.
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PY_VER=%%v
echo Python %PY_VER%

REM ---- Create venv ----
if not exist "venv\Scripts\python.exe" (
    echo Creating virtual environment in venv\...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] venv creation failed. Try: python -m pip install --user virtualenv
        exit /b 1
    )
) else (
    echo venv exists - reusing
)

REM ---- Install dependencies ----
echo Installing dependencies...
call venv\Scripts\activate.bat
python -m pip install --quiet --upgrade pip wheel
python -m pip install --quiet -r requirements.txt

REM ---- Install gunicorn (alternative to uvicorn; works on Windows but limited) ----
echo Installing gunicorn (optional alternative server)...
python -m pip install --quiet "gunicorn>=21.2" 2>nul || echo   gunicorn install skipped (Windows has limited gunicorn support - uvicorn is fine)

REM ---- Generate .env ----
if not exist ".env" (
    echo Generating .env from template...
    copy /Y .env.example .env >nul
    powershell -Command "(Get-Content .env) -replace '^ENVIRONMENT=.*','ENVIRONMENT=production' | Set-Content .env" >nul 2>&1
)

REM ---- Create runtime dirs ----
if not exist "data" mkdir data
if not exist "logs" mkdir logs

REM ---- Verify ----
echo.
echo Verifying install...
python -c "from bradlyai.config import settings; print('  App:    ', settings.APP_NAME); print('  Version:', settings.APP_VERSION); print('  Env:    ', settings.ENVIRONMENT); print('  DB:     ', settings.DATABASE_URL)"

echo.
echo === Install complete ===
echo.
echo Next steps:
echo   start:   deploy\start.bat
echo   status:  deploy\status.bat
echo   stop:    deploy\stop.bat
echo.
echo Dashboard will be at: http://localhost:8000
endlocal
