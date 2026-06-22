@echo off
REM ============================================================================
REM BradlyAI - Windows starter (cmd.exe)
REM Binds 0.0.0.0:8000, logs to logs\bradlyai.log, auto-restart on crash.
REM Usage:  deploy\start.bat           (background, with supervisor)
REM         deploy\start.bat --fg      (foreground, debug)
REM ============================================================================
setlocal enabledelayedexpansion

cd /d "%~dp0\.."

set PID_FILE=deploy\bradlyai.pid
set LOG_FILE=logs\bradlyai.log
set LOG_DIR=logs
set DATA_DIR=data
set MAX_RESTARTS=10

if not exist "%LOG_DIR%" mkdir %LOG_DIR%
if not exist "%DATA_DIR%" mkdir %DATA_DIR%

REM ---- Already running? ----
if exist "%PID_FILE%" (
    for /f "usebackq" %%P in ("%PID_FILE%") do set OLD_PID=%%P
    tasklist /FI "PID eq !OLD_PID!" 2>nul | findstr /R "!OLD_PID!" >nul
    if not errorlevel 1 (
        echo BradlyAI already running ^(PID !OLD_PID!^). Stop with deploy\stop.bat
        exit /b 0
    ) else (
        echo Stale PID file - cleaning
        del "%PID_FILE%" 2>nul
    )
)

REM ---- Foreground mode (debug) ----
if /i "%1"=="--fg" (
    echo Starting BradlyAI in FOREGROUND...
    call venv\Scripts\activate.bat
    set ENVIRONMENT=production
    set HOST=0.0.0.0
    set PORT=8000
    set DATABASE_URL=sqlite+aiosqlite:///%CD%\data\bradlyai_soc.db
    python run.py --host 0.0.0.0 --port 8000
    exit /b %errorlevel%
)

REM ---- Background mode ----
echo Starting BradlyAI in BACKGROUND ^(port 8000^)...

REM Spawn a tiny supervisor loop in a separate process that restarts the worker on crash.
REM The supervisor writes its own PID to the PID file.
start /b "" cmd /c ^
    "set ENVIRONMENT=production&& ^
     set HOST=0.0.0.0&& ^
     set PORT=8000&& ^
     set DATABASE_URL=sqlite+aiosqlite:///%CD:\=\\\\%\\data\\bradlyai_soc.db&& ^
     cd /d %CD% && ^
     call venv\Scripts\activate.bat && ^
     echo %RANDOM% > %PID_FILE% && ^
     set COUNT=0 && ^
     :loop && ^
     echo [%date% %time%] Launching worker && ^
     call python run.py --host 0.0.0.0 --port 8000 >> %LOG_FILE% 2>&1 && ^
     set /a COUNT+=1 && ^
     if !COUNT! LSS %MAX_RESTARTS% (^
         echo [%date% %time%] Worker exited, restarting in 5s... ^(attempt !COUNT!/%MAX_RESTARTS%^) && ^
         timeout /t 5 /nobreak >nul && ^
         goto loop && ^
     ) else (^
         echo [%date% %time%] Max restarts reached, giving up && ^
         exit /b 1 && ^
     )"

REM Wait 4s for boot
timeout /t 4 /nobreak >nul

REM Health probe
echo.
echo Checking health...
curl -s -m 5 http://127.0.0.1:8000/health
echo.
echo.
echo BradlyAI started.
echo Dashboard:   http://localhost:8000/
echo Swagger UI:  http://localhost:8000/docs
echo Health:      http://localhost:8000/health
echo.
echo Commands:
echo   status:  deploy\status.bat
echo   stop:    deploy\stop.bat
echo   logs:    type %LOG_FILE%
endlocal
