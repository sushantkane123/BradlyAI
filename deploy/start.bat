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
set SUP_FILE=deploy\_supervisor.bat
set LOG_FILE=logs\bradlyai.log

if not exist "logs" mkdir logs
if not exist "data" mkdir data

REM ---- Already running? ----
if exist "%PID_FILE%" (
    set /p OLD_PID=<"%PID_FILE%"
    tasklist /FI "PID eq !OLD_PID!" 2>nul | findstr /R "!OLD_PID!" >nul
    if not errorlevel 1 (
        echo BradlyAI already running (PID !OLD_PID!). Stop with deploy\stop.bat
        exit /b 0
    ) else (
        echo Stale PID file - cleaning
        del "%PID_FILE%" 2>nul
        if exist "%SUP_FILE%" del "%SUP_FILE%" 2>nul
    )
)

REM ---- Foreground mode ----
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
echo Starting BradlyAI in BACKGROUND (port 8000)...

REM Generate a separate supervisor batch file with proper syntax
> "%SUP_FILE%" echo @echo off
>> "%SUP_FILE%" echo setlocal
>> "%SUP_FILE%" echo set ENVIRONMENT=production
>> "%SUP_FILE%" echo set HOST=0.0.0.0
>> "%SUP_FILE%" echo set PORT=8000
>> "%SUP_FILE%" echo set DATABASE_URL=sqlite+aiosqlite:///%CD:\=\\%\\data\\bradlyai_soc.db
>> "%SUP_FILE%" echo cd /d "%CD%"
>> "%SUP_FILE%" echo call venv\Scripts\activate.bat
>> "%SUP_FILE%" echo set MAX=10
>> "%SUP_FILE%" echo set COUNT=0
>> "%SUP_FILE%" echo :loop
>> "%SUP_FILE%" echo     set /a COUNT+=1
>> "%SUP_FILE%" echo     echo [%date% %time%] Launching worker (attempt !COUNT!/10) ^>^> %LOG_FILE%
>> "%SUP_FILE%" echo     call python run.py --host 0.0.0.0 --port 8000 ^>^> %LOG_FILE% 2^>^&1
>> "%SUP_FILE%" echo     echo [%date% %time%] Worker exited; restarting in 5s (attempt !COUNT!/10) ^>^> %LOG_FILE%
>> "%SUP_FILE%" echo     if !COUNT! LSS 10 (
>> "%SUP_FILE%" echo         timeout /t 5 /nobreak ^>nul
>> "%SUP_FILE%" echo         goto loop
>> "%SUP_FILE%" echo     )
>> "%SUP_FILE%" echo echo [%date% %time%] Max restarts reached, giving up ^>^> %LOG_FILE%
>> "%SUP_FILE%" echo exit /b 1

REM Launch the supervisor detached using START
REM /B = no new window, "" = required dummy title for START, /MIN = minimized window
start "bradlyai-supervisor" /B cmd /c "%SUP_FILE%"

REM Wait a moment, then capture the supervisor PID
timeout /t 1 /nobreak >nul
for /f "tokens=2" %%P in ('tasklist /FI "WINDOWTITLE eq bradlyai-supervisor*" /NH 2^>nul ^| findstr "bradlyai-supervisor"') do (
    echo %%P > "%PID_FILE%"
    goto got_pid
)
REM Fallback: find python running run.py
for /f "tokens=2" %%P in ('wmic process where "name='python.exe' and commandline like '%%run.py%%'" get processid /FORMAT:LIST 2^>nul ^| findstr "ProcessId"') do (
    echo %%P > "%PID_FILE%"
    goto got_pid
)
:got_pid

REM Wait for boot
timeout /t 4 /nobreak >nul

REM Health probe
echo.
echo Checking health...
curl -s -m 5 http://127.0.0.1:8000/health
echo.
echo.
if exist "%PID_FILE%" (
    set /p CUR_PID=<"%PID_FILE%"
    echo BradlyAI started. Supervisor PID: !CUR_PID!
) else (
    echo BradlyAI started.
)
echo.
echo Dashboard:   http://localhost:8000/
echo Swagger UI:  http://localhost:8000/docs
echo Health:      http://localhost:8000/health
echo.
echo Commands:
echo   status:  deploy\status.bat
echo   stop:    deploy\stop.bat
echo   logs:    type %LOG_FILE%
endlocal
