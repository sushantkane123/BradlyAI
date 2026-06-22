@echo off
REM ============================================================================
REM BradlyAI - Windows graceful shutdown
REM Usage: deploy\stop.bat
REM ============================================================================
setlocal

cd /d "%~dp0\.."
set PID_FILE=deploy\bradlyai.pid

if not exist "%PID_FILE%" (
    echo BradlyAI is not running ^(no PID file^).
    exit /b 0
)

REM ---- Find all python processes running run.py and kill them ----
echo Stopping BradlyAI workers...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq *bradlyai*" 2>nul
for /f "tokens=*" %%P in ('tasklist /FI "IMAGENAME eq python.exe" /NH /FO CSV 2^>nul ^| findstr /I "run.py"') do (
    for /f "tokens=2 delims=," %%Q in ("%%P") do (
        set WPID=%%Q
        set WPID=!WPID:"=!
        echo Killing PID !WPID!...
        taskkill /F /PID !WPID! 2>nul
    )
)

REM Kill any python process listening on port 8000
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8000" ^| findstr "LISTENING"') do (
    if not "%%a"=="0" (
        echo Killing process on port 8000 ^(PID %%a^)...
        taskkill /F /PID %%a 2>nul
    )
)

del "%PID_FILE%" 2>nul
echo BradlyAI stopped.
endlocal
