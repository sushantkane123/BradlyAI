@echo off
REM ============================================================================
REM BradlyAI - Windows status / health check
REM Usage: deploy\status.bat
REM ============================================================================
setlocal

cd /d "%~dp0\.."

echo === Process ===
tasklist /FI "IMAGENAME eq python.exe" /NH /FO TABLE 2>nul | findstr /I "python" || echo   none

echo.
echo === Port 8000 ===
netstat -ano | findstr ":8000" | findstr "LISTENING" || echo   not listening

echo.
echo === Health endpoint ===
curl -s -m 5 http://127.0.0.1:8000/health 2>nul
if errorlevel 1 echo   not responding

echo.
echo.
echo === Persistent storage ===
if exist "data\bradlyai_soc.db" (
    for %%F in ("data\bradlyai_soc.db") do echo   Database: %%~zF bytes  ^(%%~fF^)
) else (
    echo   Database: not yet created
)

echo.
echo === Last 10 log lines ===
if exist "logs\bradlyai.log" (
    powershell -Command "Get-Content logs\bradlyai.log -Tail 10"
) else (
    echo   no log file yet
)
endlocal
