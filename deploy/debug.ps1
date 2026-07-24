# ============================================================================
# BradlyAI - Diagnostic script (Windows PowerShell)
# Run this and paste the output back to me - it will tell us exactly what's broken.
# Usage:  .\deploy\debug.ps1
# ============================================================================
$ErrorActionPreference = 'Continue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
Set-Location $RootDir

function Section($title) {
    Write-Host ''
    Write-Host "=== $title ===" -ForegroundColor Cyan
}

function Pass($msg)   { Write-Host "  PASS  $msg" -ForegroundColor Green }
function Warn($msg)   { Write-Host "  WARN  $msg" -ForegroundColor Yellow }
function Fail($msg)   { Write-Host "  FAIL  $msg" -ForegroundColor Red }
function Info($msg)   { Write-Host "  INFO  $msg" -ForegroundColor Gray }

Section "1. Python"
try {
    $py = & python --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Pass "Python available: $py"
    } else {
        Fail "Python command failed: $py"
    }
} catch {
    Fail "Python not in PATH. Install from https://www.python.org/downloads/ (tick 'Add Python to PATH')"
}

Section "2. Git & branch"
try {
    $branch = & git rev-parse --abbrev-ref HEAD 2>&1
    if ($LASTEXITCODE -eq 0) {
        Pass "On branch: $branch"
        $latest = & git log --oneline -3 2>&1
        Info "Latest commits:"
        $latest | ForEach-Object { Write-Host "    $_" }
    } else {
        Fail "Not in a git repo"
    }
} catch {
    Fail "Git not in PATH"
}

Section "3. Virtual environment"
if (Test-Path 'venv\Scripts\python.exe') {
    $venvPy = & '.\venv\Scripts\python.exe' --version 2>&1
    Pass "venv exists: $venvPy"
    $deps = & '.\venv\Scripts\python.exe' -m pip list 2>&1 | Where-Object { $_ -match 'fastapi|uvicorn|sqlalchemy|pydantic' }
    if ($deps) {
        Pass "Key packages installed:"
        $deps | ForEach-Object { Write-Host "    $_" }
    } else {
        Fail "Key packages NOT installed. Run deploy\install.ps1 or deploy\install.bat"
    }
} else {
    Fail "venv NOT created. Run deploy\install.ps1 or deploy\install.bat"
}

Section "4. .env file"
if (Test-Path '.env') {
    Pass ".env exists"
    $envContent = Get-Content '.env' -TotalCount 20
    $envContent | ForEach-Object { Write-Host "    $_" }
} else {
    Fail ".env missing. Run deploy\install.ps1 (it copies .env.example to .env)"
}

Section "5. Can we import BradlyAI?"
try {
    & '.\venv\Scripts\python.exe' -c "from bradlyai.config import settings; print(f'    App: {settings.APP_NAME}'); print(f'    Env: {settings.ENVIRONMENT}'); print(f'    DB:  {settings.DATABASE_URL}')" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Pass "bradlyai module imports OK"
    } else {
        Fail "bradlyai module import failed - see error above"
    }
} catch {
    Fail "Could not run python in venv"
}

Section "6. Port 8000"
$portConn = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($portConn) {
    foreach ($c in $portConn) {
        $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        Warn "Port 8000 IN USE by PID $($c.OwningProcess): $($proc.ProcessName)"
    }
} else {
    Pass "Port 8000 is free"
}

Section "7. BradlyAI process"
$workers = Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*run.py*' -or $_.Path -like '*BradlyAI*' }
if ($workers) {
    Pass "BradlyAI process running:"
    $workers | Format-Table Id, StartTime, CPU, WS -AutoSize | Out-String | Write-Host
} else {
    Warn "No BradlyAI process running. Run deploy\start.ps1"
}

Section "8. /health endpoint"
try {
    $h = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/health' -Method Get -TimeoutSec 5
    Pass "/health responding:"
    $h | Format-List | Out-String | Write-Host
} catch {
    Warn "/health not responding: $($_.Exception.Message)"
}

Section "9. Logs"
if (Test-Path 'logs\bradlyai.log') {
    Pass "Log file exists, last 15 lines:"
    Get-Content 'logs\bradlyai.log' -Tail 15 | ForEach-Object { Write-Host "    $_" }
} else {
    Warn "No log file yet"
}

Section "10. Deploy script family"
$scripts = Get-ChildItem "$ScriptDir\*" -Include *.sh,*.bat,*.ps1 -File
$scripts | ForEach-Object {
    $size = $_.Length
    Write-Host ("    {0,-30} {1,6} bytes" -f $_.Name, $size)
}

Write-Host ''
Write-Host "=== End of diagnostic ===" -ForegroundColor Cyan
Write-Host ''
Write-Host "Paste everything above back to the Arena session and I'll tell you what to fix." -ForegroundColor Yellow
