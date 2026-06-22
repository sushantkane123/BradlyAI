# ============================================================================
# BradlyAI - PowerShell installer
# Usage:  powershell -ExecutionPolicy Bypass -File deploy\install.ps1
#         .\deploy\install.ps1
# ============================================================================
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
Set-Location $RootDir

Write-Host ''
Write-Host '=== BradlyAI PowerShell Installer ===' -ForegroundColor Cyan
Write-Host ''

# ---- Python check ----
$python = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $python) {
    Write-Host '[ERROR] Python not found in PATH.' -ForegroundColor Red
    Write-Host '        Install Python 3.10+ from https://www.python.org/downloads/'
    exit 1
}
$pyVer = & python --version 2>&1
Write-Host "Python: $pyVer"

# ---- Create venv ----
if (-not (Test-Path 'venv\Scripts\python.exe')) {
    Write-Host 'Creating virtual environment...'
    & python -m venv venv
} else {
    Write-Host 'venv exists - reusing'
}

# ---- Activate & install ----
& "$RootDir\venv\Scripts\Activate.ps1"
python -m pip install --quiet --upgrade pip wheel
Write-Host 'Installing requirements...'
python -m pip install --quiet -r requirements.txt

# ---- gunicorn (optional) ----
try {
    python -m pip install --quiet "gunicorn>=21.2" 2>$null
    Write-Host 'gunicorn installed'
} catch {
    Write-Host 'gunicorn skipped (Windows has limited support)' -ForegroundColor Yellow
}

# ---- Generate .env ----
if (-not (Test-Path '.env')) {
    Write-Host 'Generating .env from template...'
    Copy-Item '.env.example' '.env' -Force
    (Get-Content '.env') -replace '^ENVIRONMENT=.*', 'ENVIRONMENT=production' | Set-Content '.env'
}

# ---- Runtime dirs ----
New-Item -ItemType Directory -Force -Path 'data' | Out-Null
New-Item -ItemType Directory -Force -Path 'logs' | Out-Null

# ---- Verify ----
Write-Host ''
Write-Host 'Verifying install...' -ForegroundColor Cyan
& python -c "from bradlyai.config import settings; print(f'  App:     {settings.APP_NAME}'); print(f'  Version: {settings.APP_VERSION}'); print(f'  Env:     {settings.ENVIRONMENT}'); print(f'  DB:      {settings.DATABASE_URL}')"

Write-Host ''
Write-Host '=== Install complete ===' -ForegroundColor Green
Write-Host ''
Write-Host 'Next steps:'
Write-Host '  Start:   .\deploy\start.ps1'
Write-Host '  Status:  .\deploy\status.ps1'
Write-Host '  Stop:    .\deploy\stop.ps1'
Write-Host ''
Write-Host 'Dashboard will be at: http://localhost:8000'
