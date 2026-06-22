# ============================================================================
# BradlyAI - PowerShell starter
# Usage:  .\deploy\start.ps1           (background)
#         .\deploy\start.ps1 -Foreground  (foreground, debug)
# ============================================================================
[CmdletBinding()]
param(
    [switch]$Foreground
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
Set-Location $RootDir

$Port = 8000
$PidFile = Join-Path $ScriptDir 'bradlyai.pid'
$LogFile = Join-Path $RootDir 'logs\bradlyai.log'
New-Item -ItemType Directory -Force -Path (Join-Path $RootDir 'logs') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $RootDir 'data') | Out-Null

# ---- Already running? ----
if (Test-Path $PidFile) {
    $oldPid = Get-Content $PidFile -ErrorAction SilentlyContinue
    if ($oldPid -and (Get-Process -Id $oldPid -ErrorAction SilentlyContinue)) {
        Write-Host "BradlyAI already running (PID $oldPid). Stop with .\deploy\stop.ps1" -ForegroundColor Yellow
        exit 0
    } else {
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    }
}

# ---- Activate venv ----
& "$RootDir\venv\Scripts\Activate.ps1"

$env:ENVIRONMENT = 'production'
$env:HOST = '0.0.0.0'
$env:PORT = $Port
$env:DATABASE_URL = "sqlite+aiosqlite:///$RootDir\data\bradlyai_soc.db"

# ---- Foreground mode ----
if ($Foreground) {
    Write-Host "Starting BradlyAI in FOREGROUND..." -ForegroundColor Cyan
    & python "$RootDir\run.py" --host 0.0.0.0 --port $Port
    exit $LASTEXITCODE
}

# ---- Background mode with crash-loop supervisor ----
Write-Host "Starting BradlyAI in BACKGROUND (port $Port)..." -ForegroundColor Cyan

$supervisorScript = @"
`$ErrorActionPreference = 'SilentlyContinue'
`$env:ENVIRONMENT = 'production'
`$env:HOST = '0.0.0.0'
`$env:PORT = $Port
`$env:DATABASE_URL = 'sqlite+aiosqlite:///$RootDir\data\bradlyai_soc.db'
Set-Location '$RootDir'
& '$RootDir\venv\Scripts\Activate.ps1'

`$MAX = 10
`$count = 0
while (`$count -lt `$MAX) {
    `$count++
    Add-Content -Path '$LogFile' -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Launching worker (attempt `$count/`$MAX)"
    `$proc = Start-Process -FilePath python -ArgumentList '$RootDir\run.py','--host','0.0.0.0','--port','$Port' `
        -RedirectStandardOutput '$LogFile' -RedirectStandardError '$LogFile' `
        -PassThru -NoNewWindow
    `$proc | Wait-Process
    Add-Content -Path '$LogFile' -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Worker exited; restarting in 5s"
    Start-Sleep -Seconds 5
}
Add-Content -Path '$LogFile' -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Max restarts reached; giving up"
"@

# Save supervisor script to a temp file and launch detached
$supFile = Join-Path $ScriptDir '_supervisor.ps1'
Set-Content -Path $supFile -Value $supervisorScript

$supervisor = Start-Process -FilePath powershell `
    -ArgumentList '-ExecutionPolicy','Bypass','-File',"`"$supFile`"" `
    -WindowStyle Hidden -PassThru
Set-Content -Path $PidFile -Value $supervisor.Id

Start-Sleep -Seconds 4

# ---- Health probe ----
Write-Host ''
try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -Method Get -TimeoutSec 5
    Write-Host "Health: $($health.status) | DB: $($health.database) | Env: $($health.environment)" -ForegroundColor Green
} catch {
    Write-Host "Health: NOT RESPONDING (yet — try deploy\status.bat in a few seconds)" -ForegroundColor Yellow
}

Write-Host ''
Write-Host "Dashboard:   http://localhost:$Port/" -ForegroundColor Cyan
Write-Host "Swagger UI:  http://localhost:$Port/docs"
Write-Host "Health:      http://localhost:$Port/health"
Write-Host ''
Write-Host 'Commands:' -ForegroundColor Cyan
Write-Host "  status:  .\deploy\status.ps1"
Write-Host "  stop:    .\deploy\stop.ps1"
Write-Host "  logs:    Get-Content $LogFile -Wait"
