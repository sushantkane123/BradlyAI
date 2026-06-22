# ============================================================================
# BradlyAI - PowerShell status / health check
# Usage: .\deploy\status.ps1
# ============================================================================
$ErrorActionPreference = 'SilentlyContinue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
Set-Location $RootDir

Write-Host '=== Process ===' -ForegroundColor Cyan
$workers = Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*run.py*' }
if ($workers) {
    $workers | Format-Table Id, StartTime, CPU, WS, Path -AutoSize | Out-String | Write-Host
} else {
    Write-Host '  not running' -ForegroundColor Yellow
}

Write-Host ''
Write-Host '=== Port 8000 ===' -ForegroundColor Cyan
$conn = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($conn) {
    foreach ($c in $conn) {
        $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        Write-Host "  listening (PID $($c.OwningProcess): $($proc.ProcessName))"
    }
} else {
    Write-Host '  not listening' -ForegroundColor Yellow
}

Write-Host ''
Write-Host '=== /health ===' -ForegroundColor Cyan
try {
    $h = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/health' -Method Get -TimeoutSec 5
    $h | Format-List | Out-String | Write-Host
} catch {
    Write-Host '  not responding' -ForegroundColor Yellow
}

Write-Host ''
Write-Host '=== Persistent storage ===' -ForegroundColor Cyan
$db = Join-Path $RootDir 'data\bradlyai_soc.db'
if (Test-Path $db) {
    $size = (Get-Item $db).Length
    Write-Host "  Database: $size bytes  ($db)"
} else {
    Write-Host '  Database: not yet created'
}

Write-Host ''
Write-Host '=== Last 10 log lines ===' -ForegroundColor Cyan
$log = Join-Path $RootDir 'logs\bradlyai.log'
if (Test-Path $log) {
    Get-Content $log -Tail 10 | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Host '  no log file yet'
}
