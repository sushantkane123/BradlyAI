# ============================================================================
# BradlyAI - PowerShell shutdown
# Usage: .\deploy\stop.ps1
# ============================================================================
$ErrorActionPreference = 'SilentlyContinue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
Set-Location $RootDir

$PidFile = Join-Path $ScriptDir 'bradlyai.pid'

# Stop supervisor if PID file exists
if (Test-Path $PidFile) {
    $supPid = Get-Content $PidFile
    if ($supPid -and (Get-Process -Id $supPid -ErrorAction SilentlyContinue)) {
        Write-Host "Stopping supervisor (PID $supPid)..."
        Stop-Process -Id $supPid -Force
    }
    Remove-Item $PidFile -Force
}

# Kill any leftover python worker processes related to BradlyAI
$workers = Get-Process python -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like '*run.py*' -or
    $_.Path -like '*BradlyAI*'
}
foreach ($w in $workers) {
    Write-Host "Stopping worker PID $($w.Id)..."
    Stop-Process -Id $w.Id -Force
}

# Free port 8000
$portListeners = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
foreach ($p in $portListeners) {
    $proc = Get-Process -Id $p.OwningProcess -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host "Killing process on port 8000 (PID $($p.OwningProcess): $($proc.ProcessName))"
        Stop-Process -Id $p.OwningProcess -Force
    }
}

# Clean up temp supervisor file
Remove-Item (Join-Path $ScriptDir '_supervisor.ps1') -Force -ErrorAction SilentlyContinue

Write-Host "BradlyAI stopped." -ForegroundColor Green
