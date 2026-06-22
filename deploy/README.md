# BradlyAI `deploy/` toolkit

Production deployment scripts for BradlyAI. Pick the right script for your OS.

## Which script to use?

| Platform | Shell | Use these |
|----------|-------|-----------|
| **Linux / macOS** | bash | `install.sh` · `start.sh` · `stop.sh` · `status.sh` |
| **Windows** | cmd.exe | `install.bat` · `start.bat` · `stop.bat` · `status.bat` |
| **Windows** | PowerShell | `install.ps1` · `start.ps1` · `stop.ps1` · `status.ps1` |

All four families do the same thing — pick whichever shell you prefer.

## Quick start

**Linux/macOS:**
```bash
./deploy/install.sh
./deploy/start.sh
```

**Windows cmd.exe:**
```cmd
deploy\install.bat
deploy\start.bat
```

**Windows PowerShell:**
```powershell
.\deploy\install.ps1
.\deploy\start.ps1
```

## When on Windows but bash scripts look tempting

If you have **Git for Windows** installed, just open **Git Bash** (right-click folder → "Git Bash Here") and the bash scripts work. Otherwise use the `.bat` or `.ps1` variants above.

If you have **WSL** installed, the bash scripts work natively inside WSL.

## Production alternatives (not OS-specific)

These work the same on any OS:

- **Docker:** `docker compose up -d --build` (uses the `Dockerfile` at project root)
- **systemd (Linux only):** `deploy/bradlyai.service`
- **Reverse proxy:** `deploy/nginx.conf.example`
- **Alt WSGI server:** `deploy/gunicorn.conf.py`

See `DEPLOYMENT.md` for the full deployment guide.
