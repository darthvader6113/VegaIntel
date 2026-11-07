# VegaIntel One-Click Launcher for Windows
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " Starting VegaIntel Threat Intelligence Platform" -ForegroundColor Yellow
Write-Host "======================================================" -ForegroundColor Cyan

# Set Python Path
$env:PYTHONPATH = "backend"

Write-Host "`n[1/2] Verifying Backend environment..." -ForegroundColor Green
python -m pip install -q -r backend/requirements.txt

Write-Host "`n[2/2] Launching VegaIntel Unified Server (FastAPI + Embedded UI)..." -ForegroundColor Green
Write-Host ">>> Dashboard: http://localhost:8000" -ForegroundColor Yellow
Write-Host ">>> API Docs:  http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host ">>> STIX 2.1:  http://localhost:8000/api/export/stix" -ForegroundColor Yellow

python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000

