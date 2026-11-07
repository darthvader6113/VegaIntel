#!/usr/bin/env bash
# ==============================================================================
# VegaIntel Automated Deployment Script for Linux
# Supports both Docker Compose (Production) and Standalone Native Python modes.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================="
echo "      VegaIntel Threat Intelligence Platform Setup       "
echo "=========================================================="

# Check for .env file
if [ ! -f "backend/.env" ]; then
    echo "[!] backend/.env not detected. Creating from backend/.env.example..."
    cp backend/.env.example backend/.env
    echo "[+] backend/.env created successfully."
fi

# Detect deployment mode
if command -v docker &>/dev/null && docker compose version &>/dev/null; then
    echo "[+] Docker & Docker Compose detected."
    echo "[*] Building and starting all microservices in the background..."
    docker compose up --build -d

    echo ""
    echo "=========================================================="
    echo " VegaIntel has been successfully deployed with Docker!    "
    echo "=========================================================="
    echo ">> Dashboard:  http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):3000"
    echo ">> API & Docs: http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):8000/docs"
    echo ">> Health:     http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):8000/health"
    echo ">> STIX Feed:  http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):8000/api/export/stix"
    echo "=========================================================="
    echo "To monitor live logs, run: docker compose logs -f"
    echo "To stop the platform, run: docker compose down"
else
    echo "[!] Docker Compose not found. Running in Standalone Unified mode..."

    # Check Python 3
    if ! command -v python3 &>/dev/null; then
        echo "[ERROR] python3 is required. Please install it with: sudo apt install -y python3 python3-pip python3-venv"
        exit 1
    fi

    # Create venv if not exists
    if [ ! -d "venv" ]; then
        echo "[*] Creating Python virtual environment..."
        python3 -m venv venv
    fi

    echo "[*] Installing Python backend dependencies..."
    source venv/bin/activate
    pip install -q --upgrade pip
    pip install -q -r backend/requirements.txt

    # Check if frontend is built
    if [ ! -d "frontend/dist" ]; then
        echo "[*] Compiling frontend assets..."
        if command -v npm &>/dev/null; then
            cd frontend && npm install && npm run build && cd ..
        else
            echo "[!] npm not found. If pre-built frontend is available, continuing..."
        fi
    fi

    echo ""
    echo "=========================================================="
    echo " Starting VegaIntel Standalone Unified Server...         "
    echo "=========================================================="
    export PYTHONPATH="backend"
    python3 -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000
fi

