@echo off
setlocal

cd /d "%~dp0"

if exist "venv\Scripts\python.exe" (
    echo Starting VulnTrack AI backend with venv Python...
    "venv\Scripts\python.exe" -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8001
) else (
    echo venv not found. Starting with system Python...
    python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8001
)
