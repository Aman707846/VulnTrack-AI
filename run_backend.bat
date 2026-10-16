@echo off
setlocal

cd /d "%~dp0"
set "PYTHONPATH=%~dp0;%~dp0backend;%PYTHONPATH%"

if exist "venv\Scripts\python.exe" (
    echo Starting VulnTrack AI backend with venv Python...
    "venv\Scripts\python.exe" -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8001 --reload
) else (
    echo venv not found. Starting with system Python...
    python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8001 --reload
)

