@echo off
:: ============================================================
:: ZeroPhish AI - Server Launcher
:: Run this file to start the server: double-click or `.\run.bat`
:: ============================================================

:: Always use the virtual environment Python (3.12) regardless of
:: what system Python is set as default. This avoids any Python 3.14
:: or other version conflicts permanently.

SET "SCRIPT_DIR=%~dp0"
SET "VENV_PYTHON=%SCRIPT_DIR%.venv\Scripts\python.exe"

IF NOT EXIST "%VENV_PYTHON%" (
    echo [ERROR] Virtual environment not found at .venv\Scripts\python.exe
    echo Please run: python -m venv .venv ^&^& .venv\Scripts\pip install -r requirements.txt
    pause
    exit /b 1
)

echo [ZeroPhish AI] Starting server with .venv Python 3.12...
echo [ZeroPhish AI] Open http://127.0.0.1:8000 in your browser
echo.
"%VENV_PYTHON%" "%SCRIPT_DIR%app\main.py"
