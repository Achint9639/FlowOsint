@echo off
title FlowOsint v3.0
cd /d "%~dp0"

:: ── Check Python is installed ─────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo  [ERROR] Python is not installed or not in PATH.
    echo  Download it from: https://www.python.org/downloads/
    echo  Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

:: ── Create virtual environment if it doesn't exist ───────────────────────────
if not exist "venv\Scripts\activate.bat" (
    echo.
    echo  [*] First run detected - setting up virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo  [ERROR] Failed to create virtual environment.
        echo  Try running: python -m pip install --upgrade pip
        pause
        exit /b 1
    )
    echo  [+] Virtual environment created.
)

:: ── Activate virtual environment ─────────────────────────────────────────────
call venv\Scripts\activate.bat

:: ── Install / update dependencies ────────────────────────────────────────────
echo.
echo  [*] Checking dependencies...
pip install -r requirements.txt -q --disable-pip-version-check
if errorlevel 1 (
    echo.
    echo  [ERROR] Dependency installation failed.
    echo  Try running manually: pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)
echo  [+] Dependencies OK.
echo.

:: ── Launch FlowOsint ─────────────────────────────────────────────────────────
python flowoosint.py

pause
