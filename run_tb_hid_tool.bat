@echo off
rem Creates a local virtual environment on first run, installs the two dependencies and starts the tool.
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    where py >nul 2>nul && (py -3 -m venv .venv) || (python -m venv .venv)
    if errorlevel 1 (
        echo Python 3.9+ is required. Install it from https://www.python.org/downloads/
        pause
        exit /b 1
    )
)

if not exist ".venv\.deps_installed" (
    echo Installing dependencies...
    ".venv\Scripts\python.exe" -m pip install -q -r requirements.txt
    if errorlevel 1 (
        echo pip install failed
        pause
        exit /b 1
    )
    echo ok> ".venv\.deps_installed"
)

".venv\Scripts\python.exe" tb_hid_tool.py %*
if errorlevel 1 pause
