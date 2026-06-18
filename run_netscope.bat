@echo off
echo =========================================
echo       NetScope - Automated Launcher
echo =========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not in your PATH.
    echo Please install Python 3.10+ to run NetScope.
    pause
    exit /b
)

REM Check if virtual environment exists, create if not
IF NOT EXIST ".venv\Scripts\pythonw.exe" (
    echo [INFO] First time setup detected! Creating virtual environment...
    python -m venv .venv
    
    echo [INFO] Installing required packages (this may take a minute)...
    .venv\Scripts\python.exe -m pip install --upgrade pip >nul 2>&1
    .venv\Scripts\pip install -r requirements.txt
    echo [INFO] Setup complete!
)

echo [INFO] Launching NetScope in the background...
echo [INFO] You can safely close this terminal window.

REM Launch silently in the background
start "" ".venv\Scripts\pythonw.exe" main.py

timeout /t 3 >nul
echo [SUCCESS] NetScope is running. Open http://localhost:5000 in your browser!
pause
