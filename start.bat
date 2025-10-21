@echo off
title CipherGenius v1.1.0 - Cryptographic Scheme Generator
cls

echo.
echo ===================================================
echo.
echo         CipherGenius v1.1.0
echo    Cryptographic Scheme Generator
echo.
echo ===================================================
echo.

cd /d "%~dp0"

:: Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found
    echo.
    echo Please install Python 3.8 or higher
    echo Download: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo [OK] Python detected
python --version
echo.

:: Check Streamlit installation
python -c "import streamlit" >nul 2>&1
if errorlevel 1 (
    echo [INFO] First run detected. Installing dependencies...
    echo This may take a few minutes. Please wait...
    echo.
    pip install streamlit zhipuai -q
    echo.
    echo [OK] Dependencies installed successfully
    echo.
)

:: Check API key configuration
if not exist .env (
    echo [WARNING] No API key configuration detected
    echo.
    echo For first-time setup:
    echo  1. Copy .env.example and rename to .env
    echo  2. Edit .env file and add your API key
    echo     (Supports ZhipuAI / OpenAI / Anthropic)
    echo.
    echo Press any key to continue (limited functionality)...
    echo.
    pause >nul
)

echo [INFO] Starting CipherGenius...
echo.
echo    Components: 152 cryptographic algorithms
echo    Primitives: 122 | Modes: 16 | Protocols: 14
echo    Post-Quantum: Kyber, Dilithium, SPHINCS+, FALCON, etc.
echo    Server: http://localhost:8503
echo.
echo    TIP: Browser will open automatically
echo    STOP: Press Ctrl+C
echo.
echo ===================================================
echo.

:: Start Streamlit application
python -m streamlit run web_app.py --server.port=8503 --server.headless=true --global.developmentMode=false

:: Error handling
if errorlevel 1 (
    echo.
    echo ===================================================
    echo [ERROR] Failed to start application
    echo ===================================================
    echo.
    echo Please check the error message above.
    echo Common issues:
    echo  - Port 8502 in use: Close the program using it
    echo  - Missing dependencies: pip install -r requirements.txt
    echo  - API key error: Check .env file configuration
    echo.
    pause
)
