@echo off
setlocal EnableDelayedExpansion
title LogSentinelAI — Security Agent

:: ── Require Administrator ────────────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: ── Colours ─────────────────────────────────────────────────────────────
:: 0A = bright green on black  |  0B = cyan on black  |  0E = yellow on black
color 0B
cls

:: ── Banner ───────────────────────────────────────────────────────────────
echo.
echo   +------------------------------------------------------------------+
echo   ^|                                                                  ^|
echo   ^|        L o g S e n t i n e l A I   —   Security Agent           ^|
echo   ^|        AI-Powered Intrusion Detection  ^|  v1.2                  ^|
echo   ^|                                                                  ^|
echo   +------------------------------------------------------------------+
echo.

:: ── Python Check ────────────────────────────────────────────────────────
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [!] Python was not found on this machine.
    echo.
    echo   To run the agent via this script, Python 3.8+ is required.
    echo   Alternatively, use  LogSentinelAI.exe  which needs no Python.
    echo.
    echo   Download Python from:  https://www.python.org/downloads/
    echo   Make sure to check "Add Python to PATH" during installation.
    echo.
    echo   Press any key to open the Python download page...
    pause >nul
    start "" "https://www.python.org/downloads/"
    echo.
    echo   After installing Python, re-run this script.
    echo   Press any key to exit.
    pause >nul
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo   Python %PYVER% detected.
echo.

:: ── Install / update dependencies ───────────────────────────────────────
echo   Installing dependencies (requests, psutil, watchdog)...
python -m pip install requests psutil watchdog --quiet --disable-pip-version-check 2>nul
if %errorlevel% neq 0 (
    echo   [!] Dependency installation failed.
    echo       Try running:  python -m pip install -r requirements.txt
    echo.
) else (
    echo   Dependencies ready.
)
echo.

:: ── Dashboard URL ────────────────────────────────────────────────────────
set DASHBOARD=https://log-sentinel-ai-h3bmh3hbh6e3c6bx.francecentral-01.azurewebsites.net

echo   Dashboard  :  %DASHBOARD%
echo   Agent file :  %~dp0agent.py
echo.
echo   +------------------------------------------------------------------+
echo   ^|  NEXT STEPS                                                      ^|
echo   ^|                                                                  ^|
echo   ^|  1. A pairing code will appear below in a moment                ^|
echo   ^|  2. Sign in to your dashboard                                    ^|
echo   ^|  3. Click  "Connect Machine"  and enter the code                ^|
echo   ^|                                                                  ^|
echo   ^|  Press  Ctrl+C  at any time to stop the agent.                  ^|
echo   +------------------------------------------------------------------+
echo.

:: ── Open dashboard in browser ────────────────────────────────────────────
start "" "%DASHBOARD%"

:: ── Run agent ────────────────────────────────────────────────────────────
python "%~dp0agent.py" --server "%DASHBOARD%" --key "sentinel-secret-key"

:: ── Exit message ─────────────────────────────────────────────────────────
echo.
echo   ----------------------------------------------------------------
echo   Agent stopped.
echo   ----------------------------------------------------------------
echo.
echo   Press any key to close this window.
pause >nul
endlocal
