@echo off
setlocal
title LogSentinelAI — Remove from Startup
color 0E
cls

echo.
echo   +------------------------------------------------------------------+
echo   ^|  LogSentinelAI — Remove from Windows Startup                    ^|
echo   +------------------------------------------------------------------+
echo.
echo   This will remove LogSentinelAI from the Windows startup list.
echo   The agent files will NOT be deleted — only the auto-start entry.
echo.
echo   Press any key to continue, or close this window to cancel.
pause >nul

:: Try via the EXE first (cleanest method)
if exist "%~dp0LogSentinelAI.exe" (
    echo.
    echo   Running: LogSentinelAI.exe --uninstall
    "%~dp0LogSentinelAI.exe" --uninstall
    goto :done
)

:: Fallback: remove registry entry directly with reg.exe
echo.
echo   Removing registry entry...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "LogSentinelAI" /f >nul 2>&1
if %errorlevel% equ 0 (
    echo   Done. LogSentinelAI has been removed from Windows startup.
) else (
    echo   LogSentinelAI was not found in Windows startup (nothing to remove).
)

:: Remove the .startup_asked flag so the prompt reappears next run
if exist "%~dp0.startup_asked" del /f /q "%~dp0.startup_asked" >nul 2>&1

:done
echo.
echo   ----------------------------------------------------------------
echo   Press any key to close.
echo   ----------------------------------------------------------------
pause >nul
endlocal
