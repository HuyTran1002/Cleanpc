@echo off
title CleanPC Master
cd /d "%~dp0"
cls

echo =====================================================================
echo                CleanPC Master - Desktop App
echo =====================================================================
echo.
echo [1/2] Checking Python environment...

set "PY_CMD=python"
python --version >nul 2>&1
if %ERRORLEVEL% EQU 0 goto :START_APP

py --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set "PY_CMD=py"
    goto :START_APP
)

if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PY_CMD=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    goto :START_APP
)

echo [ERROR] Python was not found on your system.
echo Please install Python from https://www.python.org
pause
exit /b 1

:START_APP
echo [2/2] Launching CleanPC Master Desktop Application...
echo =====================================================================
echo.

"%PY_CMD%" "%~dp0desktop.py"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Application closed with code %ERRORLEVEL%.
    pause
)
