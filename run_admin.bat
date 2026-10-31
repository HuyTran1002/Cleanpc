@echo off
title CleanPC Master (Admin Mode)
cd /d "%~dp0"
cls

echo =====================================================================
echo           CleanPC Master - Launching in Administrator Mode
echo =====================================================================
echo.
echo [1/2] Checking Python environment...

set "PY_CMD=python"
python --version >nul 2>&1
if %ERRORLEVEL% EQU 0 goto :RUN_PY

py --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set "PY_CMD=py"
    goto :RUN_PY
)

if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PY_CMD=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    goto :RUN_PY
)

echo [ERROR] Python was not found on your system.
echo Please install Python from https://www.python.org
pause
exit /b 1

:RUN_PY
echo [2/2] Requesting Administrator privileges...
"%PY_CMD%" "%~dp0desktop.py" --admin
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Application closed with code %ERRORLEVEL%.
    pause
)
