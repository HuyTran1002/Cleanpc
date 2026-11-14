@echo off
title CleanPC - Khoi Phuc Cau Hinh Mac Dinh
cd /d "%~dp0"

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Dang xin quyen Administrator de khoi phuc thiet lap...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\optimize_system.ps1" -Action Restore
echo.
pause
