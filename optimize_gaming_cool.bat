@echo off
title CleanPC - Toi Uu Hieu Nang & Mat May (1-Click)
cd /d "%~dp0"

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Dang xin quyen Administrator de ap dung thiet lap he thong...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\optimize_system.ps1" -Action Optimize
echo.
pause
