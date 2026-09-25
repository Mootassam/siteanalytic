@echo off
title Build Website Intelligence Installer
cd /d "%~dp0"
set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not exist "%PY%" set "PY=python"
echo Installing build tools (first run only)...
"%PY%" -m pip install --quiet --disable-pip-version-check pyinstaller pillow pystray cryptography
echo.
echo Building Website Intelligence installer...
"%PY%" "packaging\build.py"
echo.
pause
