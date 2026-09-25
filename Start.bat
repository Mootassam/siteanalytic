@echo off
title Website Intelligence
cd /d "%~dp0"
set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not exist "%PY%" set "PY=python"
echo Starting Website Intelligence...
echo Open your browser at:  http://127.0.0.1:5001
echo (Close this window to stop.)
echo.
"%PY%" "%~dp0server.py"
pause
