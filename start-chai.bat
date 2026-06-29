@echo off
setlocal enabledelayedexpansion

:: Chai one-click development launcher
:: Starts the backend (Uvicorn) and frontend (Vite) in separate windows.

set "ROOT=%~dp0"
set "ROOT=%ROOT:~0,-1%"

echo Starting Noetic development servers...
echo Backend:  http://localhost:8060
echo Frontend: http://localhost:5240
echo.

:: Start backend in a new window
start "CHAI Backend" cmd /k "cd /d "%ROOT%\backend" && call .venv\Scripts\activate && python main.py --transport streamable-http --port 8060"

:: Give the backend a moment to initialize before the frontend starts
timeout /t 10 /nobreak >nul

:: Start frontend in a new window, pointing Vite directly at the backend API
start "CHAI Frontend" cmd /k "cd /d "%ROOT%\ui" && npm run dev -- --port 5240"

echo.
echo Both servers are starting in separate windows.
echo Close those windows to stop the servers.
pause
