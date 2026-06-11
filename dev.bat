@echo off
:: ===========================================================================
::  Goldfish — dev launcher
::  Starts Vite (frontend) + Tauri (backend) with hot reload.
::  Closing the Tauri window stops both.
:: ===========================================================================
setlocal EnableExtensions

:: Run from this script's directory so relative paths in tauri.conf.json resolve.
cd /d "%~dp0"

:: Ensure cargo and pnpm are on PATH (rustup installs to user profile by default,
:: which isn't always inherited by Explorer-launched cmd sessions).
set "PATH=%USERPROFILE%\.cargo\bin;%APPDATA%\npm;%PATH%"

where cargo >nul 2>&1 || (
    echo [ERROR] cargo not found on PATH. Install Rust from https://rustup.rs/ and re-run.
    pause
    exit /b 1
)
where pnpm >nul 2>&1 || (
    echo [ERROR] pnpm not found on PATH. Run: npm install -g pnpm
    pause
    exit /b 1
)

echo [Goldfish] starting dev environment...
echo   - Vite dev server on http://localhost:5173
echo   - Tauri window will open when frontend is ready.
echo.

cargo tauri dev
set "EXITCODE=%ERRORLEVEL%"

if not "%EXITCODE%"=="0" (
    echo.
    echo [Goldfish] dev exited with code %EXITCODE%.
    pause
)
exit /b %EXITCODE%
