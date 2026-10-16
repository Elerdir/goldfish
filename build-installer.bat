@echo off
:: ===========================================================================
::  Goldfish - release installer build (Windows)
::  Compiles an optimized release binary and bundles Windows installers:
::    MSI  (WiX)  -> target\release\bundle\msi\
::    NSIS (.exe) -> target\release\bundle\nsis\
::
::  Code signing (optional): set a certificate thumbprint in
::  crates\goldfish-tauri\tauri.conf.json (bundle.windows.certificateThumbprint)
::  or a signCommand, then re-run. See docs\packaging.md.
:: ===========================================================================
setlocal EnableExtensions

cd /d "%~dp0"

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

echo [Goldfish] building release installers...
echo            (first build pulls + compiles vendored OpenSSL + SQLCipher and
echo             downloads the WiX/NSIS toolchains - 10-30 min on a cold cache)
echo.

:: Updater signing: the bundle creates signed update artifacts (createUpdaterArtifacts).
:: The key is %USERPROFILE%\.tauri\goldfish.key (scripts\new-signing-key.ps1); its
:: DPAPI-protected password can only be decrypted by this user. Without the key the
:: updater artifacts are switched off locally (official releases are built by CI).
set "CONFIG_ARGS="
if not defined TAURI_SIGNING_PRIVATE_KEY if exist "%USERPROFILE%\.tauri\goldfish.key" (
    set "TAURI_SIGNING_PRIVATE_KEY_PATH=%USERPROFILE%\.tauri\goldfish.key"
    for /f "usebackq delims=" %%P in (`powershell -NoProfile -Command "[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((Import-Clixml '%USERPROFILE%\.tauri\goldfish-password.clixml')))"`) do set "TAURI_SIGNING_PRIVATE_KEY_PASSWORD=%%P"
)
if not defined TAURI_SIGNING_PRIVATE_KEY if not defined TAURI_SIGNING_PRIVATE_KEY_PATH (
    echo [Goldfish] no updater signing key - building without updater artifacts.
    set "CONFIG_ARGS=--config crates\goldfish-tauri\tauri.nosign.conf.json"
)

cargo tauri build --bundles msi,nsis %CONFIG_ARGS%
set "EXITCODE=%ERRORLEVEL%"

echo.
if "%EXITCODE%"=="0" (
    echo [Goldfish] build OK. Installer artifacts:
    for %%f in ("target\release\bundle\msi\*.msi") do echo   MSI:  %%~ff
    for %%f in ("target\release\bundle\nsis\*-setup.exe") do echo   NSIS: %%~ff
    echo.
    echo Opening output folder...
    if exist "target\release\bundle" start "" "target\release\bundle"
) else (
    echo [Goldfish] build FAILED with code %EXITCODE%.
    echo See the log above. Common causes: missing Perl/NASM/MSVC Build Tools, or no network for the WiX/NSIS download.
)

pause
exit /b %EXITCODE%
