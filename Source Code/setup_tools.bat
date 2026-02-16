@echo off
REM ============================================================
REM  SAS Network Diagnostics Tool -- Capture Tools Setup
REM  Downloads tshark (Wireshark CLI) and Npcap for bundling
REM ============================================================

echo.
echo  ===================================================
echo   Capture Tools Setup
echo  ===================================================
echo.
echo  This script sets up the packet capture dependencies
echo  so they can be bundled with the app.
echo.
echo  What gets downloaded:
echo    1. Wireshark Portable (for tshark.exe)
echo    2. Npcap installer (network capture driver)
echo.

if not exist "tools" mkdir tools

REM ── Step 1: tshark (from Wireshark) ──────────────────────────

echo ── Step 1: tshark ──────────────────────────────────────
echo.

if exist "tools\tshark\tshark.exe" (
    echo  Already found: tools\tshark\tshark.exe
    echo  Skipping tshark setup.
    echo.
    goto :npcap
)

echo  tshark is the command-line version of Wireshark.
echo  We need to extract it from a Wireshark installation.
echo.
echo  OPTIONS:
echo    A) If Wireshark is already installed on THIS PC:
echo       We'll copy the needed files automatically.
echo.
echo    B) If Wireshark is NOT installed:
echo       Install it from https://www.wireshark.org/download.html
echo       then re-run this script.
echo.

REM Check standard install locations
set WSDIR=
if exist "C:\Program Files\Wireshark\tshark.exe" set WSDIR=C:\Program Files\Wireshark
if exist "C:\Program Files (x86)\Wireshark\tshark.exe" set WSDIR=C:\Program Files (x86)\Wireshark

if defined WSDIR (
    echo  FOUND: Wireshark at %WSDIR%
    echo  Copying tshark and required files...
    echo.

    if not exist "tools\tshark" mkdir "tools\tshark"

    REM Core executables
    copy /y "%WSDIR%\tshark.exe" "tools\tshark\" >nul 2>&1

    REM Required DLLs — copy all DLLs to be safe
    for %%f in ("%WSDIR%\*.dll") do copy /y "%%f" "tools\tshark\" >nul 2>&1

    REM Plugins (dissectors for EIP/CIP etc.)
    if exist "%WSDIR%\plugins" (
        xcopy /s /e /q /y "%WSDIR%\plugins" "tools\tshark\plugins\" >nul 2>&1
    )

    REM Protocol profiles
    if exist "%WSDIR%\profiles" (
        xcopy /s /e /q /y "%WSDIR%\profiles" "tools\tshark\profiles\" >nul 2>&1
    )

    REM Verify
    if exist "tools\tshark\tshark.exe" (
        echo  SUCCESS: tshark copied to tools\tshark\
        echo.
    ) else (
        echo  ERROR: Copy failed. Try running as Administrator.
        echo.
    )
) else (
    echo  Wireshark not found in standard locations.
    echo  Please install Wireshark and re-run this script.
    echo  Download: https://www.wireshark.org/download.html
    echo.
    echo  After installing, run this script again.
    echo.
)

:npcap
REM ── Step 2: Npcap ────────────────────────────────────────────

echo ── Step 2: Npcap installer ────────────────────────────
echo.

REM Check if any npcap installer already exists in tools/
set NPCAP_FOUND=
for %%f in (tools\npcap*.exe) do set NPCAP_FOUND=%%f

if defined NPCAP_FOUND (
    echo  Already found: %NPCAP_FOUND%
    echo  Skipping Npcap download.
    echo.
    goto :done
)

REM Check if Npcap is installed on this system
if exist "%SYSTEMROOT%\System32\Npcap" (
    echo  Npcap is installed on this PC.
    echo.
    echo  To bundle the Npcap installer for other PCs:
    echo    1. Download from https://npcap.com/#download
    echo    2. Save the .exe as tools\npcap-installer.exe
    echo.
    echo  The app will auto-install Npcap on target PCs that
    echo  don't have it, using the bundled installer.
    echo.
) else (
    echo  Npcap is NOT installed on this PC.
    echo.
    echo  Npcap is required for packet capture on Windows.
    echo    1. Download from https://npcap.com/#download
    echo    2. Run the installer on this PC
    echo    3. Also save a copy as tools\npcap-installer.exe
    echo       for bundling with the app
    echo.
)

:done
echo ── Summary ──────────────────────────────────────────────
echo.

if exist "tools\tshark\tshark.exe" (
    echo  [OK] tshark:  tools\tshark\tshark.exe
) else (
    echo  [!!] tshark:  NOT FOUND - install Wireshark and re-run
)

set NPCAP_FOUND=
for %%f in (tools\npcap*.exe) do set NPCAP_FOUND=%%f
if defined NPCAP_FOUND (
    echo  [OK] Npcap:   %NPCAP_FOUND%
) else (
    echo  [!!] Npcap:   NOT FOUND - download from npcap.com
)

echo.
echo  After both tools are ready, run build.bat to create
echo  the deployment package with everything bundled.
echo.
pause
