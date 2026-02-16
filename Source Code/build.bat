@echo off
REM ============================================================
REM  SAS Network Diagnostics Tool -- Build Script (Windows)
REM  Produces a single portable .exe file
REM ============================================================

echo.
echo  ===================================================
echo    SAS Network Diagnostics Tool -- Build
echo  ===================================================
echo.

REM -- Check Python is available --
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.10+ and add to PATH.
    pause
    exit /b 1
)

REM -- Install / upgrade dependencies --
echo [1/3] Installing dependencies...
pip install -r requirements.txt --quiet
pip install pyinstaller --quiet
echo       Attempting optional Profinet DCP library...
pip install profi-dcp --quiet 2>nul
if errorlevel 1 (
    echo       profi-dcp not available -- Profinet DCP discovery will be disabled
    echo       [requires Npcap: https://nmap.org/npcap/]
)

REM -- Clean previous builds --
echo [2/3] Cleaning previous builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

REM -- Build the executable --
echo [3/3] Building executable (this may take 1-2 minutes)...

REM Try pyinstaller directly first, then fall back to python -m PyInstaller
where pyinstaller >nul 2>&1
if errorlevel 1 (
    echo       pyinstaller not on PATH, using: python -m PyInstaller
    python -m PyInstaller ^
        --onefile ^
        --windowed ^
        --name "SAS-NetDiag" ^
        --icon "assets\icon.ico" ^
        --add-data "assets;assets" ^
        --hidden-import "pycomm3" ^
        --hidden-import "pycomm3.cip" ^
        --hidden-import "pycomm3.packets" ^
        --hidden-import "customtkinter" ^
        --hidden-import "PIL" ^
        --hidden-import "PIL._tkinter_finder" ^
        --hidden-import "psutil" ^
        --hidden-import "profi_dcp" ^
        --collect-all "customtkinter" ^
        main.py
) else (
    pyinstaller ^
        --onefile ^
        --windowed ^
        --name "SAS-NetDiag" ^
        --icon "assets\icon.ico" ^
        --add-data "assets;assets" ^
        --hidden-import "pycomm3" ^
        --hidden-import "pycomm3.cip" ^
        --hidden-import "pycomm3.packets" ^
        --hidden-import "customtkinter" ^
        --hidden-import "PIL" ^
        --hidden-import "PIL._tkinter_finder" ^
        --hidden-import "psutil" ^
        --hidden-import "profi_dcp" ^
        --collect-all "customtkinter" ^
        main.py
)

if errorlevel 1 (
    echo.
    echo BUILD FAILED -- see errors above.
    echo.
    echo Common fixes:
    echo   - Run: python -m pip install pyinstaller
    echo   - Or add Python Scripts folder to your PATH
    pause
    exit /b 1
)

echo.
echo ====================================================
echo  BUILD SUCCESSFUL!
echo.
echo  Output:  dist\SAS-NetDiag.exe
echo  Size:
for %%A in (dist\SAS-NetDiag.exe) do echo           %%~zA bytes
echo.
echo  The .exe is fully portable -- copy it anywhere.
echo.
echo  OPTIONAL for Packet Capture:
echo    Place a tools\ folder next to the .exe with:
echo      tools\tshark\tshark.exe  (from Wireshark)
echo      tools\npcap-installer.exe (from npcap.com)
echo    Run setup_tools.bat to set this up automatically.
echo ====================================================
echo.
pause
