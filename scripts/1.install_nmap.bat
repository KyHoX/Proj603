@echo off
setlocal


REM Set Nmap version and installer URL
set NMAP_VERSION=7.93
set NMAP_INSTALLER=nmap-%NMAP_VERSION%-setup.exe
set NMAP_URL=https://nmap.org/dist/%NMAP_INSTALLER%



:check_nmap
REM Function to check if Nmap is already installed

nmap --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Nmap is not installed. Installing Nmap...
    REM Download and install Python from official source
    REM Modify the URL below to the latest Python version if needed
    goto download
)

REM Check if Python installation was successful or if Python was already installed
nmap --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Installation of Nmap failed. Please check your internet connection and try again.
    exit /b 1
)


goto end
REM Download Nmap installer
:download
echo Downloading Nmap %NMAP_VERSION% installer...
curl -o %NMAP_INSTALLER% %NMAP_URL%

REM Check if the download was successful
if not exist %NMAP_INSTALLER% (
    echo Failed to download Nmap installer.
    exit /b 1
)

REM Install Nmap 

echo Installing Nmap %NMAP_VERSION%...
start /wait %NMAP_INSTALLER%



:end
powershell.exe -Command "setx PATH '%PATH%;C:\Program Files (x86)\Nmap'"
echo Nmap is already installed.
echo Nmap %NMAP_VERSION%
pause
echo Cleaning up...
del %NMAP_INSTALLER%


