@echo off
REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed. Installing Python...
    REM Download and install Python from official source
    REM Modify the URL below to the latest Python version if needed
    powershell -Command "(New-Object Net.WebClient).DownloadFile('https://www.python.org/ftp/python/3.10.0/python-3.10.0-amd64.exe', 'python_installer.exe')"
    python_installer.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
    del python_installer.exe
)

REM Check if Python installation was successful or if Python was already installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Installation of Python failed. Please check your internet connection and try again.
    exit /b 1
)

echo Python is installed.

REM Install Nmap module using pip
echo Upgrading pip ...
python -m pip install --upgrade pip

REM Install psutil module using pip
echo Installing psutil...
pip install psutil

REM Install PyQt5 module using pip
echo Installing PyQt5...
pip install PyQt5


REM Install Nmap module using pip
echo Installing python-nmap...
pip install python-nmap

REM Install Nmap3 module using pip
echo Installing python3-nmap...
pip install python3-nmap

REM Install Netaddr module using pip
echo Installing netaddr...
pip install netaddr

REM Check if installation was successful
pip show python-nmap >nul 2>&1
if %errorlevel% equ 0 (
    echo Installation of python-nmap successful!
) else (
    echo Installation of python-nmap failed. Please check your internet connection and try again.
)
