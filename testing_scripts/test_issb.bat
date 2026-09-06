@echo off
setlocal

echo ================================
echo USER
echo ================================
whoami
whoami /groups
echo.

echo ================================
echo SYSTEM
echo ================================
hostname
ver
systeminfo | findstr /I /C:"OS Name" /C:"OS Version" /C:"System Manufacturer" /C:"System Model"
echo.

echo ================================
echo CURRENT DIRECTORY
echo ================================
cd
dir
echo.

echo ================================
echo IMPORTANT DIRECTORIES
echo ================================
echo USERPROFILE=%USERPROFILE%
echo TEMP=%TEMP%
echo TMP=%TMP%
echo APPDATA=%APPDATA%
echo LOCALAPPDATA=%LOCALAPPDATA%
echo PROGRAMFILES=%PROGRAMFILES%
echo.

endlocal