@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\Build-MsiPackage.ps1" %*
if errorlevel 1 pause
