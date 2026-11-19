@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\Build-GpoMsiPackage.ps1" %*
if errorlevel 1 pause
