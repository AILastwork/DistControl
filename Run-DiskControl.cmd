@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0DiskControl.ps1"
if errorlevel 1 pause

