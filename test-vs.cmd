@echo off
setlocal

call "%~dp0build-vs.cmd" Debug
if errorlevel 1 exit /b %ERRORLEVEL%

"%~dp0build\x64\Debug\DiskControl.Tests.exe"
exit /b %ERRORLEVEL%
