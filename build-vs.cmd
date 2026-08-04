@echo off
setlocal

set "CONFIG=%~1"
if "%CONFIG%"=="" set "CONFIG=Debug"

set "MSBUILD=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
if exist "%MSBUILD%" goto build
echo MSBuild not found: %MSBUILD%
exit /b 1

:build
rem The Codex shell can expose both PATH and Path. MSBuild on .NET Framework
rem fails when it inherits duplicate environment keys, so keep the normal Path.
set PATH=
"%MSBUILD%" "%~dp0DiskControl.sln" /m /p:Configuration=%CONFIG% /p:Platform=x64
exit /b %ERRORLEVEL%
