@echo off
setlocal
cd /d "%~dp0"

set "PSModulePath=%USERPROFILE%\Documents\WindowsPowerShell\Modules;%ProgramFiles%\WindowsPowerShell\Modules;%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0stop-vocat.ps1" %*
set "VOCAT_EXIT_CODE=%ERRORLEVEL%"

if not "%VOCAT_EXIT_CODE%"=="0" (
    echo.
    echo VoCat could not be stopped safely. Review the error above.
    pause
)

exit /b %VOCAT_EXIT_CODE%
