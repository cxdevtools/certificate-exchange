@echo off
rem Single entry point for certtool on Windows:
rem   cxdev-certificates status [environment]
rem   cxdev-certificates fetch [environment] [--apply]
rem   cxdev-certificates upload [--certificate NAME] [--apply]
rem   cxdev-certificates rollout <environment> [--endpoint CODE] [--apply]
rem   cxdev-certificates cleanup [--include-unused] [--apply]
rem Equivalent to: python -m certtool <command> [...]
rem
rem Run it in the project directory: certtool.json (incl. the technical user's credentials) and the
rem certificates are read from there. Add this bin directory to the PATH to use it everywhere.
rem Python: %PYTHON% if set, else the Python launcher "py -3", else "python".
setlocal

rem Installation directory = parent of this script's directory
for %%I in ("%~dp0..") do set "ROOT=%%~fI"

if defined PYTHONPATH goto prepend
set "PYTHONPATH=%ROOT%"
goto python
:prepend
set "PYTHONPATH=%ROOT%;%PYTHONPATH%"

:python
set "CERTTOOL_PROG=cxdev-certificates"
if defined PYTHON goto run_custom
where py >nul 2>nul
if not errorlevel 1 goto run_launcher
python -m certtool %*
goto end

:run_custom
"%PYTHON%" -m certtool %*
goto end

:run_launcher
py -3 -m certtool %*

:end
exit /b %ERRORLEVEL%
