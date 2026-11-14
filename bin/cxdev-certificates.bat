@echo off
rem Single entry point for certtool. Run from a project directory with certtool.json.
setlocal
for %%I in ("%~dp0..") do set "ROOT=%%~fI"
set "CERTTOOL_PROG=cxdev-certificates"
set "CERTTOOL_HOME=%ROOT%"
if defined JAVA goto run_custom
if defined JAVA_HOME goto run_java_home
where java >nul 2>nul
if errorlevel 1 goto no_java
java -cp "%ROOT%\lib\*" me.cxdev.certtool.CertTool %*
goto end
:run_custom
"%JAVA%" -cp "%ROOT%\lib\*" me.cxdev.certtool.CertTool %*
goto end
:run_java_home
"%JAVA_HOME%\bin\java.exe" -cp "%ROOT%\lib\*" me.cxdev.certtool.CertTool %*
goto end
:no_java
echo ERROR: Java 21 or newer is required. Install it or set JAVA to its executable. 1>&2
set "RESULT=2"
goto result
:end
set "RESULT=%ERRORLEVEL%"
:result
exit /b %RESULT%
