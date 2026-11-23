@echo off
REM an https download with verification and no execution of the result
curl -fsSL -o data.json https://example.test/data.json
certutil -decode cert.b64 cert.cer
curl -fsSL -o data.json https://example.test/data.json && call :process
